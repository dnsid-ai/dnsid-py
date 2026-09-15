"""OIDC federation helpers for DNSid identities.

This module implements the DNSid OIDC application profile: JWT bearer assertions
signed with an agent's operational key, token exchange against an OIDC issuer,
and verification of issued tokens back to a DNSid identity record. The OIDC
profile is an application profile layered on top of DNSid; it is explicitly NOT
part of the core DNSid protocol.
"""

from __future__ import annotations

import datetime
import json
import math
import uuid
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urlparse

import httpx

from ._crypto import jwk_from_dict, verify_signature
from ._utils import b64url_decode, b64url_encode, normalize_fqdn
from ._verification_budget import bounded_http_timeout, remaining_seconds, verification_operation
from .enums import VerificationCode
from .exceptions import ArgumentError, DNSidError, VerificationError
from .interfaces import IdentityResolver, KeyProvider
from .jose import _decode_jwt_header_claims, _validate_duration, _validate_protected_header
from .models import JWK, TLSCertificate, TransportConfig, VerifiedDomain

_DEFAULT_ASSERTION_LIFETIME = datetime.timedelta(seconds=300)
_DEFAULT_MAX_ASSERTION_LIFETIME = datetime.timedelta(seconds=900)
_TIMEOUT = 10.0
_MAX_BODY_BYTES = 1 * 1024 * 1024
_JWT_RESERVED = {"iss", "sub", "aud", "iat", "exp", "jti", "fqdn"}
_Timeout = float | httpx.Timeout


class NetworkError(DNSidError):
    """OIDC discovery, JWKS, or token endpoint transport failure."""


class OAuthError(DNSidError):
    """OIDC token endpoint returned an OAuth error response."""

    def __init__(self, error: str = "", error_description: str = "") -> None:
        """Initialize from an OAuth error response.

        Args:
            error: OAuth 2.0 error code returned by the token endpoint.
            error_description: Human-readable description from the response, if any.
        """
        self.error = error
        self.error_description = error_description
        super().__init__(error_description or error or "OIDC token exchange failed")


@dataclass
class OIDCConfig:
    """Configure OIDC assertion creation, token exchange, and token verification.

    Controls assertion lifetimes, clock-skew tolerance, the allowed issuers and
    token signing algorithms, default issuer/endpoint values, and HTTP transport
    defaults shared by all OIDCProfile operations.
    """

    default_scope: str = "openid"
    assertion_lifetime: datetime.timedelta = field(
        default_factory=lambda: _DEFAULT_ASSERTION_LIFETIME
    )
    max_assertion_lifetime: datetime.timedelta = field(
        default_factory=lambda: _DEFAULT_MAX_ASSERTION_LIFETIME
    )
    clock_skew: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(seconds=30))
    allowed_issuers: list[str] = field(default_factory=list)
    allowed_token_algorithms: list[str] = field(default_factory=lambda: ["RS256"])
    allow_http_loopback_issuer: bool = False
    default_issuer: str = ""
    default_server_url: str = ""
    default_discovery_url: str = ""
    default_token_endpoint: str = ""
    http_client: httpx.Client | None = field(default=None, repr=False, compare=False)
    timeout: _Timeout | None = None


@dataclass
class OIDCAssertionOptions:
    """Specify how to build a signed OIDC JWT bearer assertion.

    ``issuer`` names the target OIDC issuer and becomes the assertion audience.
    ``expiry`` overrides the configured assertion lifetime, and
    ``additional_claims`` are merged into the JWT payload; reserved JWT claims
    may not be overridden.
    """

    issuer: str
    expiry: datetime.timedelta | None = None
    additional_claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class OIDCTokenExchangeOptions:
    """Specify how to exchange a DNSid assertion for tokens at an OIDC issuer.

    ``audience`` is required. The issuer may be given directly or derived from
    ``server_url`` or ``discovery_url``; a ``token_endpoint`` skips discovery.
    Empty fields fall back to the corresponding ``OIDCConfig`` defaults. When
    ``assertion`` is empty, a fresh assertion is created for the exchange.
    """

    issuer: str = ""
    audience: str = ""
    scope: str | list[str] = ""
    assertion: str = ""
    server_url: str = ""
    discovery_url: str = ""
    token_endpoint: str = ""
    assertion_expiry: datetime.timedelta | None = None
    http_client: httpx.Client | None = field(default=None, repr=False, compare=False)
    timeout: _Timeout | None = None


@dataclass
class OIDCDiscoveryDocument:
    """Hold the validated subset of an OIDC discovery document.

    Carries the issuer, token endpoint, and JWKS URI after same-origin and
    issuer-match validation, plus the raw discovery response for access to any
    additional metadata.
    """

    issuer: str
    token_endpoint: str
    jwks_uri: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class OIDCTokenResponse:
    """Hold the result of a successful OIDC JWT bearer token exchange.

    Includes the issued tokens plus the exchange context: the issuer and token
    endpoint used, the requested audience and scope, and the validity window of
    the assertion that was presented.
    """

    access_token: str
    token_type: str
    id_token: str = ""
    expires_in: int | None = None
    scope: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    issuer: str = ""
    token_endpoint: str = ""
    audience: str = ""
    requested_scope: str = ""
    assertion_issued_at: datetime.datetime | None = None
    assertion_expires_at: datetime.datetime | None = None


@dataclass
class VerifyOIDCTokenOptions:
    """Specify how to verify a token issued by an OIDC issuer.

    ``issuer`` and ``audience`` are matched exactly against the token claims.
    When ``verify_dnsid_subject`` is true, the token subject is additionally
    resolved and verified as a DNSid identity.
    """

    issuer: str
    audience: str
    verify_dnsid_subject: bool = True


@dataclass
class VerifiedOIDCSubject:
    """Hold the verified subject extracted from an OIDC token.

    ``verified_domain`` carries the DNSid verification result for the subject
    when subject verification was requested, otherwise ``None``. ``claims`` is
    the full decoded claim set of the token.
    """

    issuer: str
    subject: str
    audience: str
    verified_domain: VerifiedDomain | None
    claims: dict[str, Any]


@dataclass
class _TokenExchangeTarget:
    issuer: str
    token_endpoint: str
    http_client: httpx.Client | None
    timeout: _Timeout | None


class OIDCProfile:
    """OIDC / OAuth JWT bearer helpers for a DNSid identity.

    Implements the DNSid OIDC application profile: creating JWT bearer
    assertions signed with the agent's operational key, exchanging them for
    tokens at an OIDC issuer, and verifying issued tokens back to a DNSid
    identity record. This is an application profile and is explicitly NOT part
    of the core DNSid protocol.
    """

    @classmethod
    def from_identity_manager(
        cls,
        manager: object,
        config: OIDCConfig | None = None,
    ) -> OIDCProfile:
        """Build a profile from an IdentityManager.

        Reuses the manager's resolver, key provider, domain, and transport
        configuration so OIDC operations act for the same DNSid identity.

        The inherited transport is the manager's validated snapshot: a manager
        built with an injected ``https_fetcher`` rejects ``ca_bundle_path``, so
        the clients this profile creates will not carry that bundle. Construct
        the profile directly with ``transport_config=`` to supply one.

        Args:
            manager: An ``IdentityManager`` instance to borrow collaborators from.
            config: Optional OIDC configuration; defaults to ``OIDCConfig()``.

        Returns:
            An ``OIDCProfile`` bound to the manager's domain and keys.
        """
        return cls(
            resolver=manager,  # type: ignore[arg-type]
            key_provider=manager._key_provider,  # type: ignore[attr-defined]
            domain=manager.local_domain,  # type: ignore[attr-defined]
            config=config,
            transport_config=manager.config.transport,  # type: ignore[attr-defined]
        )

    def __init__(
        self,
        resolver: IdentityResolver,
        key_provider: KeyProvider | None,
        domain: str,
        config: OIDCConfig | None = None,
        transport_config: TransportConfig | None = None,
    ) -> None:
        """Initialize the profile for one DNSid identity.

        Args:
            resolver: Resolver used to verify DNSid token subjects.
            key_provider: Provider of the agent's operational signing key.
            domain: The agent's FQDN; normalized on construction.
            config: OIDC configuration; defaults to ``OIDCConfig()``.
            transport_config: Optional HTTP transport configuration used when no
                explicit ``httpx.Client`` is supplied.
        """
        self._resolver = resolver
        self._key_provider = key_provider
        self._domain = normalize_fqdn(domain) if domain else ""
        self._config = config or OIDCConfig()
        _validate_duration(self._config.assertion_lifetime, "assertion_lifetime")
        _validate_duration(self._config.max_assertion_lifetime, "max_assertion_lifetime")
        _validate_duration(self._config.clock_skew, "clock_skew", allow_zero=True)
        self._transport_config = transport_config

    def _require_signing_provider(self) -> KeyProvider:
        if self._key_provider is None or not self._domain:
            raise ArgumentError(
                "OIDC signing requires a key_provider; profile is verification-only"
            )
        return self._key_provider

    def create_oidc_assertion(self, opts: OIDCAssertionOptions) -> str:
        """Create a signed JWT bearer assertion for the given issuer.

        The assertion is signed with the agent's operational key and carries
        ``iss``, ``sub``, and ``fqdn`` set to the agent's domain, the issuer as
        the sole audience, and a unique ``jti``.

        Args:
            opts: Assertion options; ``opts.issuer`` is required.

        Returns:
            The compact-serialized signed JWT.

        Raises:
            ArgumentError: If the issuer is invalid, the expiry is not positive
                or exceeds the maximum assertion lifetime, or
                ``additional_claims`` would override a reserved JWT claim.
        """
        issuer = _validate_exact_oidc_issuer(opts.issuer, self._config)
        expiry = opts.expiry if opts.expiry is not None else self._config.assertion_lifetime
        _validate_duration(expiry, "OIDC assertion expiry")
        if expiry > self._config.max_assertion_lifetime:
            raise ArgumentError("OIDC assertion expiry exceeds maximum lifetime")

        for key in opts.additional_claims:
            if key in _JWT_RESERVED:
                raise ArgumentError(f"additional_claims must not override reserved claim: {key}")

        now = _now()
        claims = {
            "iss": self._domain,
            "sub": self._domain,
            "aud": [issuer],
            "iat": int(now.timestamp()),
            "exp": int((now + expiry).timestamp()),
            "jti": uuid.uuid4().hex,
            "fqdn": self._domain,
            **opts.additional_claims,
        }
        if claims["exp"] <= claims["iat"]:
            raise ArgumentError("OIDC assertion expiry is below timestamp resolution")
        key_provider = self._require_signing_provider()
        signing_key = key_provider.signing_key()
        header = {"alg": signing_key.signature_alg(), "kid": signing_key.kid, "typ": "JWT"}
        return _sign_jwt(header, claims, key_provider)

    def discover_oidc_issuer(
        self,
        issuer: str,
        discovery_url: str = "",
        http_client: httpx.Client | None = None,
        timeout: _Timeout | None = None,
    ) -> OIDCDiscoveryDocument:
        """Fetch and validate the issuer's OIDC discovery document.

        Args:
            issuer: Exact OIDC issuer URL (HTTPS, no trailing slash).
            discovery_url: Optional explicit discovery URL; defaults to the
                issuer's ``/.well-known/openid-configuration``.
            http_client: Optional HTTP client override.
            timeout: Optional request timeout override.

        Returns:
            The validated discovery document.

        Raises:
            ArgumentError: If the issuer or discovery URL is invalid.
            NetworkError: On transport failure, redirect, or non-200 response.
            VerificationError: With ``VerificationCode.RECORD_INVALID`` if the
                document is malformed, the discovered issuer mismatches, or the
                endpoints are not on the issuer origin.
        """
        issuer = _validate_exact_oidc_issuer(issuer, self._config)
        return self._discover_oidc_document(
            issuer,
            discovery_url,
            http_client if http_client is not None else self._config.http_client,
            timeout if timeout is not None else self._config.timeout,
        )

    def _discover_oidc_document(
        self,
        issuer: str | None,
        discovery_url: str,
        http_client: httpx.Client | None,
        timeout: _Timeout | None,
    ) -> OIDCDiscoveryDocument:
        url = (
            _validate_configured_endpoint(discovery_url, "discovery URL")
            if discovery_url
            else _discovery_url(_require_issuer(issuer))
        )
        data = _get_json(
            url,
            self._transport_config,
            http_client,
            timeout,
            self._config.allow_http_loopback_issuer,
        )
        discovered_issuer = _validate_discovered_issuer(_require_str(data, "issuer"), self._config)
        if issuer is not None and discovered_issuer != issuer:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "OIDC discovery issuer mismatch"
            )
        issuer = discovered_issuer
        token_endpoint = _require_str(data, "token_endpoint")
        jwks_uri = _require_str(data, "jwks_uri")
        _validate_same_origin_endpoint(token_endpoint, issuer, "token_endpoint")
        _validate_same_origin_endpoint(jwks_uri, issuer, "jwks_uri")
        return OIDCDiscoveryDocument(
            issuer=issuer, token_endpoint=token_endpoint, jwks_uri=jwks_uri, raw=data
        )

    def exchange_oidc_token(self, opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse:
        """Exchange a JWT bearer assertion for tokens at the issuer.

        Resolves the issuer and token endpoint from the options, configured
        defaults, or discovery; creates a fresh assertion when none is supplied;
        and POSTs a ``jwt-bearer`` grant to the token endpoint.

        Args:
            opts: Exchange options; ``opts.audience`` is required.

        Returns:
            The parsed token response, annotated with the exchange context.

        Raises:
            ArgumentError: If required options are missing or invalid, or a
                supplied assertion's audience does not exactly match the issuer.
            NetworkError: On transport failure or a disallowed redirect.
            OAuthError: If the token endpoint returns an OAuth error response.
            VerificationError: With ``VerificationCode.RECORD_INVALID`` if the
                response is malformed or lacks a Bearer access token.
        """
        if not opts.audience:
            raise ArgumentError("audience is required")
        target = self._resolve_token_exchange_target(opts)
        assertion = opts.assertion or self.create_oidc_assertion(
            OIDCAssertionOptions(target.issuer, expiry=opts.assertion_expiry)
        )
        if opts.assertion:
            _, claims = _decode_jwt(assertion)
            if _to_string_list(claims.get("aud")) != [target.issuer]:
                raise ArgumentError("OIDC assertion audience must exactly match issuer")
        else:
            _, claims = _decode_jwt(assertion)
        assertion_issued_at, assertion_expires_at = _assertion_datetimes(claims)

        scope = _scope_value(opts.scope)
        if not scope:
            scope = self._config.default_scope
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "audience": opts.audience,
        }
        if scope:
            form["scope"] = scope

        data = _post_form_json(
            target.token_endpoint,
            form,
            self._transport_config,
            target.http_client,
            target.timeout,
            self._config.allow_http_loopback_issuer,
        )
        access_token = str(data.get("access_token") or "")
        token_type = str(data.get("token_type") or "")
        if not access_token:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "OIDC token response missing access_token"
            )
        if token_type.lower() != "bearer":
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "OIDC token response token_type must be Bearer"
            )
        expires_in = data.get("expires_in")
        return OIDCTokenResponse(
            access_token=access_token,
            id_token=str(data.get("id_token") or ""),
            token_type=token_type,
            expires_in=expires_in if isinstance(expires_in, int) else None,
            scope=str(data.get("scope") or ""),
            raw=data,
            issuer=target.issuer,
            token_endpoint=target.token_endpoint,
            audience=opts.audience,
            requested_scope=scope,
            assertion_issued_at=assertion_issued_at,
            assertion_expires_at=assertion_expires_at,
        )

    def mint_oidc_token(self, opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse:
        """Mint tokens using a freshly created assertion.

        Behaves like :meth:`exchange_oidc_token` except that any caller-supplied
        assertion in *opts* is ignored and a new one is always created. See
        :meth:`exchange_oidc_token` for the raised exceptions.

        Args:
            opts: Exchange options; ``opts.audience`` is required.

        Returns:
            The parsed token response.
        """
        return self.exchange_oidc_token(replace(opts, assertion=""))

    def get_oidc_token(self, opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse:
        """Get tokens for the given options.

        Alias for :meth:`mint_oidc_token`: a fresh assertion is always created
        and exchanged. See :meth:`exchange_oidc_token` for the raised
        exceptions.

        Args:
            opts: Exchange options; ``opts.audience`` is required.

        Returns:
            The parsed token response.
        """
        return self.mint_oidc_token(opts)

    def _resolve_token_exchange_target(
        self, opts: OIDCTokenExchangeOptions
    ) -> _TokenExchangeTarget:
        http_client = opts.http_client if opts.http_client is not None else self._config.http_client
        timeout = opts.timeout if opts.timeout is not None else self._config.timeout
        issuer = _first_non_empty(opts.issuer, self._config.default_issuer)
        server_url = _first_non_empty(opts.server_url, self._config.default_server_url)
        discovery_url = _first_non_empty(opts.discovery_url, self._config.default_discovery_url)
        token_endpoint = _first_non_empty(
            opts.token_endpoint, self._config.default_token_endpoint
        )

        server_url = _validate_configured_base_url(server_url, "server URL") if server_url else ""
        if issuer:
            issuer = _validate_exact_oidc_issuer(issuer, self._config)

        if server_url and not issuer:
            issuer = self._discover_issuer_only(
                discovery_url or _discovery_url(server_url),
                http_client,
                timeout,
            )
        elif discovery_url:
            doc = self._discover_oidc_document(issuer or None, discovery_url, http_client, timeout)
            issuer = doc.issuer
            if not token_endpoint and not server_url:
                token_endpoint = doc.token_endpoint
        elif not issuer:
            raise ArgumentError("OIDC issuer is required")
        elif not token_endpoint and not server_url:
            doc = self.discover_oidc_issuer(issuer, http_client=http_client, timeout=timeout)
            token_endpoint = doc.token_endpoint

        if token_endpoint:
            token_endpoint = _validate_configured_endpoint(token_endpoint, "token endpoint")
        elif server_url:
            token_endpoint = _validate_configured_endpoint(
                f"{server_url}/token", "token endpoint"
            )
        else:
            raise ArgumentError("OIDC token endpoint is required")

        return _TokenExchangeTarget(
            issuer=issuer,
            token_endpoint=token_endpoint,
            http_client=http_client,
            timeout=timeout,
        )

    def _discover_issuer_only(
        self,
        discovery_url: str,
        http_client: httpx.Client | None,
        timeout: _Timeout | None,
    ) -> str:
        url = _validate_configured_endpoint(discovery_url, "discovery URL")
        data = _get_json(
            url,
            self._transport_config,
            http_client,
            timeout,
            self._config.allow_http_loopback_issuer,
        )
        return _validate_discovered_issuer(_require_str(data, "issuer"), self._config)

    @verification_operation
    def verify_oidc_token(
        self,
        token: str,
        opts: VerifyOIDCTokenOptions,
        *,
        peer_cert: TLSCertificate | None = None,
    ) -> VerifiedOIDCSubject:
        """Verify an OIDC-issued token and optionally its DNSid subject.

        Enforces the issuer allowlist and exact issuer/audience/azp claims,
        restricts the JWT header and signing algorithm, fetches the issuer's
        JWKS via discovery, verifies the signature, and validates the time
        claims. When ``opts.verify_dnsid_subject`` is true, the token subject
        is additionally verified as a DNSid identity via the resolver.

        Args:
            token: Compact-serialized JWT issued by the OIDC issuer.
            opts: Verification options; issuer and audience are required.
            peer_cert: Certificate from the current peer connection. Required
                when the DNSid subject record carries ``fl=mtls``.

        Returns:
            The verified subject, its claims, and the optional DNSid
            verification result.

        Raises:
            ArgumentError: If the issuer is invalid or the audience is empty.
            NetworkError: On discovery or JWKS transport failure.
            VerificationError: With ``VerificationCode.RECORD_INVALID`` for
                disallowed-issuer, claim, or structural failures, and
                ``VerificationCode.SIGNATURE_INVALID`` for algorithm, key, or
                signature failures.
        """
        issuer = _validate_exact_oidc_issuer(opts.issuer, self._config)
        if issuer not in self._config.allowed_issuers:
            raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC issuer is not allowed")
        if not opts.audience:
            raise ArgumentError("audience is required")

        header, claims = _decode_jwt(token)
        _validate_protected_header(header, self._config.allowed_token_algorithms)
        _validate_token_times(claims, self._config.clock_skew)
        if claims.get("iss") != issuer:
            raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC issuer mismatch")
        audience = _to_string_list(claims.get("aud"))
        if audience != [opts.audience]:
            raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC audience mismatch")
        azp = claims.get("azp")
        if azp is not None and azp != opts.audience:
            raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC azp mismatch")
        if set(header) - {"alg", "kid", "typ"}:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "unsupported OIDC token header"
            )

        alg = str(header.get("alg") or "")
        if alg not in self._config.allowed_token_algorithms:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "OIDC token signing algorithm is not allowed",
            )
        if alg not in {"RS256", "ES256", "EdDSA"}:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "OIDC token signing algorithm is not implemented",
            )

        doc = self.discover_oidc_issuer(issuer)
        jwks = _get_json(
            doc.jwks_uri,
            self._transport_config,
            self._config.http_client,
            self._config.timeout,
            self._config.allow_http_loopback_issuer,
        )
        signing_key = _key_by_id(jwks, str(header.get("kid") or ""))
        if signing_key is None or not _oidc_key_supports_alg(signing_key, alg):
            raise VerificationError(VerificationCode.SIGNATURE_INVALID, "OIDC signing key mismatch")

        parts = token.split(".")
        sig_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        try:
            sig_bytes = b64url_decode(parts[2])
        except Exception as exc:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID, "OIDC token signature encoding invalid"
            ) from exc
        if not _verify_oidc_signature(signing_key, alg, sig_input, sig_bytes):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID, "OIDC token signature invalid"
            )

        _validate_token_times(claims, self._config.clock_skew)
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC token missing sub")
        verified = None
        if opts.verify_dnsid_subject:
            verified = (
                self._resolver.verify_domain(sub, peer_cert=peer_cert)
                if peer_cert is not None
                else self._resolver.verify_domain(sub)
            )
        _validate_token_times(claims, self._config.clock_skew)
        return VerifiedOIDCSubject(
            issuer=issuer,
            subject=sub,
            audience=opts.audience,
            verified_domain=verified,
            claims=claims,
        )


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _sign_jwt(header: dict[str, Any], claims: dict[str, Any], key_provider: KeyProvider) -> str:
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("ascii"))
    claims_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode("ascii"))
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    return f"{header_b64}.{claims_b64}.{b64url_encode(key_provider.sign(signing_input))}"


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    return _decode_jwt_header_claims(token)


def _discovery_url(issuer: str) -> str:
    return f"{issuer}/.well-known/openid-configuration"


def _require_issuer(issuer: str | None) -> str:
    if issuer is None:
        raise ArgumentError("OIDC issuer is required")
    return issuer


def _first_non_empty(*values: str) -> str:
    for value in values:
        if value:
            return value
    return ""


def _scope_value(scope: str | list[str]) -> str:
    if isinstance(scope, str):
        return scope
    for token in scope:
        if not isinstance(token, str) or not token or token.strip() != token:
            raise ArgumentError("scope list entries must be non-empty tokens")
        if any(ch.isspace() for ch in token):
            raise ArgumentError("scope list entries must not contain whitespace")
    return " ".join(scope)


def _assertion_datetimes(
    claims: dict[str, Any],
) -> tuple[datetime.datetime | None, datetime.datetime | None]:
    iat = _numeric_date(claims.get("iat"))
    exp = _numeric_date(claims.get("exp"))
    issued_at = datetime.datetime.fromtimestamp(iat, datetime.UTC) if iat is not None else None
    expires_at = datetime.datetime.fromtimestamp(exp, datetime.UTC) if exp is not None else None
    return issued_at, expires_at


def _has_userinfo(parsed: Any) -> bool:
    return parsed.username is not None or parsed.password is not None


def _validate_configured_base_url(raw: str, name: str) -> str:
    p = urlparse(raw)
    if (
        not p.scheme
        or not p.netloc
        or p.params
        or p.query
        or p.fragment
        or _has_userinfo(p)
    ):
        raise ArgumentError(f"invalid OIDC {name}")
    if p.scheme == "https":
        return raw.rstrip("/")
    if p.scheme == "http" and _is_loopback_host(p.hostname or ""):
        return raw.rstrip("/")
    raise ArgumentError(f"OIDC {name} must use HTTPS unless it is loopback HTTP")


def _validate_configured_endpoint(raw: str, name: str) -> str:
    p = urlparse(raw)
    if (
        not p.scheme
        or not p.netloc
        or p.params
        or p.query
        or p.fragment
        or _has_userinfo(p)
    ):
        raise ArgumentError(f"invalid OIDC {name}")
    if not p.path:
        raise ArgumentError(f"OIDC {name} must include a path")
    if p.scheme == "https":
        return raw
    if p.scheme == "http" and _is_loopback_host(p.hostname or ""):
        return raw
    raise ArgumentError(f"OIDC {name} must use HTTPS unless it is loopback HTTP")


def _validate_exact_oidc_issuer(issuer: str, config: OIDCConfig) -> str:
    p = urlparse(issuer)
    if (
        not p.scheme
        or not p.netloc
        or p.params
        or p.query
        or p.fragment
        or _has_userinfo(p)
    ):
        raise ArgumentError("invalid OIDC issuer")
    if issuer.endswith("/"):
        raise ArgumentError("invalid OIDC issuer")
    if p.scheme == "https":
        return issuer
    if (
        p.scheme == "http"
        and config.allow_http_loopback_issuer
        and _is_loopback_host(p.hostname or "")
    ):
        return issuer
    raise ArgumentError("OIDC issuer must use HTTPS")


def _validate_discovered_issuer(issuer: str, config: OIDCConfig) -> str:
    try:
        return _validate_exact_oidc_issuer(issuer, config)
    except ArgumentError as exc:
        raise VerificationError(
            VerificationCode.RECORD_INVALID, "OIDC discovery issuer is invalid"
        ) from exc


def _is_loopback_host(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_same_origin_endpoint(endpoint: str, issuer: str, name: str) -> None:
    e = urlparse(endpoint)
    i = urlparse(issuer)
    if not e.scheme or not e.netloc or e.scheme != i.scheme or e.netloc != i.netloc:
        raise VerificationError(
            VerificationCode.RECORD_INVALID, f"OIDC {name} must use the issuer origin"
        )
    if not e.path or e.query or e.fragment:
        raise VerificationError(VerificationCode.RECORD_INVALID, f"invalid OIDC {name}")


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(VerificationCode.RECORD_INVALID, f"OIDC discovery missing {key}")
    return value


def _client(
    transport_config: TransportConfig | None = None,
    timeout: _Timeout | None = None,
    allow_loopback_host: str | None = None,
) -> httpx.Client:
    client_kwargs: dict[str, Any] = {
        "follow_redirects": False,
        "timeout": timeout if timeout is not None else _TIMEOUT,
    }
    from .safe_transport import make_ssrf_safe_transport

    client_kwargs["transport"] = make_ssrf_safe_transport(
        transport_config, allow_loopback_host=allow_loopback_host
    )
    return httpx.Client(**client_kwargs)


def _get_json(
    url: str,
    transport_config: TransportConfig | None = None,
    http_client: httpx.Client | None = None,
    timeout: _Timeout | None = None,
    allow_http_loopback: bool = False,
) -> dict[str, Any]:
    loopback_host = _loopback_http_host(url)
    if loopback_host is not None and not allow_http_loopback:
        raise ArgumentError("OIDC loopback HTTP requires explicit opt-in")
    def read(client: httpx.Client) -> dict[str, Any]:
        with client.stream(
            "GET", url, headers={"Accept": "application/json"},
            follow_redirects=False, timeout=bounded_http_timeout(timeout),
        ) as response:
            if response.is_redirect:
                raise NetworkError("OIDC redirects are not allowed")
            if response.status_code != 200:
                raise NetworkError(f"OIDC GET returned HTTP {response.status_code}")
            body = bytearray()
            for chunk in response.iter_bytes():
                remaining_seconds()
                if len(body) + len(chunk) > _MAX_BODY_BYTES:
                    raise NetworkError("OIDC response body too large")
                body.extend(chunk)
            return _response_json(httpx.Response(200, content=bytes(body)))

    try:
        if http_client is not None:
            return read(http_client)
        with _client(transport_config, timeout, loopback_host) as client:
            return read(client)
    except httpx.TransportError as exc:
        raise NetworkError(f"OIDC GET failed for {url!r}: {exc}") from exc


def _post_form_json(
    url: str,
    form: dict[str, str],
    transport_config: TransportConfig | None = None,
    http_client: httpx.Client | None = None,
    timeout: _Timeout | None = None,
    allow_http_loopback: bool = False,
) -> dict[str, Any]:
    loopback_host = _loopback_http_host(url)
    if loopback_host is not None and not allow_http_loopback:
        raise ArgumentError("OIDC loopback HTTP requires explicit opt-in")
    try:
        if http_client is not None:
            if timeout is not None:
                response = http_client.post(
                    url,
                    data=form,
                    headers={"Accept": "application/json"},
                    follow_redirects=False,
                    timeout=timeout,
                )
            else:
                response = http_client.post(
                    url,
                    data=form,
                    headers={"Accept": "application/json"},
                    follow_redirects=False,
                )
        else:
            with _client(
                transport_config, timeout, loopback_host
            ) as client:
                response = client.post(url, data=form, headers={"Accept": "application/json"})
    except httpx.TransportError as exc:
        raise NetworkError(f"OIDC token POST failed for {url!r}: {exc}") from exc
    if response.is_redirect:
        raise NetworkError("OIDC token endpoint redirects are not allowed")
    if response.status_code != 200:
        try:
            data = response.json()
        except Exception:
            data = {}
        raise OAuthError(str(data.get("error") or ""), str(data.get("error_description") or ""))
    return _response_json(response)


def _response_json(response: httpx.Response) -> dict[str, Any]:
    if len(response.content) > _MAX_BODY_BYTES:
        raise NetworkError("OIDC response body too large")
    try:
        data = response.json()
    except Exception as exc:
        raise VerificationError(
            VerificationCode.RECORD_INVALID, "OIDC response is not valid JSON"
        ) from exc
    if not isinstance(data, dict):
        raise VerificationError(
            VerificationCode.RECORD_INVALID, "OIDC response is not a JSON object"
        )
    return data


def _loopback_http_host(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host if parsed.scheme == "http" and _is_loopback_host(host) else None


def _to_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return []


def _key_by_id(jwks: dict[str, Any], kid: str) -> JWK | None:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    for raw in keys:
        if isinstance(raw, dict) and raw.get("kid") == kid:
            return jwk_from_dict(raw)
    return None


def _verify_oidc_signature(key: JWK, alg: str, payload: bytes, signature: bytes) -> bool:
    raw = key._raw if key._raw.get("alg") else {**key._raw, "alg": alg}
    return verify_signature(raw, payload, signature)


def _oidc_key_supports_alg(key: JWK, alg: str) -> bool:
    raw_alg = key._raw.get("alg")
    if raw_alg and raw_alg != alg:
        return False
    if key.use and key.use != "sig":
        return False
    key_ops = key._raw.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        return False
    if alg == "RS256":
        return key.kty == "RSA" and bool(key._raw.get("n")) and bool(key._raw.get("e"))
    try:
        return key.signature_alg() == alg
    except Exception:
        return False


def _numeric_date(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _validate_token_times(claims: dict[str, Any], skew_delta: datetime.timedelta) -> None:
    iat = _numeric_date(claims.get("iat"))
    exp = _numeric_date(claims.get("exp"))
    skew = skew_delta.total_seconds()
    now = _now().timestamp()
    if exp is None:
        raise VerificationError(
            VerificationCode.RECORD_INVALID, "OIDC token missing or invalid exp"
        )
    if iat is None:
        raise VerificationError(
            VerificationCode.RECORD_INVALID, "OIDC token missing or invalid iat"
        )
    if exp <= iat:
        raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC token exp must be after iat")
    nbf = claims.get("nbf")
    if "nbf" in claims:
        nbf_ts = _numeric_date(nbf)
        if nbf_ts is None:
            raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC token invalid nbf")
        if now + skew < nbf_ts:
            raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC token not yet valid")
    if iat > now + skew:
        raise VerificationError(
            VerificationCode.RECORD_INVALID, "OIDC token issued-at time is in the future"
        )
    if exp <= now:
        raise VerificationError(VerificationCode.RECORD_INVALID, "OIDC token is expired")
