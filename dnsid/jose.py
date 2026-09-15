"""JOSE profile: JWT and JWS helpers (RFC 7515, RFC 7519).

Application-layer conveniences built on top of DNSid identity verification.
Not part of the DNSid protocol; not required for DNSid conformance.

Usage::

    from dnsid import IdentityManager, IdentityManagerDependencies
    from dnsid.jose import JoseProfile, JoseConfig

    manager = IdentityManager(config, key_provider)
    jose = JoseProfile(
        resolver=manager,
        key_provider=key_provider,
        domain=config.identity.domain,
    )

    # Outbound: authenticate to a counterparty
    token = jose.create_jwt(JWTOptions(audience="other-agent.example"))

    # Inbound: verify a token from a counterparty
    verified = jose.verify_jwt(token)
"""

from __future__ import annotations

import datetime
import math
import uuid
from collections.abc import Container
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ._verification_budget import verification_operation

if TYPE_CHECKING:
    pass

from ._utils import (
    APPLICATION_JOSE_ALGS,
    b64url_decode_strict,
    b64url_encode,
    normalize_fqdn,
    parse_key_id,
)
from .enums import VerificationCode
from .exceptions import ArgumentError, VerificationError
from .interfaces import IdentityResolver, KeyProvider
from .models import JWTOptions, TLSCertificate, VerifiedDomain

_DEFAULT_JWT_EXPIRY = datetime.timedelta(minutes=15)


@dataclass
class JoseConfig:
    """Freshness settings for the JOSE profile."""

    max_lifetime: datetime.timedelta = field(
        default_factory=lambda: datetime.timedelta(seconds=900)
    )
    clock_skew: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(seconds=60))


class JoseProfile:
    """JWT and JWS helpers for a DNSid identity.

    An application profile layered on top of DNSid identity verification.
    Application profiles are not part of the core DNSid protocol and are not
    required for DNSid conformance.
    """

    @classmethod
    def from_identity_manager(
        cls,
        manager: object,
        config: JoseConfig | None = None,
    ) -> JoseProfile:
        """Construct a JoseProfile from a fully-initialised IdentityManager.

        Reads domain and key_provider from the manager so callers don't need to
        repeat them.  Mirrors ``JoseProfile.fromIdentityManager(idm)`` in the
        TypeScript SDK.
        """
        return cls(
            resolver=manager,  # type: ignore[arg-type]
            key_provider=manager._key_provider,  # type: ignore[attr-defined]
            domain=manager.local_domain,  # type: ignore[attr-defined]
            config=config,
        )

    def __init__(
        self,
        resolver: IdentityResolver,
        key_provider: KeyProvider | None = None,
        domain: str = "",
        config: JoseConfig | None = None,
    ) -> None:
        """Initialize the profile for a local DNSid identity.

        Args:
            resolver: Any object satisfying the IdentityResolver protocol
                (IdentityManager or a test double with a verify_domain method).
            key_provider: Key management implementation for the local identity.
            domain: FQDN of the local identity. Used as iss/sub in JWTs and as
                the domain portion of the ``{domain}#{kid}`` kid in JWS. Omit
                for verification-only use with an explicit expected audience.
            config: Optional freshness overrides.  Defaults to 900 s lifetime /
                60 s skew.
        """
        self._resolver = resolver
        self._key_provider = key_provider
        self._domain = normalize_fqdn(domain) if domain else ""
        self._config = config or JoseConfig()
        _validate_duration(self._config.max_lifetime, "max_lifetime")
        _validate_duration(self._config.clock_skew, "clock_skew", allow_zero=True)

    def _require_signing_provider(self) -> KeyProvider:
        if self._key_provider is None or not self._domain:
            raise ArgumentError(
                "JOSE signing requires a key_provider; profile is verification-only"
            )
        return self._key_provider

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------

    def create_jwt(self, opts: JWTOptions) -> str:
        """Create a self-signed JWT for authenticating to a counterparty identity.

        iss and sub are set to the local domain; aud is opts.audience.

        Args:
            opts: JWT creation options; ``audience`` is required.

        Returns:
            The signed JWT in compact serialization.

        Raises:
            ArgumentError: If ``audience`` is missing, the requested expiry
                exceeds the configured maximum lifetime, or
                ``additional_claims`` would override a reserved claim.
        """
        import json

        if not opts.audience:
            raise ArgumentError("audience is required")

        expiry = opts.expiry if opts.expiry is not None else _DEFAULT_JWT_EXPIRY
        _validate_duration(expiry, "JWT expiry")
        if expiry > self._config.max_lifetime:
            raise ArgumentError("JWT expiry exceeds maximum lifetime")

        now = _now()
        aud = normalize_fqdn(opts.audience)

        _RESERVED = {"iss", "sub", "aud", "iat", "exp", "jti"}
        for key in opts.additional_claims:
            if key in _RESERVED:
                raise ArgumentError(f"additional_claims must not override reserved claim: {key!r}")

        claims: dict[str, Any] = {
            "iss": self._domain,
            "sub": self._domain,
            "aud": aud,
            "iat": int(now.timestamp()),
            "exp": int((now + expiry).timestamp()),
            "jti": str(uuid.uuid4()),
            **opts.additional_claims,
        }

        if claims["exp"] <= claims["iat"]:
            raise ArgumentError("JWT expiry is below timestamp resolution")
        key_provider = self._require_signing_provider()
        signing_key = key_provider.signing_key()
        header = {
            "alg": signing_key.signature_alg(),
            "kid": signing_key.kid,
            "typ": "JWT",
        }

        header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("ascii"))
        claims_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode("ascii"))
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
        sig_bytes = key_provider.sign(signing_input)
        return f"{header_b64}.{claims_b64}.{b64url_encode(sig_bytes)}"

    @verification_operation
    def verify_jwt(
        self, jwt: str, *, expected_audience: str | None = None,
        peer_cert: TLSCertificate | None = None
    ) -> VerifiedDomain:
        """Verify a JWT received from a counterparty.

        Validates the DNSid identity of the issuer, then verifies the JWT
        signature against the issuer's verified signing key.

        Args:
            jwt: The JWT compact serialization to verify.
            expected_audience: Trusted FQDN audience; defaults to the local domain.
                Required for a verification-only profile without a local domain.
            peer_cert: Certificate from the current peer connection. Required
                when the issuer's DNSid record carries ``fl=mtls``.

        Returns:
            The VerifiedDomain for the issuer's DNSid identity.  The decoded
            claims payload is not returned — timing claims and the signature
            are validated internally; decode the JWT's payload segment
            separately if the application needs its claims.

        Raises:
            VerificationError: If the JWT is malformed, a claim fails
                validation (iss/sub/aud/iat/exp/nbf), the alg is not in the
                application-layer allowlist, the kid is unknown, or the
                signature is invalid; also propagated from issuer identity
                verification.  Carries a VerificationCode.
        """
        audience = self._domain if expected_audience is None else expected_audience
        if not isinstance(audience, str) or not audience:
            raise ArgumentError("expected audience is required")
        try:
            audience = normalize_fqdn(audience)
        except Exception as exc:
            raise ArgumentError("expected audience must be an FQDN") from exc
        header, claims = _decode_jwt_header_claims(jwt)
        _validate_protected_header(header, APPLICATION_JOSE_ALGS)

        if not isinstance(claims.get("iss"), str) or not claims["iss"]:
            raise VerificationError(VerificationCode.RECORD_INVALID, "JWT missing iss claim")

        iss = _claim_fqdn(claims["iss"])
        sub = _claim_fqdn(claims.get("sub"))
        if sub != iss:
            raise VerificationError(VerificationCode.RECORD_INVALID, "JWT sub must equal iss")

        aud_raw = claims.get("aud", [])
        aud_list = [aud_raw] if isinstance(aud_raw, str) else aud_raw
        if not isinstance(aud_list, list) or not aud_list:
            raise VerificationError(VerificationCode.RECORD_INVALID, "invalid JWT audience")
        if audience not in [_claim_fqdn(a) for a in aud_list]:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"JWT audience mismatch: {audience!r} not in aud",
            )

        now_ts = _now().timestamp()
        clock_skew = self._config.clock_skew.total_seconds()
        max_lifetime = self._config.max_lifetime.total_seconds()

        iat = _require_numeric_date(claims, "iat")
        if iat > (now_ts + clock_skew):
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT issued-at time is in the future"
            )

        exp = _require_numeric_date(claims, "exp")
        if exp <= iat:
            raise VerificationError(VerificationCode.RECORD_INVALID, "JWT exp must be after iat")
        if (exp - iat) > max_lifetime:
            raise VerificationError(VerificationCode.RECORD_INVALID, "JWT lifetime exceeds maximum")
        if exp <= now_ts:
            raise VerificationError(VerificationCode.RECORD_INVALID, "JWT is expired")

        if "nbf" in claims and (now_ts + clock_skew) < _require_numeric_date(claims, "nbf"):
            raise VerificationError(VerificationCode.RECORD_INVALID, "JWT not yet valid (nbf)")

        verified_domain = (
            self._resolver.verify_domain(claims["iss"], peer_cert=peer_cert)
            if peer_cert is not None
            else self._resolver.verify_domain(claims["iss"])
        )

        kid = header.get("kid", "")
        signing_key = verified_domain.jwks.key_by_id(kid)
        if signing_key is None:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "JWT kid not found in issuer JWKS",
            )

        alg = header.get("alg", "")
        if alg not in APPLICATION_JOSE_ALGS:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"JWT alg not in application-layer allowlist: {alg!r}",
            )
        key_alg = signing_key.signature_alg()
        if alg != key_alg:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"JWT alg mismatch: header declares {alg!r} but key binding implies {key_alg!r}",
            )

        parts = jwt.split(".")
        sig_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        sig = b64url_decode_strict(parts[2])
        if not signing_key.verify(sig_input, sig):
            raise VerificationError(VerificationCode.SIGNATURE_INVALID, "JWT signature invalid")

        if exp <= _now().timestamp():
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT expired during verification"
            )
        return verified_domain

    # ------------------------------------------------------------------
    # JWS
    # ------------------------------------------------------------------

    def create_jws(self, payload: bytes) -> str:
        """Produce a JWS compact serialization (RFC 7515).

        kid is encoded as ``{domain}#{kid}`` to enable verify_jws to resolve
        the signer.

        Args:
            payload: Raw bytes to sign.

        Returns:
            The JWS compact serialization.

        Raises:
            ArgumentError: If the signing key kid contains ``'#'``.
        """
        import json

        key_provider = self._require_signing_provider()
        signing_key = key_provider.signing_key()
        if "#" in signing_key.kid:
            raise ArgumentError("signing key kid must not contain '#'")

        header = {
            "alg": signing_key.signature_alg(),
            "kid": f"{self._domain}#{signing_key.kid}",
            "typ": "jose",
        }
        header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("ascii"))
        payload_b64 = b64url_encode(payload)
        sig_input = f"{header_b64}.{payload_b64}".encode("ascii")
        sig_bytes = key_provider.sign(sig_input)
        return f"{header_b64}.{payload_b64}.{b64url_encode(sig_bytes)}"

    @verification_operation
    def verify_jws(
        self, jws: str, *, peer_cert: TLSCertificate | None = None
    ) -> tuple[bytes, VerifiedDomain]:
        """Verify a JWS compact serialization from a counterparty (RFC 7515).

        Args:
            jws: The JWS compact serialization to verify.
            peer_cert: Certificate from the current peer connection. Required
                when the signer's DNSid record carries ``fl=mtls``.

        Returns:
            ``(payload_bytes, verified_domain)`` — the decoded payload and the
            VerifiedDomain for the signer's DNSid identity.

        Raises:
            VerificationError: If the JWS is malformed, the kid header is
                missing or unknown, the alg is not in the application-layer
                allowlist, or the signature is invalid; also propagated from
                signer identity verification.  Carries a VerificationCode.
        """
        parts = _compact_parts(jws)
        header_b64, payload_b64, sig_b64 = parts

        header: dict[str, Any] = _b64url_decode_json(header_b64)
        _validate_protected_header(header, APPLICATION_JOSE_ALGS)
        payload = _decode_segment(payload_b64)

        if not header.get("kid"):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "JWS missing kid header parameter",
            )

        domain, kid = parse_key_id(header["kid"])
        verified_domain = (
            self._resolver.verify_domain(domain, peer_cert=peer_cert)
            if peer_cert is not None
            else self._resolver.verify_domain(domain)
        )

        signing_key = verified_domain.jwks.key_by_id(kid)
        if signing_key is None:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "JWS kid not found in signer JWKS",
            )

        alg = header.get("alg", "")
        if alg not in APPLICATION_JOSE_ALGS:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"JWS alg not in application-layer allowlist: {alg!r}",
            )
        key_alg = signing_key.signature_alg()
        if alg != key_alg:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"JWS alg mismatch: header declares {alg!r} but key binding implies {key_alg!r}",
            )

        sig_input = (header_b64 + "." + payload_b64).encode("ascii")
        sig = _decode_segment(sig_b64)
        if not signing_key.verify(sig_input, sig):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "JWS signature invalid",
            )

        return payload, verified_domain


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _decode_jwt_header_claims(jwt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = _compact_parts(jwt)
    return _b64url_decode_json(parts[0]), _b64url_decode_json(parts[1])


def _b64url_decode_json(b64: str) -> dict[str, Any]:
    import json

    def members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        def invalid_constant(value: str) -> None:
            raise ValueError(f"invalid JSON constant: {value}")

        result = json.loads(
            _decode_segment(b64).decode("utf-8"), object_pairs_hook=members,
            parse_constant=invalid_constant,
        )
        if not isinstance(result, dict):
            raise ValueError("expected JSON object")
        return result
    except (ValueError, UnicodeError) as exc:
        raise VerificationError(VerificationCode.RECORD_INVALID, "malformed JOSE JSON") from exc


def _compact_parts(token: str) -> list[str]:
    # Standalone bounds: 1 MiB compact token, 16 KiB encoded protected header.
    if not isinstance(token, str) or len(token) > 1024 * 1024:
        raise VerificationError(VerificationCode.RECORD_INVALID, "JOSE token exceeds size limit")
    parts = token.split(".")
    if len(parts) != 3 or len(parts[0]) > 16384:
        raise VerificationError(VerificationCode.RECORD_INVALID, "malformed JOSE compact token")
    for part in parts:
        _decode_segment(part)
    return parts


def _decode_segment(value: str) -> bytes:
    try:
        decoded = b64url_decode_strict(value) if value else b""
        if b64url_encode(decoded) != value:
            raise ValueError("non-canonical base64url")
        return decoded
    except (ValueError, UnicodeError) as exc:
        raise VerificationError(VerificationCode.RECORD_INVALID, "invalid JOSE base64url") from exc


def _validate_protected_header(header: dict[str, Any], algorithms: Container[str]) -> None:
    if (not isinstance(header.get("alg"), str) or not header["alg"]
            or not isinstance(header.get("kid"), str) or not header["kid"]
            or ("typ" in header and not isinstance(header["typ"], str))
            or "crit" in header or ("b64" in header and header["b64"] is not True)):
        raise VerificationError(VerificationCode.RECORD_INVALID, "invalid JOSE protected header")
    if header["alg"] not in algorithms:
        raise VerificationError(VerificationCode.SIGNATURE_INVALID, "JOSE algorithm is not allowed")


def _require_numeric_date(claims: dict[str, Any], name: str) -> int | float:
    value = claims.get(name)
    if (isinstance(value, bool) or not isinstance(value, int | float)
            or (isinstance(value, float) and not math.isfinite(value))):
        raise VerificationError(VerificationCode.RECORD_INVALID, f"missing or invalid {name}")
    return value


def _claim_fqdn(value: Any) -> str:
    try:
        if not isinstance(value, str) or not value:
            raise ValueError("expected FQDN string")
        return normalize_fqdn(value)
    except Exception as exc:
        raise VerificationError(VerificationCode.RECORD_INVALID, "invalid JWT FQDN claim") from exc


def _validate_duration(value: object, name: str, *, allow_zero: bool = False) -> None:
    if not isinstance(value, datetime.timedelta) or (
        value < datetime.timedelta(0) if allow_zero else value <= datetime.timedelta(0)
    ):
        bound = "non-negative" if allow_zero else "positive"
        raise ArgumentError(f"{name} must be a {bound} finite duration")
