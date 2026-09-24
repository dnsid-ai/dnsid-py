"""Web Bot Authentication profile.

Application-layer helpers for authenticating web bots/agents via HTTP requests
using DNSid-issued JWTs in the ``Authorization: Bearer`` header.

This profile implements the Agent Identity Assertion (AIA) pattern where:
- Outbound bot requests carry a signed JWT identifying the bot's domain
- Inbound requests can be verified by resolving the JWT issuer's DNSid identity

The JWT includes a ``bot`` claim containing metadata about the bot (name, version,
purpose, operator URL) to comply with emerging web bot identification standards.

Usage::

    from dnsid import IdentityManager
    from dnsid.web_bot_auth import WebBotAuthProfile, BotIdentity, BotAuthConfig

    manager = IdentityManager(config, key_provider)
    bot_auth = WebBotAuthProfile.from_identity_manager(
        manager,
        bot=BotIdentity(
            name="AcmeBot",
            version="1.0",
            purpose="data-collection",
            operator_url="https://acme.example/bot-info",
        ),
    )

    # Sign an outbound request
    import httpx
    request = httpx.Request("GET", "https://target.example/api/data")
    signed = bot_auth.sign_bot_request(request)

    # Verify an inbound request
    verified = bot_auth.verify_bot_request(
        headers={"authorization": "Bearer <jwt>"},
        expected_audience="https://target.example",
    )
"""

from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

from ._utils import APPLICATION_JOSE_ALGS, b64url_decode, b64url_encode, normalize_fqdn
from .enums import VerificationCode
from .exceptions import ArgumentError, VerificationError
from .interfaces import IdentityResolver, KeyProvider
from .models import TLSCertificate, VerifiedDomain


@dataclass
class BotIdentity:
    """Metadata describing the bot/agent for inclusion in the JWT ``bot`` claim.

    Attributes:
        name: Human-readable bot name (e.g. "AcmeSearchBot").
        version: Bot version string (e.g. "1.2.3").
        purpose: Short machine-readable purpose tag. Common values:
            "search-indexing", "data-collection", "monitoring", "ai-training",
            "summarization".
        operator_url: URL with more info about the bot and its operator (like
            robots.txt contact info). Should be an HTTPS URL.
    """

    name: str
    version: str = ""
    purpose: str = ""
    operator_url: str = ""


@dataclass
class BotAuthConfig:
    """Configuration for the Web Bot Auth profile.

    Attributes:
        max_lifetime: Maximum acceptable JWT lifetime. Default 15 minutes.
        clock_skew: Allowed clock skew tolerance. Default 60 seconds.
        require_bot_claim: If True, verification rejects JWTs without a
            ``bot`` claim.
    """

    max_lifetime: datetime.timedelta = field(
        default_factory=lambda: datetime.timedelta(minutes=15)
    )
    clock_skew: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(seconds=60))
    require_bot_claim: bool = False


@dataclass
class VerifiedBotRequest:
    """Result of successful bot request verification.

    Attributes:
        domain: The verified DNSid domain of the bot.
        bot: Bot identity metadata extracted from the JWT ``bot`` claim, or
            None.
        verified_domain: The full VerifiedDomain result from DNSid resolution.
        claims: The decoded JWT claims.
    """

    domain: str
    bot: BotIdentity | None
    verified_domain: VerifiedDomain
    claims: dict[str, Any]


_DEFAULT_BOT_JWT_EXPIRY = datetime.timedelta(minutes=5)


class WebBotAuthProfile:
    """Web bot authentication helpers using DNSid-issued JWTs.

    Implements the Agent Identity Assertion (AIA) pattern for HTTP bot auth:
    - Signs outbound requests with ``Authorization: Bearer <dnsid-jwt>``
    - Verifies inbound requests by validating the Bearer token

    An application profile layered on top of DNSid identity verification.
    Application profiles are not part of the core DNSid protocol and are not
    required for DNSid conformance.
    """

    @classmethod
    def from_identity_manager(
        cls,
        manager: object,
        bot: BotIdentity | None = None,
        config: BotAuthConfig | None = None,
    ) -> WebBotAuthProfile:
        """Construct from a fully-initialised IdentityManager.

        Reads domain and key_provider from the manager.
        """
        return cls(
            resolver=manager,  # type: ignore[arg-type]
            key_provider=manager._key_provider,  # type: ignore[attr-defined]
            domain=manager.local_domain,  # type: ignore[attr-defined]
            bot=bot,
            config=config,
        )

    def __init__(
        self,
        resolver: IdentityResolver,
        key_provider: KeyProvider | None,
        domain: str,
        bot: BotIdentity | None = None,
        config: BotAuthConfig | None = None,
    ) -> None:
        """Initialize the profile for a local bot identity.

        Args:
            resolver: Any object satisfying the IdentityResolver protocol.
            key_provider: Key management implementation for the local bot
                identity, or None for a verification-only profile.
            domain: FQDN of the local bot identity, or "" when
                verification-only.
            bot: Bot metadata to include in signed JWTs.
            config: Optional freshness/verification overrides.
        """
        self._resolver = resolver
        self._key_provider = key_provider
        self._domain = normalize_fqdn(domain) if domain else ""
        self._bot = bot
        self._config = config or BotAuthConfig()

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def create_bot_token(
        self,
        target_url: str,
        *,
        expiry: datetime.timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a signed JWT for bot authentication.

        The JWT includes:
        - ``iss``/``sub``: the bot's DNSid domain
        - ``aud``: the target URL origin (scheme + host)
        - ``bot``: bot identity metadata
        - ``iat``, ``exp``, ``jti``: standard temporal claims

        Args:
            target_url: The URL being requested. The audience is derived from
                its origin.
            expiry: Token lifetime. Default 5 minutes.
            additional_claims: Extra claims to include in the JWT payload.

        Returns:
            The signed JWT in compact serialization.

        Raises:
            ArgumentError: If the profile is verification-only, ``target_url``
                is not a valid URL, the requested expiry exceeds the configured
                maximum lifetime, or ``additional_claims`` would override a
                reserved claim.
        """
        import json
        from urllib.parse import urlparse

        if self._key_provider is None or not self._domain:
            raise ArgumentError(
                "bot token signing requires a key_provider; profile is verification-only"
            )
        key_provider = self._key_provider

        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.hostname:
            raise ArgumentError("target_url must be a valid URL with scheme and host")

        # Audience is the origin (scheme://host[:port])
        port_suffix = ""
        if parsed.port and not (
            (parsed.scheme == "https" and parsed.port == 443)
            or (parsed.scheme == "http" and parsed.port == 80)
        ):
            port_suffix = f":{parsed.port}"
        audience = f"{parsed.scheme}://{parsed.hostname}{port_suffix}"

        token_expiry = expiry or _DEFAULT_BOT_JWT_EXPIRY
        if token_expiry > self._config.max_lifetime:
            raise ArgumentError("bot token expiry exceeds maximum lifetime")

        now = _now()
        extra = additional_claims or {}

        _RESERVED = {"iss", "sub", "aud", "iat", "exp", "jti", "bot"}
        for key in extra:
            if key in _RESERVED:
                raise ArgumentError(
                    f"additional_claims must not override reserved claim: {key!r}"
                )

        claims: dict[str, Any] = {
            "iss": self._domain,
            "sub": self._domain,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + token_expiry).timestamp()),
            "jti": str(uuid.uuid4()),
        }

        if self._bot:
            bot_claim: dict[str, str] = {"name": self._bot.name}
            if self._bot.version:
                bot_claim["version"] = self._bot.version
            if self._bot.purpose:
                bot_claim["purpose"] = self._bot.purpose
            if self._bot.operator_url:
                bot_claim["operator_url"] = self._bot.operator_url
            claims["bot"] = bot_claim

        claims.update(extra)

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

    def sign_bot_request(
        self,
        request: httpx.Request,
        *,
        expiry: datetime.timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> httpx.Request:
        """Sign an outbound httpx.Request with a bot auth JWT.

        Adds an ``Authorization: Bearer <jwt>`` header to the request and
        sets a ``User-Agent`` header incorporating the bot identity.

        Args:
            request: The httpx.Request to sign.
            expiry: Token lifetime override.
            additional_claims: Extra claims for the JWT.

        Returns:
            A new httpx.Request with the Authorization header set.

        Raises:
            ArgumentError: Propagated from token creation (invalid URL, expiry
                over the maximum, or reserved-claim override).
        """
        import httpx as _httpx

        token = self.create_bot_token(
            str(request.url),
            expiry=expiry,
            additional_claims=additional_claims,
        )

        # Build updated headers
        headers = dict(request.headers)
        headers["authorization"] = f"Bearer {token}"

        if self._bot:
            ua_parts = [self._bot.name]
            if self._bot.version:
                ua_parts[0] = f"{self._bot.name}/{self._bot.version}"
            if self._bot.operator_url:
                ua_parts.append(f"(+{self._bot.operator_url})")
            headers["user-agent"] = " ".join(ua_parts)

        return _httpx.Request(
            method=request.method,
            url=request.url,
            headers=headers,
            content=request.content if request.content else None,
            extensions=request.extensions,
        )

    def create_signed_bot_client(
        self,
        *,
        expiry: datetime.timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
        base_headers: dict[str, str] | None = None,
    ) -> httpx.Client:
        """Return an httpx.Client that automatically signs every request with bot auth.

        Every outbound request gets an ``Authorization: Bearer <dnsid-jwt>`` header.

        Args:
            expiry: Token lifetime override applied to every request.
            additional_claims: Extra claims added to every JWT.
            base_headers: Default headers applied to every request.

        Returns:
            An httpx.Client that signs each request before sending it.
        """
        import httpx

        profile = self
        _expiry = expiry
        _extra = additional_claims

        class _BotAuthTransport(httpx.BaseTransport):
            def __init__(self) -> None:
                self._inner = httpx.HTTPTransport()

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                signed = profile.sign_bot_request(
                    request, expiry=_expiry, additional_claims=_extra
                )
                return self._inner.handle_request(signed)

        return httpx.Client(headers=base_headers or {}, transport=_BotAuthTransport())

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_bot_request(
        self,
        *,
        headers: dict[str, str],
        expected_audience: str,
        peer_cert: TLSCertificate | None = None,
    ) -> VerifiedBotRequest:
        """Verify an inbound bot request by validating its Authorization Bearer JWT.

        Resolves the JWT issuer's DNSid identity and verifies the signature.

        Args:
            headers: The HTTP request headers (case-insensitive lookup for
                Authorization).
            expected_audience: Required trusted origin of the server receiving
                the request; the JWT ``aud`` claim must match this value.
            peer_cert: Certificate from the current peer connection. Required
                when the issuer's DNSid record carries ``fl=mtls``.

        Returns:
            A VerifiedBotRequest with the verified domain and bot metadata.

        Raises:
            VerificationError: If the token is missing, malformed, expired, or
                signature-invalid, or a claim fails validation; also
                propagated from issuer identity verification.  Carries a
                VerificationCode.
        """
        if not isinstance(expected_audience, str) or not expected_audience:
            raise ArgumentError("expected_audience must be a non-empty string")

        # Extract token from Authorization header
        auth_value = _get_header_ci(headers, "authorization")
        if not auth_value:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "missing Authorization header",
            )

        if not auth_value.lower().startswith("bearer "):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "Authorization header must use Bearer scheme",
            )

        token = auth_value[7:].strip()
        if not token:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "empty Bearer token",
            )

        # Decode and validate
        header, claims = _decode_jwt_parts(token)

        iss = claims.get("iss")
        if not iss:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT missing iss claim"
            )
        if not isinstance(iss, str):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"JWT iss claim must be a string, got {type(iss).__name__}",
            )
        iss = normalize_fqdn(iss)

        sub = claims.get("sub", "")
        if "sub" in claims and not isinstance(sub, str):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"JWT sub claim must be a string, got {type(sub).__name__}",
            )
        if sub and normalize_fqdn(sub) != iss:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT sub must equal iss"
            )

        # Audience check
        aud_raw = claims.get("aud")
        if aud_raw is None:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"JWT audience mismatch: expected {expected_audience!r}",
            )
        if isinstance(aud_raw, str):
            aud_list = [aud_raw]
        elif isinstance(aud_raw, list):
            # Validate all list members are strings
            for item in aud_raw:
                if not isinstance(item, str):
                    raise VerificationError(
                        VerificationCode.RECORD_INVALID,
                        "JWT aud claim contains non-string value",
                    )
            aud_list = aud_raw
        else:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "JWT aud claim must be a string or array of strings",
            )
        if expected_audience not in aud_list:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"JWT audience mismatch: expected {expected_audience!r}",
            )

        # Temporal validation
        now_ts = int(_now().timestamp())
        clock_skew = int(self._config.clock_skew.total_seconds())
        max_lifetime = int(self._config.max_lifetime.total_seconds())

        iat = claims.get("iat", 0)
        if not isinstance(iat, int) or isinstance(iat, bool):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "JWT iat claim must be an integer",
            )
        if not iat:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT missing iat claim"
            )
        if iat > (now_ts + clock_skew):
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT iat is in the future"
            )

        exp = claims.get("exp", 0)
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "JWT exp claim must be an integer",
            )
        if not exp:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT missing exp claim"
            )
        if exp <= iat:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT exp must be after iat"
            )
        if (exp - iat) > max_lifetime:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT lifetime exceeds maximum"
            )
        if exp < now_ts:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWT is expired"
            )

        # Bot claim
        bot_data = claims.get("bot")
        if self._config.require_bot_claim:
            if not bot_data:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "JWT missing required bot claim",
                )
            if not isinstance(bot_data, dict):
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    f"JWT bot claim must be an object, got {type(bot_data).__name__}",
                )

        bot_identity: BotIdentity | None = None
        if isinstance(bot_data, dict):
            bot_identity = BotIdentity(
                name=bot_data.get("name", ""),
                version=bot_data.get("version", ""),
                purpose=bot_data.get("purpose", ""),
                operator_url=bot_data.get("operator_url", ""),
            )

        # Resolve issuer DNSid identity and verify signature
        verified_domain = (
            self._resolver.verify_domain(iss, peer_cert=peer_cert)
            if peer_cert is not None
            else self._resolver.verify_domain(iss)
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
                f"JWT alg not in allowlist: {alg!r}",
            )
        key_alg = signing_key.signature_alg()
        if alg != key_alg:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"JWT alg mismatch: header {alg!r} vs key {key_alg!r}",
            )

        parts = token.split(".")
        sig_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        sig = b64url_decode(parts[2])
        if not signing_key.verify(sig_input, sig):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID, "JWT signature invalid"
            )

        return VerifiedBotRequest(
            domain=iss,
            bot=bot_identity,
            verified_domain=verified_domain,
            claims=claims,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _get_header_ci(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return ""


def _decode_jwt_parts(jwt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    import json

    parts = jwt.split(".")
    if len(parts) != 3:
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            "malformed JWT: expected 3 dot-separated components",
        )
    header: dict[str, Any] = json.loads(b64url_decode(parts[0]))
    claims: dict[str, Any] = json.loads(b64url_decode(parts[1]))
    return header, claims
