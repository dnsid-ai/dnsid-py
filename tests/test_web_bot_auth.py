"""Tests for WebBotAuthProfile — sign_bot_request and verify_bot_request."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

from dnsid import (
    JWKS,
    IdentityManager,
    IdentityManagerDependencies,
    TLSCertificate,
)
from dnsid._utils import b64url_decode, b64url_encode
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.web_bot_auth import (
    BotAuthConfig,
    BotIdentity,
    WebBotAuthProfile,
)
from tests._config import make_config
from tests.conftest import MockDNSResolver, RealKeyProvider, make_ec_p256_pair


class _FakeVerifiedDomain:
    """Lightweight stand-in for VerifiedDomain with just the fields we need."""

    def __init__(self, domain: str, jwks: JWKS):
        self.domain = domain
        self.jwks = jwks


def _build_bot_profile(
    provider,
    domain="bot.example.com",
    bot=None,
    config=None,
):
    """Build a WebBotAuthProfile backed by a real-crypto provider."""
    with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
        mgr = IdentityManager(
            make_config(
                domain=domain,
                governance_id="example.com",
                log_ref="microledger:abc",
                status_url=f"https://{domain}/status",
            ),
            provider,
            deps=IdentityManagerDependencies(dns_resolver=MockDNSResolver()),
        )
    return WebBotAuthProfile(
        resolver=mgr,
        key_provider=provider,
        domain=domain,
        bot=bot,
        config=config,
    )


def _decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    return header, claims


def _make_verifying_profile(
    signer_provider,
    signer_domain="bot.example.com",
    verifier_domain="server.example.com",
    config=None,
):
    """Build a profile that can verify tokens issued by signer_provider."""
    pub_key = signer_provider.signing_key()
    jwks = JWKS(keys=[pub_key])
    mock_vd = _FakeVerifiedDomain(domain=signer_domain, jwks=jwks)

    class FakeResolver:
        def verify_domain(self, domain: str):
            if domain == signer_domain:
                return mock_vd
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"unknown domain: {domain}",
            )

    verifier_private, verifier_pub = make_ec_p256_pair("v1")
    verifier_provider = RealKeyProvider("v1", {"v1": (verifier_private, verifier_pub)})

    return WebBotAuthProfile(
        resolver=FakeResolver(),
        key_provider=verifier_provider,
        domain=verifier_domain,
        config=config,
    )


# ---------------------------------------------------------------------------
# Token creation tests
# ---------------------------------------------------------------------------


class TestCreateBotToken:
    def test_returns_three_part_jwt(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com/api")
        assert len(token.split(".")) == 3

    def test_header_fields(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com/api")
        header, _ = _decode_jwt(token)
        assert header["alg"] == "ES256"
        assert header["kid"] == "k1"
        assert header["typ"] == "JWT"

    def test_claims_iss_sub_are_domain(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com/api")
        _, claims = _decode_jwt(token)
        assert claims["iss"] == "bot.example.com"
        assert claims["sub"] == "bot.example.com"

    def test_audience_is_origin(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com/api/v1/data?q=1")
        _, claims = _decode_jwt(token)
        assert claims["aud"] == "https://target.example.com"

    def test_audience_includes_non_default_port(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com:8443/api")
        _, claims = _decode_jwt(token)
        assert claims["aud"] == "https://target.example.com:8443"

    def test_audience_excludes_default_https_port(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com:443/api")
        _, claims = _decode_jwt(token)
        assert claims["aud"] == "https://target.example.com"

    def test_bot_claim_included(self, ec_provider):
        bot = BotIdentity(
            name="TestBot",
            version="2.0",
            purpose="testing",
            operator_url="https://bot.example.com/info",
        )
        profile = _build_bot_profile(ec_provider, bot=bot)
        token = profile.create_bot_token("https://target.example.com/api")
        _, claims = _decode_jwt(token)
        assert claims["bot"]["name"] == "TestBot"
        assert claims["bot"]["version"] == "2.0"
        assert claims["bot"]["purpose"] == "testing"
        assert claims["bot"]["operator_url"] == "https://bot.example.com/info"

    def test_no_bot_claim_when_no_bot_identity(self, ec_provider):
        profile = _build_bot_profile(ec_provider, bot=None)
        token = profile.create_bot_token("https://target.example.com/api")
        _, claims = _decode_jwt(token)
        assert "bot" not in claims

    def test_exp_in_future(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com/api")
        _, claims = _decode_jwt(token)
        assert claims["exp"] > int(time.time())

    def test_jti_is_uuid(self, ec_provider):
        import uuid

        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token("https://target.example.com/api")
        _, claims = _decode_jwt(token)
        uuid.UUID(claims["jti"])  # raises if not valid UUID

    def test_additional_claims(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        token = profile.create_bot_token(
            "https://target.example.com/api",
            additional_claims={"custom": "value"},
        )
        _, claims = _decode_jwt(token)
        assert claims["custom"] == "value"

    def test_rejects_reserved_additional_claims(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        with pytest.raises(ArgumentError, match="reserved claim"):
            profile.create_bot_token(
                "https://target.example.com/api",
                additional_claims={"iss": "evil"},
            )

    def test_rejects_invalid_url(self, ec_provider):
        profile = _build_bot_profile(ec_provider)
        with pytest.raises(ArgumentError, match="valid URL"):
            profile.create_bot_token("/relative/path")

    def test_rejects_expiry_exceeding_max(self, ec_provider):
        import datetime

        config = BotAuthConfig(max_lifetime=datetime.timedelta(minutes=5))
        profile = _build_bot_profile(ec_provider, config=config)
        with pytest.raises(ArgumentError, match="exceeds maximum"):
            profile.create_bot_token(
                "https://target.example.com/api",
                expiry=datetime.timedelta(minutes=10),
            )


# ---------------------------------------------------------------------------
# sign_bot_request tests
# ---------------------------------------------------------------------------


class TestSignBotRequest:
    def test_adds_authorization_header(self, ec_provider):
        import httpx

        bot = BotIdentity(name="TestBot", version="1.0")
        profile = _build_bot_profile(ec_provider, bot=bot)
        req = httpx.Request("GET", "https://target.example.com/data")
        signed = profile.sign_bot_request(req)
        assert "authorization" in {k.lower() for k in dict(signed.headers)}
        auth = signed.headers["authorization"]
        assert auth.startswith("Bearer ")

    def test_adds_user_agent_header(self, ec_provider):
        import httpx

        bot = BotIdentity(
            name="TestBot",
            version="1.0",
            operator_url="https://bot.example.com/info",
        )
        profile = _build_bot_profile(ec_provider, bot=bot)
        req = httpx.Request("GET", "https://target.example.com/data")
        signed = profile.sign_bot_request(req)
        ua = signed.headers["user-agent"]
        assert "TestBot/1.0" in ua
        assert "+https://bot.example.com/info" in ua

    def test_token_is_valid_jwt(self, ec_provider):
        import httpx

        profile = _build_bot_profile(ec_provider)
        req = httpx.Request("GET", "https://target.example.com/data")
        signed = profile.sign_bot_request(req)
        token = signed.headers["authorization"].removeprefix("Bearer ")
        header, claims = _decode_jwt(token)
        assert header["alg"] == "ES256"
        assert claims["aud"] == "https://target.example.com"


# ---------------------------------------------------------------------------
# Verification tests
# ---------------------------------------------------------------------------


class TestVerifyBotRequest:
    def test_roundtrip_sign_verify(self, ec_provider):
        """A token signed by the bot profile can be verified."""
        bot = BotIdentity(name="TestBot", version="1.0", purpose="testing")
        signer = _build_bot_profile(ec_provider, bot=bot)
        token = signer.create_bot_token("https://server.example.com/api")

        verifier = _make_verifying_profile(ec_provider, signer_domain="bot.example.com")
        result = verifier.verify_bot_request(
            headers={"Authorization": f"Bearer {token}"},
            expected_audience="https://server.example.com",
        )
        assert result.domain == "bot.example.com"
        assert result.bot is not None
        assert result.bot.name == "TestBot"
        assert result.bot.purpose == "testing"

    def test_verification_only_manager_can_verify_but_not_sign(self, ec_provider):
        """A verifier with no local identity verifies inbound tokens; signing raises."""
        signer = _build_bot_profile(ec_provider)
        token = signer.create_bot_token("https://server.example.com/api")
        verified = _make_verifying_profile(ec_provider)._resolver.verify_domain(
            "bot.example.com"
        )

        manager = IdentityManager.for_verification(
            IdentityManagerDependencies(dns_resolver=MockDNSResolver())
        )
        verifier = WebBotAuthProfile.from_identity_manager(manager)
        with patch.object(manager, "verify_domain", return_value=verified):
            result = verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
                expected_audience="https://server.example.com",
            )
        assert result.domain == "bot.example.com"

        with pytest.raises(ArgumentError, match="verification-only"):
            verifier.create_bot_token("https://server.example.com/api")

    def test_forwards_peer_certificate(self, ec_provider):
        signer = _build_bot_profile(ec_provider)
        token = signer.create_bot_token("https://server.example.com/api")
        verifier = _make_verifying_profile(ec_provider)
        verified = verifier._resolver.verify_domain("bot.example.com")
        peer_cert = TLSCertificate(san_dns_names=["bot.example.com"])

        with patch.object(
            verifier._resolver, "verify_domain", return_value=verified
        ) as verify_domain:
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
                expected_audience="https://server.example.com",
                peer_cert=peer_cert,
            )

        verify_domain.assert_called_once_with(
            "bot.example.com", peer_cert=peer_cert
        )

    def test_missing_auth_header_raises(self, ec_provider):
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="missing Authorization"):
            verifier.verify_bot_request(headers={})

    def test_non_bearer_scheme_raises(self, ec_provider):
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="Bearer scheme"):
            verifier.verify_bot_request(headers={"Authorization": "Basic abc123"})

    def test_empty_token_raises(self, ec_provider):
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="empty Bearer"):
            verifier.verify_bot_request(headers={"Authorization": "Bearer "})

    def test_malformed_jwt_raises(self, ec_provider):
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="malformed JWT"):
            verifier.verify_bot_request(headers={"Authorization": "Bearer only-one-part"})

    def test_audience_mismatch_raises(self, ec_provider):
        bot = BotIdentity(name="TestBot")
        signer = _build_bot_profile(ec_provider, bot=bot)
        token = signer.create_bot_token("https://server.example.com/api")

        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="audience mismatch"):
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
                expected_audience="https://other.example.com",
            )

    def test_expired_token_raises(self, ec_provider):
        import datetime

        bot = BotIdentity(name="TestBot")
        signer = _build_bot_profile(ec_provider, bot=bot)

        # Create a token with very short expiry, then mock time forward
        token = signer.create_bot_token(
            "https://server.example.com/api",
            expiry=datetime.timedelta(seconds=1),
        )

        verifier = _make_verifying_profile(ec_provider)
        # Patch _now to return future time
        future = time.time() + 120
        with patch("dnsid.web_bot_auth._now") as mock_now:
            mock_now.return_value = datetime.datetime.fromtimestamp(future, tz=datetime.UTC)
            with pytest.raises(VerificationError, match="expired"):
                verifier.verify_bot_request(
                    headers={"Authorization": f"Bearer {token}"},
                )

    def test_wrong_signing_key_raises(self):
        """Token signed by one key can't be verified against another."""
        priv1, pub1 = make_ec_p256_pair("signer-key")
        signer_provider = RealKeyProvider("signer-key", {"signer-key": (priv1, pub1)})
        signer = _build_bot_profile(signer_provider, domain="bot.example.com")
        token = signer.create_bot_token("https://server.example.com/api")

        # Verifier has a different key for the same kid
        priv2, pub2 = make_ec_p256_pair("signer-key")
        jwks = JWKS(keys=[pub2])
        mock_vd = _FakeVerifiedDomain(domain="bot.example.com", jwks=jwks)

        class FakeResolver:
            def verify_domain(self, domain):
                return mock_vd

        priv_v, pub_v = make_ec_p256_pair("v1")
        verifier = WebBotAuthProfile(
            resolver=FakeResolver(),
            key_provider=RealKeyProvider("v1", {"v1": (priv_v, pub_v)}),
            domain="server.example.com",
        )

        with pytest.raises(VerificationError, match="signature invalid"):
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
            )

    def test_require_bot_claim(self, ec_provider):
        """When require_bot_claim=True, tokens without bot claim are rejected."""
        # Sign without bot identity
        signer = _build_bot_profile(ec_provider, bot=None)
        token = signer.create_bot_token("https://server.example.com/api")

        config = BotAuthConfig(require_bot_claim=True)
        verifier = _make_verifying_profile(ec_provider, config=config)
        with pytest.raises(VerificationError, match="missing required bot claim"):
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
            )

    def test_case_insensitive_header_lookup(self, ec_provider):
        """Authorization header lookup is case-insensitive."""
        bot = BotIdentity(name="TestBot")
        signer = _build_bot_profile(ec_provider, bot=bot)
        token = signer.create_bot_token("https://server.example.com/api")

        verifier = _make_verifying_profile(ec_provider)
        # lowercase key
        result = verifier.verify_bot_request(
            headers={"authorization": f"Bearer {token}"},
        )
        assert result.domain == "bot.example.com"

    def test_from_identity_manager(self, ec_provider):
        """Test the from_identity_manager class method."""
        with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
            mgr = IdentityManager(
                make_config(
                    domain="bot.example.com",
                    governance_id="example.com",
                    log_ref="microledger:abc",
                    status_url="https://bot.example.com/status",
                ),
                ec_provider,
                deps=IdentityManagerDependencies(dns_resolver=MockDNSResolver()),
            )
        bot = BotIdentity(name="TestBot")
        profile = WebBotAuthProfile.from_identity_manager(mgr, bot=bot)
        token = profile.create_bot_token("https://target.example.com/api")
        _, claims = _decode_jwt(token)
        assert claims["iss"] == "bot.example.com"
        assert claims["bot"]["name"] == "TestBot"


# ---------------------------------------------------------------------------
# EdDSA key tests
# ---------------------------------------------------------------------------


class TestEdDSABotAuth:
    def test_roundtrip_ed25519(self, ed_provider):
        """Bot auth works with Ed25519 keys."""
        bot = BotIdentity(name="EdBot")
        signer = _build_bot_profile(ed_provider, bot=bot)
        token = signer.create_bot_token("https://server.example.com/api")

        header, claims = _decode_jwt(token)
        assert header["alg"] == "EdDSA"

        # Build verifier
        pub_key = ed_provider.signing_key()
        jwks = JWKS(keys=[pub_key])
        mock_vd = _FakeVerifiedDomain(domain="bot.example.com", jwks=jwks)

        class FakeResolver:
            def verify_domain(self, domain):
                return mock_vd

        from tests.conftest import make_ed25519_pair

        priv_v, pub_v = make_ed25519_pair("v1")
        verifier = WebBotAuthProfile(
            resolver=FakeResolver(),
            key_provider=RealKeyProvider("v1", {"v1": (priv_v, pub_v)}),
            domain="server.example.com",
        )
        result = verifier.verify_bot_request(
            headers={"Authorization": f"Bearer {token}"},
        )
        assert result.domain == "bot.example.com"
        assert result.bot.name == "EdBot"


# ---------------------------------------------------------------------------
# Audience validation regression tests
# ---------------------------------------------------------------------------


def _craft_token_with_aud(provider, aud_value, domain="bot.example.com"):
    """Create a signed JWT with an arbitrary aud claim value."""
    import uuid

    from dnsid._utils import b64url_encode

    signing_key = provider.signing_key()
    header = {
        "alg": signing_key.signature_alg(),
        "kid": signing_key.kid,
        "typ": "JWT",
    }
    now = int(time.time())
    claims = {
        "iss": domain,
        "sub": domain,
        "aud": aud_value,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
        "bot": {"name": "TestBot"},
    }
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    sig_bytes = provider.sign(signing_input)
    return f"{header_b64}.{claims_b64}.{b64url_encode(sig_bytes)}"


class TestAudienceValidation:
    """Regression tests: aud must be a string or array of strings."""

    def test_object_audience_rejected(self, ec_provider):
        """A token with aud as an object must not pass audience check."""
        # This would previously pass because list({"https://server.example.com": false})
        # returns ["https://server.example.com"]
        token = _craft_token_with_aud(
            ec_provider, {"https://server.example.com": False}
        )
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="must be a string or array"):
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
                expected_audience="https://server.example.com",
            )

    def test_numeric_audience_rejected(self, ec_provider):
        """A token with aud as a number must not pass audience check."""
        token = _craft_token_with_aud(ec_provider, 12345)
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="must be a string or array"):
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
                expected_audience="12345",
            )

    def test_array_with_non_string_rejected(self, ec_provider):
        """A token with aud array containing non-string values is rejected."""
        token = _craft_token_with_aud(
            ec_provider, ["https://server.example.com", 123]
        )
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="non-string value"):
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
                expected_audience="https://server.example.com",
            )

    def test_boolean_audience_rejected(self, ec_provider):
        """A token with aud as a boolean must not pass audience check."""
        token = _craft_token_with_aud(ec_provider, True)
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="must be a string or array"):
            verifier.verify_bot_request(
                headers={"Authorization": f"Bearer {token}"},
                expected_audience="True",
            )

    def test_valid_string_audience_passes(self, ec_provider):
        """A token with aud as a valid string still works."""
        token = _craft_token_with_aud(ec_provider, "https://server.example.com")
        verifier = _make_verifying_profile(ec_provider)
        result = verifier.verify_bot_request(
            headers={"Authorization": f"Bearer {token}"},
            expected_audience="https://server.example.com",
        )
        assert result.domain == "bot.example.com"

    def test_valid_array_audience_passes(self, ec_provider):
        """A token with aud as a valid string array still works."""
        token = _craft_token_with_aud(
            ec_provider,
            ["https://server.example.com", "https://other.example.com"],
        )
        verifier = _make_verifying_profile(ec_provider)
        result = verifier.verify_bot_request(
            headers={"Authorization": f"Bearer {token}"},
            expected_audience="https://server.example.com",
        )
        assert result.domain == "bot.example.com"


# ---------------------------------------------------------------------------
# Claim type-validation tests (reviewer issue: non-int iat/exp, non-string iss)
# ---------------------------------------------------------------------------


def _make_signed_jwt(provider, claims: dict, header_overrides: dict | None = None):
    """Create a signed JWT with arbitrary claims using the given provider."""
    key = provider.signing_key()
    kid = key.kid
    alg = key.signature_alg()
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    if header_overrides:
        header.update(header_overrides)
    h_enc = b64url_encode(json.dumps(header).encode())
    c_enc = b64url_encode(json.dumps(claims).encode())
    sig_input = f"{h_enc}.{c_enc}".encode("ascii")
    sig = provider.sign(sig_input)
    return f"{h_enc}.{c_enc}.{b64url_encode(sig)}"


class TestClaimTypeValidation:
    """Malformed claim types raise VerificationError, not raw TypeError/AttributeError."""

    def test_non_integer_iat_raises(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "iat": "not-an-int",
            "exp": now + 300,
        })
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="iat claim must be an integer"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})

    def test_non_integer_exp_raises(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "iat": now,
            "exp": "not-an-int",
        })
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="exp claim must be an integer"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})

    def test_non_string_iss_raises(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": 12345,
            "iat": now,
            "exp": now + 300,
        })
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="iss claim must be a string"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})

    def test_non_string_sub_raises(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "sub": 12345,
            "iat": now,
            "exp": now + 300,
        })
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="sub claim must be a string"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})

    @pytest.mark.parametrize("bad_sub", [0, False, []])
    def test_falsey_non_string_sub_raises(self, ec_provider, bad_sub):
        # A present-but-falsey non-string sub must not be treated as absent.
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "sub": bad_sub,
            "iat": now,
            "exp": now + 300,
        })
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="sub claim must be a string"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})

    def test_boolean_iat_raises(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "iat": True,
            "exp": now + 300,
        })
        verifier = _make_verifying_profile(ec_provider)
        with pytest.raises(VerificationError, match="iat claim must be an integer"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})


class TestBotClaimValidation:
    """Non-object bot claims are rejected when require_bot_claim=True."""

    def test_string_bot_claim_rejected(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "iat": now,
            "exp": now + 300,
            "bot": "present-but-not-object",
        })
        config = BotAuthConfig(require_bot_claim=True)
        verifier = _make_verifying_profile(ec_provider, config=config)
        with pytest.raises(VerificationError, match="bot claim must be an object"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})

    def test_numeric_bot_claim_rejected(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "iat": now,
            "exp": now + 300,
            "bot": 42,
        })
        config = BotAuthConfig(require_bot_claim=True)
        verifier = _make_verifying_profile(ec_provider, config=config)
        with pytest.raises(VerificationError, match="bot claim must be an object"):
            verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})

    def test_valid_object_bot_claim_accepted(self, ec_provider):
        now = int(time.time())
        token = _make_signed_jwt(ec_provider, {
            "iss": "bot.example.com",
            "iat": now,
            "exp": now + 300,
            "bot": {"name": "MyBot", "version": "1.0"},
        })
        config = BotAuthConfig(require_bot_claim=True)
        verifier = _make_verifying_profile(ec_provider, config=config)
        result = verifier.verify_bot_request(headers={"Authorization": f"Bearer {token}"})
        assert result.bot.name == "MyBot"
        assert result.bot.version == "1.0"


# ---------------------------------------------------------------------------
# Signature-Input duplicate label rejection tests
# ---------------------------------------------------------------------------


class TestSignatureInputDuplicateLabels:
    """Duplicate labels in Signature-Input are rejected per RFC 8941."""

    def test_duplicate_label_rejected(self):
        from dnsid.models import SignatureParams

        with pytest.raises(VerificationError, match="duplicate label"):
            SignatureParams.parse(
                'sig1=("@method");created=1234, sig1=("@authority");created=5678'
            )

    def test_single_member_accepted(self):
        from dnsid.models import SignatureParams

        params = SignatureParams.parse('sig1=("@method" "@authority");keyid="k1";created=100')
        assert params.label == "sig1"
        assert params.components == ["@method", "@authority"]
        assert params.created == 100

    def test_multiple_distinct_labels_accepted(self):
        from dnsid.models import SignatureParams

        params = SignatureParams.parse(
            'sig1=("@method");created=100, sig2=("@authority");created=200'
        )
        # Returns first member by default
        assert params.label == "sig1"
