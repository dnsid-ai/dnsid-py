"""Tests for JoseProfile.create_jwt and verify_jwt."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from dnsid import (
    JWKS,
    IdentityManager,
    IdentityManagerDependencies,
    JWTOptions,
    TLSCertificate,
    VerifiedDomain,
)
from dnsid._utils import b64url_decode
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.jose import JoseConfig, JoseProfile
from tests._config import make_config
from tests.conftest import MockDNSResolver


def _build_profile(provider, domain="agent.example.com", jose_config=None):
    """Build a JoseProfile backed by a real-crypto provider."""
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
    return JoseProfile(resolver=mgr, key_provider=provider, domain=domain, config=jose_config)


def _decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    return header, claims


class TestCreateJWT:
    def test_verification_only_profile_rejects_signing_cleanly(self):
        manager = IdentityManager.for_verification(
            IdentityManagerDependencies(dns_resolver=MockDNSResolver())
        )
        jose = JoseProfile.from_identity_manager(manager)

        with pytest.raises(ArgumentError, match="verification-only"):
            jose.create_jwt(JWTOptions(audience="other.example.com"))

    def test_returns_three_part_string(self, ec_provider):
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(JWTOptions(audience="other.example.com"))
        assert len(token.split(".")) == 3

    def test_header_contains_alg_and_kid(self, ec_provider):
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(JWTOptions(audience="other.example.com"))
        header, _ = _decode_jwt(token)
        assert header["alg"] == "ES256"
        assert header["kid"] == "k1"
        assert header["typ"] == "JWT"

    def test_claims_iss_sub_equal_domain(self, ec_provider):
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(JWTOptions(audience="other.example.com"))
        _, claims = _decode_jwt(token)
        assert claims["iss"] == "agent.example.com"
        assert claims["sub"] == "agent.example.com"

    def test_claims_aud_is_audience(self, ec_provider):
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(JWTOptions(audience="other.example.com"))
        _, claims = _decode_jwt(token)
        assert claims["aud"] == "other.example.com"

    def test_claims_exp_in_future(self, ec_provider):
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(JWTOptions(audience="other.example.com"))
        _, claims = _decode_jwt(token)
        assert claims["exp"] > int(time.time())

    def test_claims_jti_present(self, ec_provider):
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(JWTOptions(audience="other.example.com"))
        _, claims = _decode_jwt(token)
        assert claims["jti"]

    def test_additional_claims_merged(self, ec_provider):
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(
            JWTOptions(audience="other.example.com", additional_claims={"role": "admin"})
        )
        _, claims = _decode_jwt(token)
        assert claims["role"] == "admin"

    def test_reserved_claim_override_raises(self, ec_provider):
        jose = _build_profile(ec_provider)
        with pytest.raises(ArgumentError):
            jose.create_jwt(JWTOptions(audience="x.com", additional_claims={"iss": "evil.com"}))

    def test_empty_audience_raises(self, ec_provider):
        jose = _build_profile(ec_provider)
        with pytest.raises(ArgumentError):
            jose.create_jwt(JWTOptions(audience=""))

    def test_signature_verifies_with_public_key(self, ec_pair, ec_provider):
        _, jwk = ec_pair
        jose = _build_profile(ec_provider)
        token = jose.create_jwt(JWTOptions(audience="other.example.com"))
        parts = token.split(".")
        sig_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        sig = b64url_decode(parts[2])
        assert jwk.verify(sig_input, sig) is True

    def test_expiry_exceeds_max_lifetime_raises(self, ec_provider):
        import datetime

        config = JoseConfig(max_lifetime=datetime.timedelta(minutes=10))
        jose = _build_profile(ec_provider, jose_config=config)
        with pytest.raises(ArgumentError, match="exceeds maximum lifetime"):
            jose.create_jwt(
                JWTOptions(
                    audience="other.example.com",
                    expiry=datetime.timedelta(minutes=20),
                )
            )


class TestVerifyJWT:
    def _make_token(
        self,
        provider,
        audience: str,
        domain: str = "issuer.example.com",
        extra_claims: dict | None = None,
    ) -> str:
        issuer_jose = _build_profile(provider, domain=domain)
        return issuer_jose.create_jwt(
            JWTOptions(audience=audience, additional_claims=extra_claims or {})
        )

    def _build_verifier_profile(self, provider, domain: str = "verifier.example.com"):
        return _build_profile(provider, domain=domain)

    def _tamper_claims(self, token: str, updates: dict) -> str:
        from dnsid._utils import b64url_encode

        parts = token.split(".")
        claims = json.loads(b64url_decode(parts[1]))
        claims.update(updates)
        new_claims_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        return f"{parts[0]}.{new_claims_b64}.{parts[2]}"

    def test_verify_jwt_returns_verified_domain(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        token = self._make_token(
            ec_provider, audience="verifier.example.com", domain="issuer.example.com"
        )

        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk

        verifier_jose = self._build_verifier_profile(ec_provider)
        with patch.object(verifier_jose._resolver, "verify_domain", return_value=mock_vd):
            result = verifier_jose.verify_jwt(token)
        assert result is mock_vd

    def test_forwards_peer_certificate(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        token = self._make_token(
            ec_provider, audience="verifier.example.com", domain="issuer.example.com"
        )
        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk
        peer_cert = TLSCertificate(san_dns_names=["issuer.example.com"])
        verifier_jose = self._build_verifier_profile(ec_provider)
        with patch.object(
            verifier_jose._resolver, "verify_domain", return_value=mock_vd
        ) as verify_domain:
            assert verifier_jose.verify_jwt(token, peer_cert=peer_cert) is mock_vd
        verify_domain.assert_called_once_with(
            "issuer.example.com", peer_cert=peer_cert
        )

    def test_expired_jwt_raises(self, ec_provider):
        token = self._make_token(ec_provider, audience="verifier.example.com")
        parts = token.split(".")
        claims = json.loads(b64url_decode(parts[1]))
        claims["exp"] = int(time.time()) - 3600

        from dnsid._utils import b64url_encode

        new_claims_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        bad_token = f"{parts[0]}.{new_claims_b64}.{parts[2]}"

        verifier_jose = self._build_verifier_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            verifier_jose.verify_jwt(bad_token)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_wrong_audience_raises(self, ec_provider):
        token = self._make_token(ec_provider, audience="someone-else.example.com")
        verifier_jose = self._build_verifier_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            verifier_jose.verify_jwt(token)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_missing_iat_raises(self, ec_provider):
        token = self._make_token(ec_provider, audience="verifier.example.com")
        bad_token = self._tamper_claims(token, {"iat": None})
        verifier_jose = self._build_verifier_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            verifier_jose.verify_jwt(bad_token)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "iat" in exc_info.value.message

    def test_iat_in_future_raises(self, ec_provider):
        token = self._make_token(ec_provider, audience="verifier.example.com")
        bad_token = self._tamper_claims(token, {"iat": int(time.time()) + 120})
        verifier_jose = self._build_verifier_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            verifier_jose.verify_jwt(bad_token)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "future" in exc_info.value.message

    def test_exp_not_after_iat_raises(self, ec_provider):
        token = self._make_token(ec_provider, audience="verifier.example.com")
        parts = token.split(".")
        claims = json.loads(b64url_decode(parts[1]))
        bad_token = self._tamper_claims(token, {"exp": claims["iat"] - 1})
        verifier_jose = self._build_verifier_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            verifier_jose.verify_jwt(bad_token)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "exp must be after iat" in exc_info.value.message

    def test_lifetime_exceeds_max_raises(self, ec_provider):
        token = self._make_token(ec_provider, audience="verifier.example.com")
        parts = token.split(".")
        claims = json.loads(b64url_decode(parts[1]))
        bad_token = self._tamper_claims(token, {"exp": claims["iat"] + 2000})
        verifier_jose = self._build_verifier_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            verifier_jose.verify_jwt(bad_token)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "lifetime exceeds maximum" in exc_info.value.message

    def test_nbf_within_clock_skew_passes(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        token = self._make_token(
            ec_provider,
            audience="verifier.example.com",
            extra_claims={"nbf": int(time.time()) + 30},
        )
        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk
        verifier_jose = self._build_verifier_profile(ec_provider)
        with patch.object(verifier_jose._resolver, "verify_domain", return_value=mock_vd):
            result = verifier_jose.verify_jwt(token)
        assert result is mock_vd

    def test_nbf_beyond_clock_skew_raises(self, ec_provider):
        token = self._make_token(ec_provider, audience="verifier.example.com")
        bad_token = self._tamper_claims(token, {"nbf": int(time.time()) + 120})
        verifier_jose = self._build_verifier_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            verifier_jose.verify_jwt(bad_token)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "nbf" in exc_info.value.message
