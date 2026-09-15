"""Tests for JoseProfile.create_jws and verify_jws."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from dnsid import (
    JWKS,
    IdentityManager,
    IdentityManagerDependencies,
    TLSCertificate,
    VerifiedDomain,
)
from dnsid._utils import b64url_decode
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.jose import JoseProfile
from tests._config import make_config
from tests.conftest import MockDNSResolver


def _build_profile(provider, domain="agent.example.com"):
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
    return JoseProfile(resolver=mgr, key_provider=provider, domain=domain)


class TestCreateJWS:
    def test_returns_three_part_string(self, ec_provider):
        jose = _build_profile(ec_provider)
        result = jose.create_jws(b"hello world")
        assert len(result.split(".")) == 3

    def test_header_kid_uses_compound_form(self, ec_provider):
        jose = _build_profile(ec_provider)
        result = jose.create_jws(b"payload")
        header_b64 = result.split(".")[0]
        header = json.loads(b64url_decode(header_b64))
        assert header["kid"] == "agent.example.com#k1"

    def test_header_typ_is_jose(self, ec_provider):
        jose = _build_profile(ec_provider)
        result = jose.create_jws(b"payload")
        header = json.loads(b64url_decode(result.split(".")[0]))
        assert header["typ"] == "jose"

    def test_payload_round_trips(self, ec_provider):
        jose = _build_profile(ec_provider)
        original = b"arbitrary bytes \x00\xff"
        result = jose.create_jws(original)
        recovered = b64url_decode(result.split(".")[1])
        assert recovered == original

    def test_signature_verifies_with_public_key(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        jose = _build_profile(ec_provider)
        jws = jose.create_jws(b"data")
        parts = jws.split(".")
        sig_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        sig = b64url_decode(parts[2])
        assert pub_jwk.verify(sig_input, sig) is True

    def test_kid_with_hash_raises(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        pub_jwk.kid = "has#hash"
        jose = _build_profile(ec_provider)
        with pytest.raises(ArgumentError):
            jose.create_jws(b"data")

    def test_ed25519_jws(self, ed_provider):
        jose = _build_profile(ed_provider)
        result = jose.create_jws(b"test")
        assert len(result.split(".")) == 3


class TestVerifyJWS:
    def _create_jws(self, provider, payload: bytes, domain="signer.example.com") -> str:
        jose = _build_profile(provider, domain=domain)
        return jose.create_jws(payload)

    def test_returns_payload_and_verified_domain(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        payload = b"test payload"
        jws = self._create_jws(ec_provider, payload, domain="signer.example.com")

        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk

        verifier_jose = _build_profile(ec_provider, domain="verifier.example.com")
        with patch.object(verifier_jose._resolver, "verify_domain", return_value=mock_vd):
            recovered_payload, vd = verifier_jose.verify_jws(jws)

        assert recovered_payload == payload
        assert vd is mock_vd

    def test_forwards_peer_certificate(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        payload = b"test payload"
        jws = self._create_jws(ec_provider, payload, domain="signer.example.com")
        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk
        peer_cert = TLSCertificate(san_dns_names=["signer.example.com"])
        verifier_jose = _build_profile(ec_provider, domain="verifier.example.com")
        with patch.object(
            verifier_jose._resolver, "verify_domain", return_value=mock_vd
        ) as verify_domain:
            recovered, vd = verifier_jose.verify_jws(jws, peer_cert=peer_cert)
        assert recovered == payload
        assert vd is mock_vd
        verify_domain.assert_called_once_with(
            "signer.example.com", peer_cert=peer_cert
        )

    def test_malformed_jws_raises(self, ec_provider):
        jose = _build_profile(ec_provider)
        with pytest.raises(VerificationError) as exc_info:
            jose.verify_jws("only.two")
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_tampered_payload_fails(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        jws = self._create_jws(ec_provider, b"original", domain="signer.example.com")
        parts = jws.split(".")

        from dnsid._utils import b64url_encode

        tampered_payload = b64url_encode(b"tampered")
        bad_jws = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk

        verifier_jose = _build_profile(ec_provider, domain="verifier.example.com")
        with patch.object(verifier_jose._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier_jose.verify_jws(bad_jws)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID

    def test_missing_kid_raises(self, ec_provider):
        jose = _build_profile(ec_provider)
        import json as _json

        header = {"alg": "ES256", "typ": "jose"}  # no kid
        from dnsid._utils import b64url_encode

        h_b64 = b64url_encode(_json.dumps(header, separators=(",", ":")).encode())
        p_b64 = b64url_encode(b"data")
        bad_jws = f"{h_b64}.{p_b64}.fakesig"
        with pytest.raises(VerificationError) as exc_info:
            jose.verify_jws(bad_jws)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
