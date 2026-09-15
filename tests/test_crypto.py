"""Tests for JWK thumbprint, signature verification, JWKS helpers."""

from __future__ import annotations

import pytest

from dnsid import JWK, JWKS, check_ek_ku_distinctness
from dnsid._crypto import (
    compute_thumbprint,
    ec_sign,
    ed25519_sign,
)
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.models import DnsIdTxtRecord
from tests.conftest import make_ec_p256_pair, make_ed25519_pair

# ---------------------------------------------------------------------------
# compute_thumbprint
# ---------------------------------------------------------------------------


class TestThumbprint:
    def test_ec_p256_thumbprint_is_string(self):
        _, jwk = make_ec_p256_pair()
        result = jwk.thumbprint()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_ec_p256_thumbprint_is_deterministic(self):
        _, jwk = make_ec_p256_pair("k1")
        assert jwk.thumbprint() == jwk.thumbprint()

    def test_different_keys_have_different_thumbprints(self):
        _, jwk1 = make_ec_p256_pair("k1")
        _, jwk2 = make_ec_p256_pair("k2")
        assert jwk1.thumbprint() != jwk2.thumbprint()

    def test_thumbprint_unpadded_base64url(self):
        _, jwk = make_ec_p256_pair()
        tp = jwk.thumbprint()
        assert "=" not in tp
        assert "+" not in tp
        assert "/" not in tp

    def test_ed25519_thumbprint(self):
        _, jwk = make_ed25519_pair()
        tp = jwk.thumbprint()
        assert isinstance(tp, str)
        assert len(tp) > 0

    def test_missing_raw_raises(self):
        jwk = JWK(kty="EC", alg="ES256", kid="k1")  # _raw is empty
        with pytest.raises((ValueError, KeyError)):
            jwk.thumbprint()

    def test_unsupported_kty_raises(self):
        with pytest.raises(ValueError, match="unsupported kty"):
            compute_thumbprint({"kty": "oct", "k": "abc"})

    def test_rfc7638_known_vector(self):
        # RFC 7638 §3.1 example key — known thumbprint
        raw = {
            "e": "AQAB",
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
            "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
            "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F"
            "DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
            "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
            "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        }
        # RFC 7638 specifies the thumbprint for this key
        tp = compute_thumbprint(raw)
        assert tp == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


# ---------------------------------------------------------------------------
# Public JWK/JWKS serialization
# ---------------------------------------------------------------------------


def test_jwk_and_jwks_to_dict_return_independent_public_values():
    raw = {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": "k1",
        "x": "public",
        "d": "private",
        "key_ops": ["verify"],
    }
    key = JWK(kty="OKP", alg="EdDSA", kid="k1", _raw=raw)

    serialized = JWKS(keys=[key]).to_dict()
    assert serialized == {"keys": [{name: value for name, value in raw.items() if name != "d"}]}

    serialized["keys"][0]["key_ops"].append("sign")
    assert key.to_dict()["key_ops"] == ["verify"]


# ---------------------------------------------------------------------------
# JWK.verify (via verify_signature)
# ---------------------------------------------------------------------------


class TestJWKVerify:
    def test_ec_valid_signature(self):
        private, jwk = make_ec_p256_pair()
        payload = b"hello world"
        sig = ec_sign(private, "ES256", payload)
        assert jwk.verify(payload, sig) is True

    def test_ec_wrong_payload(self):
        private, jwk = make_ec_p256_pair()
        sig = ec_sign(private, "ES256", b"original")
        assert jwk.verify(b"tampered", sig) is False

    def test_ec_wrong_key(self):
        private1, _ = make_ec_p256_pair("k1")
        _, jwk2 = make_ec_p256_pair("k2")
        sig = ec_sign(private1, "ES256", b"data")
        assert jwk2.verify(b"data", sig) is False

    def test_ec_truncated_signature(self):
        private, jwk = make_ec_p256_pair()
        sig = ec_sign(private, "ES256", b"data")
        assert jwk.verify(b"data", sig[:30]) is False

    def test_ed25519_valid_signature(self):
        private, jwk = make_ed25519_pair()
        payload = b"test payload"
        sig = ed25519_sign(private, payload)
        assert jwk.verify(payload, sig) is True

    def test_ed25519_wrong_payload(self):
        private, jwk = make_ed25519_pair()
        sig = ed25519_sign(private, b"original")
        assert jwk.verify(b"different", sig) is False

    def test_empty_raw_returns_false(self):
        jwk = JWK(kty="EC", alg="ES256", kid="k1")  # _raw empty
        assert jwk.verify(b"data", b"sig") is False


# ---------------------------------------------------------------------------
# JWKS.signing_keys
# ---------------------------------------------------------------------------


class TestJWKSSigningKeys:
    def test_returns_sig_use_keys(self):
        _, k1 = make_ec_p256_pair("k1")
        jwks = JWKS(keys=[k1])
        keys = jwks.signing_keys()
        assert len(keys) == 1
        assert keys[0].kid == "k1"

    def test_raises_when_empty(self):
        jwks = JWKS(keys=[])
        with pytest.raises(VerificationError) as exc_info:
            jwks.signing_keys()
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_raises_when_no_signing_alg(self):
        # A key with an unknown/non-signing alg
        jwk = JWK(kty="oct", alg="HS256", kid="k1")
        jwks = JWKS(keys=[jwk])
        with pytest.raises(VerificationError):
            jwks.signing_keys()

    def test_multiple_keys_all_returned(self):
        _, k1 = make_ec_p256_pair("k1")
        _, k2 = make_ed25519_pair("k2")
        jwks = JWKS(keys=[k1, k2])
        keys = jwks.signing_keys()
        assert len(keys) == 2

    @pytest.mark.parametrize("invalid_use", ["enc", "other"])
    def test_excludes_non_signature_use_keys(self, invalid_use):
        _, sig = make_ec_p256_pair("sig-key")
        _, excluded = make_ed25519_pair("excluded-key")
        excluded.use = invalid_use
        keys = JWKS(keys=[sig, excluded]).signing_keys()
        assert [k.kid for k in keys] == ["sig-key"]


class TestJWKSProtocolRoleHelpers:
    @pytest.mark.parametrize("profile", ["dnsid-draft-01", "DNSid1"])
    def test_selects_current_record_and_operational_keys(self, profile):
        _, key = make_ec_p256_pair("current")
        jwks = JWKS(keys=[key])

        assert jwks.current_record_signing_key(profile) is key
        assert jwks.current_operational_signing_key(profile) is key
        assert jwks.validate_record_signing(profile) is None
        assert jwks.validate_operational(profile) is None

    @pytest.mark.parametrize(
        "helper_name",
        ["current_record_signing_key", "current_operational_signing_key"],
    )
    def test_requires_one_current_key_with_kid_and_alg(self, helper_name):
        _, key = make_ec_p256_pair("current")
        helper = getattr(JWKS(keys=[key, key]), helper_name)
        with pytest.raises(VerificationError):
            helper()

        key.alg = ""
        helper = getattr(JWKS(keys=[key]), helper_name)
        with pytest.raises(VerificationError, match="must declare alg"):
            helper()

        key.alg = "ES256"
        key.kid = ""
        helper = getattr(JWKS(keys=[key]), helper_name)
        with pytest.raises(VerificationError, match="kid"):
            helper()

    def test_rejects_unknown_profile(self):
        _, key = make_ec_p256_pair("current")
        with pytest.raises(VerificationError, match="unsupported identity record profile"):
            JWKS(keys=[key]).current_record_signing_key("dnsid-draft-99")


# ---------------------------------------------------------------------------
# JWKS.validate
# ---------------------------------------------------------------------------


class TestJWKSValidate:
    def test_valid_jwks_passes(self):
        _, k1 = make_ec_p256_pair("k1")
        JWKS(keys=[k1]).validate()  # should not raise

    def test_missing_alg_accepted(self):
        # alg is optional; kty/crv binding is sufficient for validation.
        _, k1 = make_ec_p256_pair("k1")
        k1.alg = ""
        JWKS(keys=[k1]).validate()  # should not raise

    def test_inconsistent_alg_raises(self):
        _, k1 = make_ec_p256_pair("k1")
        k1.alg = "EdDSA"  # wrong: P-256 implies ES256
        with pytest.raises(VerificationError) as exc_info:
            JWKS(keys=[k1]).validate()
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_no_signing_keys_raises(self):
        jwk = JWK(kty="oct", alg="HS256", kid="k1")
        with pytest.raises(VerificationError):
            JWKS(keys=[jwk]).validate()

    def test_no_kid_on_signing_key_raises(self):
        _, k1 = make_ec_p256_pair("k1")
        k1.kid = ""
        with pytest.raises(VerificationError):
            JWKS(keys=[k1]).validate()

    def test_empty_jwks_raises(self):
        with pytest.raises(VerificationError):
            JWKS(keys=[]).validate()

    @pytest.mark.parametrize("invalid_use", ["enc", "other"])
    def test_non_signature_use_key_rejected(self, invalid_use):
        _, key = make_ed25519_pair("excluded-key")
        key.use = invalid_use
        with pytest.raises(VerificationError) as exc_info:
            JWKS(keys=[key]).validate()
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    @pytest.mark.parametrize("invalid_use", ["enc", "other"])
    def test_non_signature_use_key_ignored_when_signing_key_present(self, invalid_use):
        _, sig = make_ec_p256_pair("sig-key")
        _, excluded = make_ed25519_pair("excluded-key")
        excluded.use = invalid_use
        JWKS(keys=[sig, excluded]).validate()  # should not raise

    def test_duplicate_kid_rejected(self):
        _, k1 = make_ec_p256_pair("dup")
        _, k2 = make_ed25519_pair("dup")
        with pytest.raises(VerificationError) as exc_info:
            JWKS(keys=[k1, k2]).validate()
        assert exc_info.value.code == VerificationCode.RECORD_INVALID


# ---------------------------------------------------------------------------
# check_ek_ku_distinctness
# ---------------------------------------------------------------------------


class TestEkKuDistinctness:
    def test_disjoint_key_sets_pass(self):
        _, ek_key = make_ec_p256_pair("ek1")
        _, ku_key = make_ed25519_pair("ku1")
        check_ek_ku_distinctness(JWKS(keys=[ek_key]), JWKS(keys=[ku_key]))  # should not raise

    def test_shared_key_is_rejected(self):
        _, shared = make_ec_p256_pair("shared")
        _, other = make_ed25519_pair("other")
        with pytest.raises(VerificationError) as exc_info:
            check_ek_ku_distinctness(JWKS(keys=[shared]), JWKS(keys=[shared, other]))
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "RFC 7638 thumbprint collision" in str(exc_info.value)

    def test_empty_ek_passes(self):
        _, ku_key = make_ec_p256_pair("ku1")
        check_ek_ku_distinctness(JWKS(keys=[]), JWKS(keys=[ku_key]))  # should not raise

    def test_missing_ek_passes(self):
        _, ku_key = make_ec_p256_pair("ku1")
        check_ek_ku_distinctness(None, JWKS(keys=[ku_key]))  # should not raise

    def test_empty_ku_passes(self):
        _, ek_key = make_ec_p256_pair("ek1")
        check_ek_ku_distinctness(JWKS(keys=[ek_key]), JWKS(keys=[]))  # should not raise

    def test_missing_ku_passes(self):
        _, ek_key = make_ec_p256_pair("ek1")
        check_ek_ku_distinctness(JWKS(keys=[ek_key]), None)  # should not raise

    def test_self_accounted_with_distinct_keys_passes(self):
        # Self-accounting (gi == identity FQDN) must never be inferred from key
        # equality — distinct ek/ku keys must pass regardless of the gi relationship.
        record = DnsIdTxtRecord(
            gi="agent.example.com",
            ek="https://agent.example.com/.well-known/jwks.json",
            ku="https://agent.example.com/.well-known/jwks.json",
            lr="microledger:abc",
            su="https://agent.example.com/status",
            sg="dGVzdA",
            identity_fqdn="agent.example.com",
        )
        record.validate()

        _, ek_key = make_ec_p256_pair("ek1")
        _, ku_key = make_ed25519_pair("ku1")
        check_ek_ku_distinctness(JWKS(keys=[ek_key]), JWKS(keys=[ku_key]))  # should not raise
