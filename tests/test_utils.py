"""Tests for normalize_fqdn, is_domain_name, base64url helpers, SignatureParams."""

from __future__ import annotations

import pytest

from dnsid._utils import (
    b64url_decode,
    b64url_encode,
    is_domain_name,
    is_valid_tag_name,
    is_valid_tag_value,
    normalize_fqdn,
    parse_key_id,
    parse_ledger_ref,
)
from dnsid.exceptions import ArgumentError, ParseError, ValidationError
from dnsid.models import SignatureParams


class TestNormalizeFQDN:
    def test_lowercases_ascii(self):
        assert normalize_fqdn("AGENT.EXAMPLE.COM") == "agent.example.com"

    def test_strips_trailing_dot(self):
        assert normalize_fqdn("agent.example.com.") == "agent.example.com"

    def test_strips_trailing_ideographic_full_stop(self):
        # U+3002 maps to '.' during UTS#46 encoding; must not leave a trailing dot (#79).
        assert normalize_fqdn("example.com。") == "example.com"
        assert normalize_fqdn("example.com。", agent_fqdn=True) == "example.com"

    def test_mixed_case(self):
        assert normalize_fqdn("Billing-Agent.Acme.Example") == "billing-agent.acme.example"

    def test_idna_unicode_label(self):
        result = normalize_fqdn("agent.münchen.example.com")
        assert result == "agent.xn--mnchen-3ya.example.com"

    def test_empty_raises(self):
        with pytest.raises(ValidationError):
            normalize_fqdn("")

    def test_empty_label_raises(self):
        with pytest.raises(ValidationError):
            normalize_fqdn("agent..example.com")

    def test_agent_fqdn_too_long_raises(self):
        # 247 octets with agent_fqdn=True — over the 246 limit
        long_name = "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + "." + "d" * 60 + ".com"
        with pytest.raises(ValidationError, match="246"):
            normalize_fqdn(long_name, agent_fqdn=True)

    def test_normal_fqdn_accepted_without_agent_limit(self):
        # Under 253 octets, OK without agent_fqdn flag
        result = normalize_fqdn("agent.example.com")
        assert result == "agent.example.com"


class TestIsDomainName:
    def test_simple_domain(self):
        assert is_domain_name("example.com") is True

    def test_subdomain(self):
        assert is_domain_name("billing-agent.acme.example") is True

    def test_single_label(self):
        assert is_domain_name("localhost") is True

    def test_uri_is_not_domain(self):
        assert is_domain_name("https://example.com") is False

    def test_ledger_ref_is_not_domain(self):
        assert is_domain_name("algorand:ADDR123") is False

    def test_empty_string(self):
        assert is_domain_name("") is False

    def test_trailing_dot_stripped(self):
        assert is_domain_name("example.com.") is True


class TestBase64Url:
    def test_encode_decode_roundtrip(self):
        data = b"\x00\xff\xfe\x80\x01"
        assert b64url_decode(b64url_encode(data)) == data

    def test_no_padding_in_output(self):
        encoded = b64url_encode(b"hello")
        assert "=" not in encoded

    def test_accepts_padded_input(self):
        padded = "aGVsbG8="
        assert b64url_decode(padded) == b"hello"

    def test_accepts_unpadded_input(self):
        assert b64url_decode("aGVsbG8") == b"hello"


class TestParseLedgerRef:
    def test_valid(self):
        method, ref = parse_ledger_ref("algorand:ADDR123")
        assert method == "algorand"
        assert ref == "ADDR123"

    def test_entry_ref_with_colon(self):
        method, ref = parse_ledger_ref("scitt:urn:example:123")
        assert method == "scitt"
        assert ref == "urn:example:123"

    def test_no_colon_raises(self):
        with pytest.raises(ParseError):
            parse_ledger_ref("nodot")

    def test_empty_method_raises(self):
        with pytest.raises(ParseError):
            parse_ledger_ref(":ref")

    def test_invalid_method_pattern_raises(self):
        with pytest.raises(ParseError):
            parse_ledger_ref("UPPER:ref")


class TestParseKeyId:
    def test_valid(self):
        domain, kid = parse_key_id("agent.example.com#k1")
        assert domain == "agent.example.com"
        assert kid == "k1"

    def test_no_hash_raises(self):
        with pytest.raises(ArgumentError):
            parse_key_id("agent.example.com")

    def test_empty_kid_raises(self):
        with pytest.raises(ArgumentError):
            parse_key_id("agent.example.com#")

    def test_kid_with_hash_raises(self):
        with pytest.raises(ArgumentError):
            parse_key_id("agent.example.com#k1#extra")


class TestTagValidation:
    def test_valid_tag_names(self):
        for name in ("v", "gi", "ku", "lr", "su", "sg", "fl", "ka", "cu", "ext1", "myTag_1"):
            assert is_valid_tag_name(name), f"expected valid: {name!r}"

    def test_invalid_tag_names(self):
        for name in ("1start", "", "has space", "has-hyphen"):
            assert not is_valid_tag_name(name), f"expected invalid: {name!r}"

    def test_valid_tag_values(self):
        for val in ("DNSid1", "https://example.com", "abc123", ""):
            assert is_valid_tag_value(val)

    def test_invalid_tag_values(self):
        for val in ("has space", "has;semicolon"):
            assert not is_valid_tag_value(val), f"expected invalid: {val!r}"


class TestSignatureParams:
    def test_serialize_round_trip(self):
        params = SignatureParams(
            label="sig1",
            key_id="agent.example.com#k1",
            alg="ecdsa-p256-sha256",
            created=1700000000,
            expires=None,
            nonce="abc123",
            components=["@method", "@authority", "@target-uri"],
        )
        serialized = params.serialize()
        assert serialized.startswith("sig1=")
        assert '"@method"' in serialized
        assert 'keyid="agent.example.com#k1"' in serialized
        assert "created=1700000000" in serialized

        parsed = SignatureParams.parse(serialized)
        assert parsed.label == "sig1"
        assert parsed.key_id == "agent.example.com#k1"
        assert parsed.alg == "ecdsa-p256-sha256"
        assert parsed.created == 1700000000
        assert parsed.components == ["@method", "@authority", "@target-uri"]

    def test_parse_missing_components_list_raises(self):
        from dnsid.exceptions import VerificationError

        with pytest.raises(VerificationError):
            SignatureParams.parse("sig1=keyid=bad")

    def test_value_string_excludes_label(self):
        params = SignatureParams(
            label="sig1",
            key_id="d#k",
            alg="ed25519",
            created=100,
            expires=None,
            nonce="n",
            components=["@method"],
        )
        vs = params.value_string()
        assert not vs.startswith("sig1=")
        assert vs.startswith('("@method")')
