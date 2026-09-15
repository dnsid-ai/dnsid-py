"""Tests for DnsIdTxtRecord parse, validate, canonical, serialize, policy_flags."""

from __future__ import annotations

import pytest

from dnsid import DnsIdTxtRecord, TLSCertificate
from dnsid.exceptions import ParseError, ValidationError

# Two-key profile record (ek required). This is the SDK's generated wire version.
_VALID_RECORD = (
    "v=dnsid-draft-01;"
    "gi=example.com;"
    "ek=https://example.com/.well-known/jwks.json;"
    "ku=https://agent.example.com/.well-known/jwks.json;"
    "lr=microledger:abc;"
    "su=https://agent.example.com/status;"
    "sg=dGVzdA"
)


class TestParse:
    def test_parses_valid_record(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD)
        assert r.v == "dnsid-draft-01"
        assert r.gi == "example.com"
        assert r.ku == "https://agent.example.com/.well-known/jwks.json"
        assert r.lr == "microledger:abc"
        assert r.su == "https://agent.example.com/status"
        assert r.sg == "dGVzdA"

    def test_missing_v_tag_raises(self):
        raw = "gi=example.com;ku=https://x.com/jwks.json;lr=m:a;su=https://x.com/s;sg=abc"
        with pytest.raises(ParseError):
            DnsIdTxtRecord.parse(raw)

    def test_v_not_first_raises(self):
        raw = "gi=example.com;v=dnsid-draft-01;ek=https://example.com/j;ku=https://x.com/j;lr=m:a;su=https://x.com/s;sg=a"
        with pytest.raises(ParseError):
            DnsIdTxtRecord.parse(raw)

    def test_duplicate_tag_raises(self):
        raw = _VALID_RECORD + ";gi=other.com"
        with pytest.raises(ParseError):
            DnsIdTxtRecord.parse(raw)

    def test_invalid_tag_name_raises(self):
        raw = "v=dnsid-draft-01;gi=example.com;ek=https://example.com/j;ku=https://a.com/j;lr=m:a;su=https://a.com/s;sg=x;123bad=val"
        with pytest.raises(ParseError):
            DnsIdTxtRecord.parse(raw)

    def test_trailing_semicolon_allowed(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD + ";")
        assert r.v == "dnsid-draft-01"

    def test_optional_tags_parsed(self):
        raw = _VALID_RECORD + ";fl=mtls,logchk;ka=30d;cu=https://agent.example.com/agents.md"
        r = DnsIdTxtRecord.parse(raw)
        assert r.fl == "mtls,logchk"
        assert r.ka == "30d"
        assert r.cu == "https://agent.example.com/agents.md"

    def test_unknown_tags_preserved(self):
        raw = _VALID_RECORD + ";xt=custom_value"
        r = DnsIdTxtRecord.parse(raw)
        assert r.unknown_tags.get("xt") == "custom_value"

    def test_missing_required_tag_raises(self):
        raw = "v=dnsid-draft-01;gi=example.com;ek=https://example.com/j;ku=https://a.com/j;lr=m:a;su=https://a.com/s"  # no sg
        with pytest.raises(ParseError, match="sg"):
            DnsIdTxtRecord.parse(raw)

    def test_empty_required_tag_from_issue_raises(self):
        raw = "v=dnsid-draft-01;gi=;ek=https://example.com/jwks.json;ku=https://agent.example.com/jwks.json;lr=microledger:abc123;su=https://agent.example.com/status;sg=AAAA"
        with pytest.raises(ParseError):
            DnsIdTxtRecord.parse(raw)

    @pytest.mark.parametrize("tag", ["v", "gi", "ek", "ku", "lr", "su", "sg"])
    def test_each_empty_required_tag_raises(self, tag):
        pairs = {
            "v": "dnsid-draft-01",
            "gi": "example.com",
            "ek": "https://example.com/jwks.json",
            "ku": "https://agent.example.com/jwks.json",
            "lr": "microledger:abc",
            "su": "https://agent.example.com/status",
            "sg": "EdDSA:AAAA",
        }
        pairs[tag] = ""
        raw = ";".join(f"{k}={v}" for k, v in pairs.items())
        with pytest.raises(ParseError):
            DnsIdTxtRecord.parse(raw)

    def test_space_after_semicolon_accepted(self):
        raw = "v=DNSid1; gi=example.com;ek=https://example.com/j;ku=https://agent.example.com/j;lr=m:a;su=https://agent.example.com/s;sg=x"
        r = DnsIdTxtRecord.parse(raw)
        assert r.gi == "example.com"


    def test_unsupported_version_raises(self):
        raw = "v=dnsid-draft02;gi=example.com;ku=https://agent.example.com/jwks.json;lr=m:a;su=https://agent.example.com/status;sg=abc"
        with pytest.raises(ParseError, match="unsupported"):
            DnsIdTxtRecord.parse(raw)

    def test_oi_is_preserved_as_an_unknown_extension(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD + ";oi=example.com")
        assert r.unknown_tags["oi"] == "example.com"
        assert "oi=example.com" in r.canonical()


class TestVersionDispatch:
    """Per-version required-tag dispatch: ek on two-key profiles only (issue #99)."""

    _TWO_KEY_VERSIONS = ["dnsid-draft-01", "DNSid1"]
    # Known historical keys the profile support matrix rejects outright.
    _UNSUPPORTED_VERSIONS = [
        "dnsid-draft-00",
        "dnsid-draft01",
        "dnsid-draft-01-20260504",
        "dnsid-draft-01-20260527",
        "dnsid-draft-01-20260626",
    ]

    @staticmethod
    def _record(version: str, *, ek: bool) -> str:
        parts = [f"v={version}", "gi=example.com"]
        if ek:
            parts.append("ek=https://example.com/.well-known/jwks.json")
        parts += [
            "ku=https://agent.example.com/.well-known/jwks.json",
            "lr=microledger:abc",
            "su=https://agent.example.com/status",
            "sg=dGVzdA",
        ]
        return ";".join(parts)



    @pytest.mark.parametrize("version", _TWO_KEY_VERSIONS)
    def test_two_key_parses_with_ek(self, version):
        r = DnsIdTxtRecord.parse(self._record(version, ek=True))
        assert r.v == version
        assert r.ek == "https://example.com/.well-known/jwks.json"

    @pytest.mark.parametrize("version", _TWO_KEY_VERSIONS)
    def test_two_key_requires_ek(self, version):
        with pytest.raises(ParseError, match="ek"):
            DnsIdTxtRecord.parse(self._record(version, ek=False))

    @pytest.mark.parametrize("version", _UNSUPPORTED_VERSIONS)
    def test_unsupported_historical_version_rejected(self, version):
        with pytest.raises(ParseError, match="unsupported"):
            DnsIdTxtRecord.parse(self._record(version, ek=True))
        with pytest.raises(ParseError, match="unsupported"):
            DnsIdTxtRecord.parse(self._record(version, ek=False))

    def test_dnsid1_requires_ek_explicit(self):
        # Explicit (non-parametrized) guard that the DNSid1 literal inherits the
        # two-key ek requirement, not just via the shared parametrized path.
        raw = (
            "v=DNSid1;gi=example.com;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "lr=microledger:abc;su=https://agent.example.com/status;sg=dGVzdA"
        )
        with pytest.raises(ParseError, match="ek"):
            DnsIdTxtRecord.parse(raw)


class TestCanonical:
    def test_excludes_sg(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD)
        canonical = r.canonical()
        assert "sg=" not in canonical

    def test_alphabetical_order(self):
        # DNSid1 canonical form: all tags (excluding sg) sorted alphabetically,
        # so v= sorts last, after su=.
        raw = _VALID_RECORD + ";fl=mtls;ka=30d"
        r = DnsIdTxtRecord.parse(raw)
        canonical = r.canonical()
        tags = [t.split("=")[0] for t in canonical.split(";")]
        assert tags == sorted(tags), "all tags must be alphabetically sorted"
        assert tags[-1] == "v"

    def test_no_whitespace(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD)
        assert " " not in r.canonical()

    def test_unknown_tags_included_in_canonical(self):
        raw = _VALID_RECORD + ";xt=custom"
        r = DnsIdTxtRecord.parse(raw)
        assert "xt=custom" in r.canonical()

    def test_semicolon_separated(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD)
        canonical = r.canonical()
        assert ";" in canonical
        assert "\n" not in canonical

    def test_dnsid1_canonical_all_tags_alphabetical(self):
        """DNSid1 profile sorts all tags alphabetically (v= last)."""
        raw = (
            "v=DNSid1;"
            "gi=example.com;"
            "ek=https://example.com/.well-known/jwks.json;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "lr=microledger:abc;"
            "su=https://agent.example.com/status;"
            "sg=dGVzdA"
        )
        r = DnsIdTxtRecord.parse(raw)
        canonical = r.canonical()
        tags = canonical.split(";")
        assert tags == sorted(tags)
        # v= must NOT be first — it sorts after ek, gi, ku, lr, su
        assert not canonical.startswith("v=")
        assert tags[-1].startswith("v=")



class TestSerialize:
    def test_v_is_first(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD)
        assert r.serialize().startswith("v=dnsid-draft-01;")

    def test_empty_optional_tags_omitted(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD)
        serialized = r.serialize()
        for tag in ("fl=", "ka=", "cu="):
            assert tag not in serialized

    def test_round_trip(self):
        raw = _VALID_RECORD + ";fl=logchk;ka=7d"
        r = DnsIdTxtRecord.parse(raw)
        r2 = DnsIdTxtRecord.parse(r.serialize())
        assert r2.gi == r.gi
        assert r2.fl == r.fl
        assert r2.ka == r.ka


class TestValidate:
    def _make(self, **kwargs) -> DnsIdTxtRecord:
        defaults = dict(
            v="DNSid1",
            gi="example.com",
            ek="https://example.com/.well-known/jwks.json",
            ku="https://agent.example.com/.well-known/jwks.json",
            lr="microledger:abc",
            su="https://agent.example.com/status",
            sg="dGVzdA",
            identity_fqdn="agent.example.com",
        )
        defaults.update(kwargs)
        r = DnsIdTxtRecord(**defaults)
        return r

    def test_valid_record_passes(self):
        self._make().validate()

    def test_unsupported_profile_raises(self):
        with pytest.raises(ValidationError, match="unsupported DNSid profile"):
            self._make(v="dnsid-draft-02").validate()



    def test_gi_need_not_be_parent_when_ek_is_beneath_it(self):
        self._make(gi="other.com", ek="https://keys.other.com/jwks.json").validate()

    def test_ku_non_https_raises(self):
        r = self._make(ku="http://agent.example.com/jwks.json")
        with pytest.raises(ValidationError, match="https"):
            r.validate()

    def test_ku_host_mismatch_raises(self):
        r = self._make(ku="https://other.example.com/.well-known/jwks.json")
        with pytest.raises(ValidationError, match="ku host"):
            r.validate()

    def test_su_on_registry_host_passes(self):
        """su is the registry-hosted status endpoint and may be on a different
        host than the identity FQDN; it is HTTPS-validated but not host-pinned
        (SSRF is bounded at fetch time: HTTPS-only redirects, public-address
        resolution, and bounded response size)."""
        r = self._make(su="https://registry.example.net/v1/status/agent.example.com")
        r.validate()

    def test_su_must_be_https(self):
        r = self._make(su="http://registry.example.net/v1/status/agent.example.com")
        with pytest.raises(ValidationError):
            r.validate()

    def test_su_host_matching_agent_passes(self):
        """su on the same host as the agent FQDN validates successfully (#17)."""
        r = self._make(su="https://agent.example.com/status/v2")
        r.validate()

    def test_su_non_https_raises(self):
        """su with http:// scheme must raise ValidationError (#17)."""
        r = self._make(su="http://agent.example.com/status")
        with pytest.raises(ValidationError, match="https"):
            r.validate()

    @pytest.mark.parametrize("field", ["ek", "ku", "su", "cu"])
    @pytest.mark.parametrize(
        ("url", "message"),
        [
            ("https://user:pass@agent.example.com/path", "credentials"),
            ("https://agent.example.com/path#fragment", "fragment"),
        ],
    )
    def test_urls_reject_credentials_and_fragments(self, field, url, message):
        if field == "ek":
            url = url.replace("agent.example.com", "example.com")
        r = self._make(**{field: url})
        with pytest.raises(ValidationError, match=message):
            r.validate()

    def test_bad_ka_value_raises(self):
        r = self._make(ka="48h")
        with pytest.raises(ValidationError, match="ka"):
            r.validate()

    @pytest.mark.parametrize(
        "bad_lr",
        [
            "nocolon",  # no ':' separator
            ":entry",  # empty method
            "Bad:entry",  # method has uppercase
            "1bad:entry",  # method starts with digit
        ],
    )
    def test_malformed_lr_rejected_by_validate(self, bad_lr):
        r = self._make(lr=bad_lr)
        with pytest.raises(ValidationError, match="malformed lr value"):
            r.validate()

    def test_malformed_lr_accepted_by_parse(self):
        """parse() should not reject malformed lr values — that's validate()'s job."""
        # Build a valid record, serialise it, then swap in a malformed lr value
        # so the test stays version-independent.
        good = self._make(lr="microledger:abc")
        raw = good.serialize().replace("lr=microledger:abc", "lr=BADVALUE")
        r = DnsIdTxtRecord.parse(raw)
        assert r.lr == "BADVALUE"

    def test_valid_lr_passes_validate(self):
        r = self._make(lr="microledger:abc123")
        r.validate()

    def test_gi_equal_to_fqdn_passes(self):
        r = self._make(
            gi="agent.example.com",
            ek="https://agent.example.com/.well-known/jwks.json",
            identity_fqdn="agent.example.com",
        )
        r.validate()

    def test_ek_non_https_raises(self):
        r = self._make(ek="http://example.com/.well-known/jwks.json")
        with pytest.raises(ValidationError, match="https"):
            r.validate()

    def test_ek_subdomain_of_gi_passes(self):
        r = self._make(ek="https://keys.example.com/.well-known/jwks.json")
        r.validate()

    def test_ek_host_not_under_gi_raises(self):
        r = self._make(ek="https://attacker.com/.well-known/jwks.json")
        with pytest.raises(ValidationError, match="ek host"):
            r.validate()

    def test_uppercase_gi_raises(self):
        # DNSid1 gi is signed wire content and must already be in normalized
        # lowercase form; case-variant values are rejected, not normalized.
        r = self._make(gi="Example.COM", identity_fqdn="agent.example.com")
        with pytest.raises(ValidationError, match="gi must be a lowercase ASCII DNS domain"):
            r.validate()

    def test_gi_with_trailing_dot_raises(self):
        r = self._make(gi="example.com.")
        with pytest.raises(ValidationError, match="gi must be a lowercase ASCII DNS domain"):
            r.validate()

    def test_non_domain_gi_raises(self):
        # DNSid1 gi must be a lowercase ASCII DNS domain; URN-style governance
        # identifiers belong to older or future profiles.
        r = self._make(gi="algorand:ADDR123", ek="https://keys.example/jwks.json")
        with pytest.raises(ValidationError, match="gi must be a lowercase ASCII DNS domain"):
            r.validate()


_VALID_UNSIGNED = (
    "ek=https://example.com/.well-known/jwks.json;"
    "gi=example.com;"
    "ku=https://agent.example.com/.well-known/jwks.json;"
    "lr=microledger:abc;"
    "su=https://agent.example.com/status;"
    "v=DNSid1"
)


class TestParseUnsignedCanonical:
    def test_valid_unsigned_canonical_parses(self):
        r = DnsIdTxtRecord.parse_unsigned_canonical(_VALID_UNSIGNED)
        assert r.gi == "example.com"
        assert r.sg == ""

    def test_sg_tag_present_raises(self):
        with pytest.raises(ParseError, match="sg"):
            DnsIdTxtRecord.parse_unsigned_canonical(_VALID_UNSIGNED + ";sg=abc")

    def test_out_of_order_tags_raises(self):
        # Tags after v= must be in alphabetical order; swapping gi and ku breaks that.
        out_of_order = (
            "ek=https://example.com/.well-known/jwks.json;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "gi=example.com;"
            "lr=microledger:abc;"
            "su=https://agent.example.com/status;"
            "v=DNSid1"
        )
        with pytest.raises(ParseError, match="canonical form"):
            DnsIdTxtRecord.parse_unsigned_canonical(out_of_order)

    def test_identity_fqdn_valid_passes(self):
        r = DnsIdTxtRecord.parse_unsigned_canonical(
            _VALID_UNSIGNED, identity_fqdn="agent.example.com"
        )
        assert r.identity_fqdn == "agent.example.com"

    def test_identity_fqdn_mismatch_raises(self):
        # ku host is agent.example.com but identity_fqdn says other.example.com
        with pytest.raises(ValidationError):
            DnsIdTxtRecord.parse_unsigned_canonical(
                _VALID_UNSIGNED, identity_fqdn="other.example.com"
            )

    def test_missing_required_tag_raises(self):
        missing_su = (
            "ek=https://example.com/.well-known/jwks.json;"
            "gi=example.com;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "lr=microledger:abc;"
            "v=DNSid1"
        )
        with pytest.raises(ParseError, match="su"):
            DnsIdTxtRecord.parse_unsigned_canonical(missing_su)


    def test_dnsid1_v_last_unsigned_canonical_parses(self):
        unsigned = (
            "ek=https://example.com/.well-known/jwks.json;"
            "gi=example.com;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "lr=microledger:abc;"
            "su=https://agent.example.com/status;"
            "v=DNSid1"
        )
        r = DnsIdTxtRecord.parse_unsigned_canonical(unsigned)
        assert r.v == "DNSid1"
        assert r.canonical() == unsigned

    def test_dnsid1_v_first_unsigned_canonical_raises(self):
        unsigned = (
            "v=DNSid1;"
            "ek=https://example.com/.well-known/jwks.json;"
            "gi=example.com;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "lr=microledger:abc;"
            "su=https://agent.example.com/status"
        )
        with pytest.raises(ParseError, match="canonical form"):
            DnsIdTxtRecord.parse_unsigned_canonical(unsigned)


class TestKnownTagsCanonical:
    def test_includes_required_tags(self):
        r = DnsIdTxtRecord.parse_unsigned_canonical(_VALID_UNSIGNED)
        ktc = r.known_tags_canonical()
        assert "v=DNSid1" in ktc
        assert "gi=example.com" in ktc
        assert "ku=https://agent.example.com/.well-known/jwks.json" in ktc
        assert "su=https://agent.example.com/status" in ktc

    def test_includes_cu_when_set(self):
        # cu sorts before ek alphabetically, so it must appear in that position.
        canonical_with_cu = (
            "cu=https://agent.example.com/agents.md;"
            "ek=https://example.com/.well-known/jwks.json;"
            "gi=example.com;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "lr=microledger:abc;"
            "su=https://agent.example.com/status;"
            "v=DNSid1"
        )
        r = DnsIdTxtRecord.parse_unsigned_canonical(canonical_with_cu)
        assert "cu=https://agent.example.com/agents.md" in r.known_tags_canonical()

    def test_omits_cu_when_not_set(self):
        r = DnsIdTxtRecord.parse_unsigned_canonical(_VALID_UNSIGNED)
        assert "cu=" not in r.known_tags_canonical()

    def test_excludes_unknown_tags(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD + ";xt=custom")
        assert "xt=" not in r.known_tags_canonical()

    def test_dnsid1_known_tags_canonical_sorts_v_last(self):
        r = DnsIdTxtRecord.parse_unsigned_canonical(
            "ek=https://example.com/.well-known/jwks.json;"
            "gi=example.com;"
            "ku=https://agent.example.com/.well-known/jwks.json;"
            "lr=microledger:abc;"
            "su=https://agent.example.com/status;"
            "v=DNSid1"
        )
        tags = [t.split("=")[0] for t in r.known_tags_canonical().split(";")]
        assert tags == sorted(tags)
        assert tags[-1] == "v"

    def test_excludes_sg(self):
        r = DnsIdTxtRecord.parse(_VALID_RECORD)
        assert "sg=" not in r.known_tags_canonical()



class TestTLSCertificateDNSNames:
    def test_exact_san_matches_case_insensitively(self):
        TLSCertificate(san_dns_names=["Agent.Example.COM"]).validate_against_fqdn(
            "agent.example.com"
        )

    def test_leftmost_wildcard_matches_exactly_one_label(self):
        cert = TLSCertificate(san_dns_names=["*.example.com"])
        cert.validate_against_fqdn("agent.example.com")
        with pytest.raises(ValidationError, match="does not match"):
            cert.validate_against_fqdn("nested.agent.example.com")
        with pytest.raises(ValidationError, match="does not match"):
            cert.validate_against_fqdn("example.com")

    @pytest.mark.parametrize(
        "san",
        ["agent*.example.com", "*.*.example.com", "other.example.com"],
    )
    def test_invalid_or_different_san_does_not_match(self, san):
        with pytest.raises(ValidationError, match="does not match"):
            TLSCertificate(san_dns_names=[san]).validate_against_fqdn(
                "agent.example.com"
            )

    def test_common_name_fallback_is_not_possible_without_dns_sans(self):
        with pytest.raises(ValidationError, match="does not match"):
            TLSCertificate().validate_against_fqdn("agent.example.com")


class TestPolicyFlags:
    def test_empty_fl_returns_empty_set(self):
        r = DnsIdTxtRecord()
        assert r.policy_flags() == frozenset()

    def test_single_flag(self):
        r = DnsIdTxtRecord(fl="mtls")
        assert r.policy_flags() == frozenset({"mtls"})

    def test_multiple_flags(self):
        r = DnsIdTxtRecord(fl="mtls,logchk")
        assert "mtls" in r.policy_flags()
        assert "logchk" in r.policy_flags()

    def test_whitespace_trimmed(self):
        r = DnsIdTxtRecord(fl=" mtls , logchk ")
        assert r.policy_flags() == frozenset({"mtls", "logchk"})
