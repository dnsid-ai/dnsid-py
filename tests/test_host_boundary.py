"""Host-boundary checks that bind a record's key endpoints to DNS names.

ku= must equal the identity FQDN, ek= must sit at or under the gi= governance
domain, and a pinned redirect must stay on the allowed host. Every check compares
hosts in ``normalize_fqdn`` form (UTS 46, A-label, lowercase): the name the
transport resolves and presents as TLS SNI. The same tables exist in the Go and
TypeScript SDKs, so a record is accepted or rejected the same way by all three.

The length tests pin which limit applies where: the 246-octet limit is for the
agent (identity) FQDN only, so that ``_dnsid.<fqdn>`` fits in 253 octets. gi and
endpoint hosts are ordinary DNS names and take the 253-octet DNS limit.
"""

from __future__ import annotations

import httpx
import pytest

from dnsid import DnsIdTxtRecord
from dnsid._https_client import _assert_same_host_https_redirect, _host_allowed, fetch_jwks
from dnsid._utils import normalize_fqdn
from dnsid.enums import VerificationCode
from dnsid.exceptions import ValidationError, VerificationError

_IDENTITY = "agent.identity.example"
_GI = "identity.example"


def _record(**overrides: str) -> DnsIdTxtRecord:
    """Return a record valid for agent.identity.example under gi identity.example."""
    fields = dict(
        v="DNSid1",
        gi=_GI,
        ek=f"https://keys.{_GI}/ek.json",
        ku=f"https://{_IDENTITY}/ku.json",
        lr="testlog:agent",
        su=f"https://{_IDENTITY}/status",
        sg="dGVzdA",
        identity_fqdn=_IDENTITY,
    )
    fields.update(overrides)
    return DnsIdTxtRecord(**fields)


def _long_name(octets: int, suffix: str) -> str:
    """Return a valid DNS name of exactly *octets* ending in *suffix* (labels of at most 63)."""
    labels: list[str] = []
    remaining = octets - len(suffix)
    while remaining > 0:
        # Each label costs its length plus one separating dot.
        size = min(63, remaining - 1)
        assert size >= 1, f"cannot build a {octets}-octet name ending in {suffix!r}"
        labels.append("a" * size)
        remaining -= size + 1
    name = ".".join([*labels, suffix])
    assert len(name) == octets
    return name


def _assert_validation(record: DnsIdTxtRecord, error: str | None) -> None:
    if error is None:
        record.validate()
        return
    with pytest.raises(ValidationError) as exc_info:
        record.validate()
    assert error in str(exc_info.value)


@pytest.mark.parametrize(
    ("ku", "error"),
    [
        pytest.param(f"https://{_IDENTITY}/ku.json", None, id="canonical"),
        pytest.param(f"https://{_IDENTITY}:8443/ku.json", None, id="with-port"),
        pytest.param("https://AGENT.Identity.EXAMPLE/ku.json", None, id="uppercase"),
        pytest.param(f"https://{_IDENTITY}./ku.json", "ku host must not end with a root dot", id="trailing-dot"),
        pytest.param("https://other.identity.example/ku.json", "ku host must equal identity FQDN", id="other-host"),
        pytest.param("https://identity.example/ku.json", "ku host must equal identity FQDN", id="parent-domain"),
        pytest.param(
            f"https://{_IDENTITY}.attacker.example/ku.json", "ku host must equal identity FQDN",
            id="identity-as-prefix",
        ),
        pytest.param("https://agent.%C4%B0dentity.example/ku.json", "without percent-escapes", id="percent-encoded-u0130"),
        pytest.param("https://agent.identity%2Eexample/ku.json", "without percent-escapes", id="percent-encoded-dot"),
        pytest.param("https://agent.İdentity.example/ku.json", "without percent-escapes", id="raw-u0130"),
        pytest.param("https://-agent.identity.example/ku.json", "Invalid FQDN label", id="leading-hyphen-label"),
    ],
)
def test_ku_host_compared_in_canonical_form(ku: str, error: str | None):
    _assert_validation(_record(ku=ku), error)


@pytest.mark.parametrize(
    ("ek", "error"),
    [
        pytest.param(f"https://{_GI}/ek.json", None, id="at-gi"),
        pytest.param(f"https://keys.{_GI}/ek.json", None, id="under-gi"),
        pytest.param(f"https://a.b.keys.{_GI}/ek.json", None, id="deeper-under-gi"),
        pytest.param("https://KEYS.Identity.EXAMPLE/ek.json", None, id="uppercase"),
        pytest.param(f"https://keys.{_GI}./ek.json", "ek host must not end with a root dot", id="trailing-dot"),
        pytest.param("https://keys.other.example/ek.json", "ek host must equal or be beneath gi", id="sibling-domain"),
        pytest.param(
            f"https://{_GI}.attacker.example/ek.json", "ek host must equal or be beneath gi",
            id="gi-as-prefix",
        ),
        pytest.param("https://notidentity.example/ek.json", "ek host must equal or be beneath gi", id="gi-as-label-suffix"),
        pytest.param("https://keys.%C4%B0dentity.example/ek.json", "without percent-escapes", id="percent-encoded-u0130"),
        pytest.param("https://keys.identity%2Eexample/ek.json", "without percent-escapes", id="percent-encoded-dot"),
        pytest.param("https://keys.İdentity.example/ek.json", "without percent-escapes", id="raw-u0130"),
        pytest.param("https://-keys.identity.example/ek.json", "Invalid FQDN label", id="leading-hyphen-label"),
    ],
)
def test_ek_host_compared_in_canonical_form(ek: str, error: str | None):
    _assert_validation(_record(ek=ek), error)


@pytest.mark.parametrize("tag", ["su", "cu"])
def test_unpinned_record_url_rejects_escaped_host(tag: str):
    # su and cu are not host-pinned, but the host as published must still be the
    # host that is dialed: a percent-escape in the host is rejected, while the
    # path and query keep their percent-encoding.
    _assert_validation(_record(**{tag: "https://status.identity%2Eexample/doc"}), "without percent-escapes")
    _assert_validation(_record(**{tag: "https://status.İdentity.example/doc"}), "without percent-escapes")
    _assert_validation(_record(**{tag: "https://status.identity.example/a%20b?q=%2E"}), None)


@pytest.mark.parametrize(
    ("host", "allowed", "boundary", "expected"),
    [
        ("example.com", "example.com", False, True),
        ("keys.example.com", "example.com", True, True),
        ("keys.example.com", "example.com", False, False),
        ("notexample.test", "example.com", True, False),
        # Hosts are compared in normalize_fqdn form on both sides: ASCII case is
        # canonicalized, and a U-label equals its A-label.
        ("KEYS.Example.COM", "example.com", True, True),
        ("keys.example.com", "Example.COM", True, True),
        ("xn--mnchen-3ya.de", "münchen.de", False, True),
        ("münchen.de", "xn--mnchen-3ya.de", False, True),
        # A trailing dot is not canonicalized away: both sides must agree on it.
        ("keys.example.com.", "example.com", True, False),
        ("keys.example.com", "example.com.", True, False),
        ("agent.example.com.", "agent.example.com", False, False),
        ("agent.example.com", "agent.example.com.", False, False),
        ("agent.example.com.", "agent.example.com.", False, True),
        ("keys.example.com.", "example.com.", True, True),
        # U+0130 does not fold to ASCII "i" under UTS 46, so the name is a
        # different registrable domain (or no valid name at all).
        ("keys.bİgcorp.com", "bigcorp.com", True, False),
        ("bİgcorp.com", "bigcorp.com", False, False),
        # A boundary match must sit on a label boundary, in canonical form too.
        ("example.com.attacker.test", "example.com", True, False),
        ("EXAMPLE.COM.attacker.test", "example.com", True, False),
        # IP literals match only the same address, never a domain boundary.
        ("192.0.2.1", "192.0.2.1", False, True),
        ("192.0.2.1", "192.0.2.1", True, True),
        ("2001:db8::1", "2001:DB8::1", False, True),
        ("192.0.2.1", "192.0.2.2", True, False),
        ("4.3.2.1", "3.2.1", True, False),
        ("keys.example.com", "192.0.2.1", True, False),
        # A host with no canonical form is never allowed. There is no fallback
        # to comparing the host as written, even under a domain boundary.
        ("", "example.com", True, False),
        ("keys.example.com", "", True, False),
        ("-keys.example.com", "example.com", True, False),
        ("a_b.example.com", "example.com", True, False),
        ("evil%2e.example.com", "example.com", True, False),
        ("a" * 64 + ".example.com", "example.com", True, False),
    ],
)
def test_host_allowed_compares_canonical_form(host: str, allowed: str, boundary: bool, expected: bool):
    assert _host_allowed(host, allowed, boundary) is expected


def test_root_dot_is_ignored_only_on_request():
    # Pinned ku/ek redirects require the root dot to match. Web Bot Auth
    # discovery matches a presented signer name instead, so it opts out; every
    # other rule still applies.
    assert not _host_allowed("agent.example.com.", "agent.example.com")
    assert _host_allowed("agent.example.com.", "agent.example.com", ignore_root_dot=True)
    assert _host_allowed("agent.example.com", "agent.example.com.", ignore_root_dot=True)
    assert not _host_allowed("other.example.com.", "agent.example.com", ignore_root_dot=True)
    assert not _host_allowed("-agent.example.com.", "example.com", True, ignore_root_dot=True)


class _RedirectOnce(httpx.BaseTransport):
    """Answers every request with a redirect to *location* and records the requests."""

    def __init__(self, location: str) -> None:
        self.location = location
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(301, headers={"location": self.location})


@pytest.mark.parametrize(
    "location",
    [
        "https://attacker.example/jwks",
        "https://example.com.attacker.example/jwks",
        "https://keys.example.com./jwks",
        "https://-keys.example.com/jwks",
        "https://a_b.example.com/jwks",
        "https://192.0.2.1/jwks",
    ],
)
def test_pinned_fetch_refuses_redirect_off_the_allowed_host(location: str):
    transport = _RedirectOnce(location)
    with pytest.raises(VerificationError) as exc_info:
        fetch_jwks("https://keys.example.com/jwks", "example.com", transport=transport, domain_boundary=True)
    assert exc_info.value.code == VerificationCode.TLS_ERROR
    # The refused hop is never requested.
    assert len(transport.requests) == 1


def test_redirect_check_accepts_any_spelling_of_the_allowed_host():
    _assert_same_host_https_redirect("https://KEYS.Example.com/jwks", "Example.COM", domain_boundary=True)
    _assert_same_host_https_redirect("https://xn--mnchen-3ya.de/jwks", "münchen.de")


class TestLengthLimits:
    def test_normalize_fqdn_applies_agent_limit_only_on_request(self):
        assert normalize_fqdn(_long_name(246, "example.com"), agent_fqdn=True)
        with pytest.raises(ValidationError, match="246-octet"):
            normalize_fqdn(_long_name(247, "example.com"), agent_fqdn=True)
        # Without the flag the DNS limit applies: 253 octets, with or without a root dot.
        name = _long_name(253, "example.com")
        assert normalize_fqdn(name) == name
        assert normalize_fqdn(name + ".") == name
        with pytest.raises(ValidationError, match="253-octet"):
            normalize_fqdn(_long_name(254, "example.com"))

    def test_identity_fqdn_keeps_the_246_octet_limit(self):
        identity = _long_name(246, "example")
        _record(identity_fqdn=identity, ku=f"https://{identity}/ku.json").validate()
        identity = _long_name(247, "example")
        _assert_validation(_record(identity_fqdn=identity, ku=f"https://{identity}/ku.json"), "246-octet")

    def test_gi_and_ek_host_take_the_dns_limit(self):
        # A delegated record's gi need not be above the agent FQDN, so it is
        # bound only by the DNS limit.
        gi = _long_name(250, "example")
        _record(gi=gi, ek=f"https://{gi}/ek.json").validate()
        gi = _long_name(254, "example")
        _assert_validation(_record(gi=gi, ek=f"https://{gi}/ek.json"), "253-octet")
        # An ek host is an ordinary DNS name under gi.
        _record(ek=f"https://{_long_name(251, _GI)}/ek.json").validate()

    def test_endpoint_host_matches_itself_up_to_the_dns_limit(self):
        # Labels 63.63.63.55.3: longer than the agent-FQDN limit, within the DNS limit.
        host = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 55, "com"])
        assert len(host) == 251
        assert _host_allowed(host.upper(), host)
        assert _host_allowed(_long_name(251, "example.com"), "example.com", True)
        longest = _long_name(253, "example.com")
        assert _host_allowed(longest, longest)
        too_long = _long_name(254, "example.com")
        assert not _host_allowed(too_long, too_long)
