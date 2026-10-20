"""Tests for the built-in DNS resolver's DNSSEC state reporting."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import httpx
import pytest

from dnsid import (
    DnsidConfig,
    IdentityManager,
    IdentityManagerDependencies,
    VerificationConfig,
)
from dnsid._default_resolver import DefaultDNSResolver
from dnsid.enums import DNSSECMode, DNSSECState, VerificationCode
from dnsid.exceptions import VerificationError


def _doh_response(payload):
    response = MagicMock()
    response.is_success = True
    import json
    response.content = json.dumps(payload).encode()
    response.status_code = 200
    response.headers = httpx.Headers()
    response.is_stream_consumed = True
    response.iter_bytes.return_value = [response.content]
    response.__enter__.return_value = response
    response.json.return_value = payload
    return response


def test_doh_ad_response_is_valid():
    resolver = DefaultDNSResolver("https://resolver.example")
    response = _doh_response({"Status": 0, "AD": True, "Answer": []})

    with patch("httpx.Client.stream", return_value=response):
        records, state = resolver.fetch_txt("_dnsid.example.com")

    assert records == []
    assert state == DNSSECState.VALID


def test_insecure_doh_ad_response_is_unknown():
    resolver = DefaultDNSResolver("http://resolver.example")
    response = _doh_response({"Status": 0, "AD": True, "Answer": []})

    with patch("httpx.Client.stream", return_value=response):
        records, state = resolver.fetch_txt("_dnsid.example.com")

    assert records == []
    assert state == DNSSECState.UNKNOWN


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize(
    ("ttl_fields", "expected_ttl"), [({}, 0), ({"TTL": 0}, 0), ({"TTL": 60}, 60)]
)
def test_doh_txt_ttl_does_not_invent_freshness(scheme, ttl_fields, expected_ttl):
    resolver = DefaultDNSResolver(f"{scheme}://resolver.example")
    response = _doh_response({
        "Status": 0,
        "Answer": [{"type": 16, "data": '"v=DNSid1"', **ttl_fields}],
    })

    with patch("httpx.Client.stream", return_value=response):
        records, _state = resolver.fetch_txt("_dnsid.example.com")

    assert len(records) == 1
    assert records[0].strings == [b"v=DNSid1"]
    assert records[0].ttl == expected_ttl


def test_doh_no_ad_response_is_unknown():
    resolver = DefaultDNSResolver("https://resolver.example")
    response = _doh_response({"Status": 0, "AD": False, "Answer": []})

    with patch("httpx.Client.stream", return_value=response):
        records, state = resolver.fetch_txt("_dnsid.example.com")

    assert records == []
    assert state == DNSSECState.UNKNOWN


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_doh_servfail_is_not_assumed_to_be_dnssec_failed(scheme):
    resolver = DefaultDNSResolver(f"{scheme}://resolver.example")
    response = _doh_response({"Status": 2})

    with (
        patch("httpx.Client.stream", return_value=response),
        pytest.raises(VerificationError) as exc_info,
    ):
        resolver.fetch_txt("_dnsid.example.com")

    assert exc_info.value.code == VerificationCode.DNS_RESOLUTION
    assert exc_info.value.transient is True


@pytest.mark.parametrize("transport", ["system", "configured", "injected"])
@pytest.mark.parametrize("mode", list(DNSSECMode))
@pytest.mark.parametrize(
    ("error", "state"),
    [
        (dns.resolver.NXDOMAIN(), DNSSECState.UNKNOWN),
        (dns.resolver.NoAnswer(), DNSSECState.UNKNOWN),
        (dns.exception.ValidationFailure(), DNSSECState.FAILED),
        (dns.exception.Timeout(), None),
        (dns.resolver.NoNameservers(), None),
        (OSError("network unreachable"), None),
        (TimeoutError("deadline elapsed"), None),
    ],
)
def test_runtime_dns_outcome_matrix(transport, mode, error, state):
    resolver = DefaultDNSResolver("192.0.2.53:5353" if transport == "configured" else "")
    if transport == "injected":
        resolver = MagicMock()
        query = patch.object(resolver, "fetch_txt", side_effect=error)
    else:
        target = (
            "dns.resolver.Resolver.resolve" if transport == "configured"
            else "dns.resolver.resolve"
        )
        query = patch(target, side_effect=error)
    manager = IdentityManager(
        DnsidConfig(verification=VerificationConfig(dnssec_mode=mode)),
        deps=IdentityManagerDependencies(dns_resolver=resolver),
    )
    with query:
        if transport != "injected" and state is not None:
            assert resolver.fetch_txt("_dnsid.example.com") == ([], state)
        with pytest.raises(VerificationError) as exc_info:
            manager.verify_domain("example.com")

    expected = VerificationCode.DNS_RESOLUTION
    if state is not None:
        expected = (
            VerificationCode.RECORD_NOT_FOUND
            if state == DNSSECState.UNKNOWN and mode == DNSSECMode.AUTO
            else VerificationCode.DNSSEC_FAILED
        )
    assert exc_info.value.code == expected
    assert exc_info.value.transient is (state is None)
    if state is None:
        assert exc_info.value.__cause__ is error


@pytest.mark.parametrize("server", ["", "192.0.2.53:5353"])
def test_sync_dns_preserves_verification_deadlines(server):
    failure = VerificationError(VerificationCode.DEADLINE_EXCEEDED, "deadline", transient=True)
    target = "dns.resolver.Resolver.resolve" if server else "dns.resolver.resolve"
    with patch(target, side_effect=failure):
        with pytest.raises(VerificationError) as error:
            DefaultDNSResolver(server).fetch_txt("_dnsid.example.com")
    assert error.value is failure


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("status", [0, 3], ids=["nodata", "nxdomain"])
@pytest.mark.parametrize("ad", [False, True])
@pytest.mark.parametrize("mode", list(DNSSECMode))
def test_doh_absence_and_dnssec_policy(scheme, status, ad, mode):
    resolver = DefaultDNSResolver(f"{scheme}://resolver.example")
    response = _doh_response({"Status": status, "AD": ad, "Answer": []})
    state = DNSSECState.VALID if scheme == "https" and ad else DNSSECState.UNKNOWN
    manager = IdentityManager(
        DnsidConfig(verification=VerificationConfig(dnssec_mode=mode)),
        deps=IdentityManagerDependencies(dns_resolver=resolver),
    )
    with patch("httpx.Client.stream", return_value=response):
        assert resolver.fetch_txt("_dnsid.example.com") == ([], state)
        with pytest.raises(VerificationError) as exc_info:
            manager.verify_domain("example.com")

    assert exc_info.value.code == (
        VerificationCode.RECORD_NOT_FOUND
        if state == DNSSECState.VALID or mode == DNSSECMode.AUTO
        else VerificationCode.DNSSEC_FAILED
    )
    assert exc_info.value.transient is False


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("error", [httpx.ReadTimeout("timeout"), httpx.ConnectError("offline")])
def test_doh_network_errors_are_transient(scheme, error):
    resolver = DefaultDNSResolver(f"{scheme}://resolver.example")
    with (
        patch("httpx.Client.stream", side_effect=error),
        pytest.raises(VerificationError) as exc_info,
    ):
        resolver.fetch_txt("_dnsid.example.com")
    assert exc_info.value.code == VerificationCode.DNS_RESOLUTION
    assert exc_info.value.transient is True


@pytest.mark.parametrize("transport", ["system", "configured", "http", "https", "injected"])
@pytest.mark.parametrize("records", [["malformed"], ["first", "second"]])
def test_invalid_records_remain_record_invalid(transport, records):
    from contextlib import ExitStack
    from types import SimpleNamespace

    from dnsid import TXTRecord

    resolver = DefaultDNSResolver("192.0.2.53:5353" if transport == "configured" else "")
    with ExitStack() as stack:
        if transport in ("http", "https"):
            resolver = DefaultDNSResolver(f"{transport}://resolver.example")
            response = _doh_response({
                "Status": 0,
                "Answer": [{"type": 16, "data": f'"{raw}"', "TTL": 300} for raw in records],
            })
            stack.enter_context(patch("httpx.Client.stream", return_value=response))
        elif transport == "injected":
            resolver = MagicMock()
            resolver.fetch_txt.return_value = (
                [TXTRecord(strings=[raw.encode()], ttl=300) for raw in records],
                DNSSECState.UNKNOWN,
            )
        else:
            answers = MagicMock(ttl=300)
            answers.__iter__.side_effect = lambda: iter(
                [SimpleNamespace(strings=[raw.encode()]) for raw in records]
            )
            target = (
                "dns.resolver.Resolver.resolve" if transport == "configured"
                else "dns.resolver.resolve"
            )
            stack.enter_context(patch(target, return_value=answers))
        manager = IdentityManager(deps=IdentityManagerDependencies(dns_resolver=resolver))
        with pytest.raises(VerificationError) as exc_info:
            manager.verify_domain("example.com")
    assert exc_info.value.code == VerificationCode.RECORD_INVALID
    assert exc_info.value.transient is False
