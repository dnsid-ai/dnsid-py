"""Tests for the built-in DNS resolver's DNSSEC state reporting."""

from unittest.mock import MagicMock, patch

import pytest

from dnsid._default_resolver import DefaultDNSResolver
from dnsid.enums import DNSSECState, VerificationCode
from dnsid.exceptions import VerificationError


def _doh_response(payload):
    response = MagicMock()
    response.is_success = True
    import json
    response.content = json.dumps(payload).encode()
    response.status_code = 200
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


def test_doh_no_ad_response_is_unknown():
    resolver = DefaultDNSResolver("https://resolver.example")
    response = _doh_response({"Status": 0, "AD": False, "Answer": []})

    with patch("httpx.Client.stream", return_value=response):
        records, state = resolver.fetch_txt("_dnsid.example.com")

    assert records == []
    assert state == DNSSECState.UNKNOWN


def test_doh_servfail_is_not_assumed_to_be_dnssec_failed():
    resolver = DefaultDNSResolver("https://resolver.example")
    response = _doh_response({"Status": 2})

    with (
        patch("httpx.Client.stream", return_value=response),
        pytest.raises(VerificationError) as exc_info,
    ):
        resolver.fetch_txt("_dnsid.example.com")

    assert exc_info.value.code == VerificationCode.DNS_RESOLUTION
    assert exc_info.value.transient is True
