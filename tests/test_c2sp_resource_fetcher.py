"""Security and exact-bound tests for C2SP standard-resource fetching."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from dnsid.c2sp_tlog import (
    C2spResourceFetchGuarantees,
    C2spTlogTransportError,
    SafeC2spResourceFetcher,
)
from dnsid.c2sp_tlog.resource_fetcher import fetch_bounded_bytes
from dnsid.models import TransportConfig
from dnsid.safe_transport import SSRF_BLOCK_MARKER

_URL = "https://resources.example/checkpoint"


def _mock_fetcher(handler: httpx.MockTransport) -> SafeC2spResourceFetcher:
    fetcher = SafeC2spResourceFetcher()
    fetcher._client.close()
    fetcher._client = httpx.Client(
        transport=handler,
        follow_redirects=False,
        timeout=1.0,
    )
    return fetcher


def test_safe_fetcher_requires_exact_http_200() -> None:
    for status in (201, 204, 301, 302, 404):
        fetcher = _mock_fetcher(
            httpx.MockTransport(lambda request, status=status: httpx.Response(status))
        )
        with pytest.raises(C2spTlogTransportError) as exc_info:
            fetcher.fetch_bounded(_URL, 10)
        assert exc_info.value.transient is False
        if 300 <= status < 400:
            assert "redirect" in str(exc_info.value)
        else:
            assert exc_info.value.status_code == status


def test_safe_fetcher_accepts_exact_decoded_bound_and_rejects_one_more() -> None:
    exact = _mock_fetcher(
        httpx.MockTransport(lambda request: httpx.Response(200, content=b"1234"))
    )
    assert exact.fetch_bounded(_URL, 4) == b"1234"

    oversized = _mock_fetcher(
        httpx.MockTransport(lambda request: httpx.Response(200, content=b"12345"))
    )
    with pytest.raises(C2spTlogTransportError, match="byte maximum 4") as exc_info:
        oversized.fetch_bounded(_URL, 4)
    assert exc_info.value.transient is False


def test_safe_fetcher_enforces_absolute_read_deadline() -> None:
    fetcher = _mock_fetcher(
        httpx.MockTransport(lambda request: httpx.Response(200, content=b"chunk"))
    )
    fetcher._timeout_seconds = 1.0
    fetcher._clock = iter([0.0, 2.0]).__next__
    with pytest.raises(C2spTlogTransportError, match="deadline exceeded") as exc_info:
        fetcher.fetch_bounded(_URL, 10)
    assert exc_info.value.transient is True


def test_safe_fetcher_rejects_credentials_fragments_and_plain_http() -> None:
    fetcher = _mock_fetcher(
        httpx.MockTransport(lambda request: pytest.fail("request must not be sent"))
    )
    for url in (
        "http://resources.example/checkpoint",
        "https://user@resources.example/checkpoint",
        "https://resources.example/checkpoint#fragment",
    ):
        with pytest.raises(C2spTlogTransportError) as exc_info:
            fetcher.fetch_bounded(url, 10)
        assert exc_info.value.transient is False


def test_builtin_fetcher_rejects_unsafe_destination_as_non_transient() -> None:
    fetcher = SafeC2spResourceFetcher()
    with patch(
        "dnsid.safe_transport._resolve_addresses",
        return_value=["169.254.169.254"],
    ):
        with pytest.raises(C2spTlogTransportError) as exc_info:
            fetcher.fetch_bounded("https://metadata.example/resource", 10)
    assert exc_info.value.transient is False
    assert SSRF_BLOCK_MARKER in str(exc_info.value.__cause__)
    fetcher.close()


def test_ssrf_blocking_connect_error_is_non_transient() -> None:
    class BlockedFetcher:
        def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
            raise httpx.ConnectError(f"{SSRF_BLOCK_MARKER}: private destination")

        def security_guarantees(self) -> C2spResourceFetchGuarantees:
            return C2spResourceFetchGuarantees(True, True, True, True, True)

    with pytest.raises(C2spTlogTransportError) as exc_info:
        fetch_bounded_bytes(BlockedFetcher(), _URL, 10)
    assert exc_info.value.transient is False
    assert isinstance(exc_info.value.__cause__, httpx.ConnectError)


def test_safe_fetcher_applies_transport_config_with_exact_loopback_exception() -> None:
    config = TransportConfig(
        dns_server="127.0.0.1:5353",
        ca_bundle_path="/tmp/ca.pem",
        private_address_hosts=frozenset({"private.example"}),
    )
    transport = MagicMock(spec=httpx.BaseTransport)
    with patch(
        "dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_transport",
        return_value=transport,
    ) as make_transport:
        fetcher = SafeC2spResourceFetcher(
            transport_config=config,
            allow_loopback_host="registry.test.dnsid.test",
        )

    safe_config = make_transport.call_args.args[0]
    assert safe_config.dns_server == config.dns_server
    assert safe_config.ca_bundle_path == config.ca_bundle_path
    assert safe_config.private_address_hosts == frozenset()
    assert make_transport.call_args.kwargs["allow_loopback_host"] == (
        "registry.test.dnsid.test"
    )
    fetcher.close()


def test_safe_fetcher_declares_all_required_capabilities_and_finite_timeout() -> None:
    fetcher = SafeC2spResourceFetcher(timeout_seconds=2.5)
    guarantees = fetcher.security_guarantees()

    assert all(
        getattr(guarantees, field)
        for field in C2spResourceFetchGuarantees.__dataclass_fields__
    )
    assert fetcher._client.timeout.connect == 2.5
    assert fetcher._client.follow_redirects is False
    fetcher.close()
