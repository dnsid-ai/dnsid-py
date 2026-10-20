"""Native async key-set reads preserve HTTPS policy, bounds and TLS evidence."""

import asyncio
from unittest.mock import patch

import httpx
import pytest

from dnsid._https_client import async_fetch_jwks, fetch_jwks
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from tests.test_async_https_client import _Chunks
from tests.test_https_client import _FakeSSLObject, _FakeStream, _self_signed_der

_URL = "https://agent.test/jwks"


@pytest.mark.asyncio
async def test_jwks_parsing_and_peer_certificate_match_sync(ec_pair, ed_pair):
    document = {"keys": [ec_pair[1].to_dict(), ed_pair[1].to_dict()]}
    der, expiry = _self_signed_der("agent.test")

    def handle(request):
        return httpx.Response(200, json=document, extensions={
            "network_stream": _FakeStream(_FakeSSLObject(der)),
        })

    expected = fetch_jwks(_URL, "agent.test", transport=httpx.MockTransport(handle))
    with patch.object(asyncio.get_running_loop(), "run_in_executor",
                      side_effect=AssertionError("unexpected worker")):
        result = await async_fetch_jwks(_URL, "agent.test", transport=httpx.MockTransport(handle))
    assert result == expected
    assert result[0].to_dict() == document
    assert result[1].der == der
    assert result[1].not_after == expiry
    assert result[1].san_dns_names == ["agent.test"]


@pytest.mark.asyncio
@pytest.mark.parametrize("domain_boundary,location,accepted", [
    (False, "/new?version=2", True),
    (False, "https://agent.test/new", True),
    (False, "https://keys.agent.test/new", False),
    (True, "https://keys.agent.test/new", True),
    (True, "https://other.test/new", False),
    (True, "https://evilagent.test/new", False),
    (True, "https://agent.test.evil.test/new", False),
    (True, "http://agent.test/new", False),
    (True, "https://user:pass@agent.test/new", False),
    (True, "https://agent.test/new#fragment", False),
])
async def test_redirect_boundaries_and_response_cleanup(domain_boundary, location, accepted):
    requests = []
    redirect = _Chunks([b"ignored"])

    def handle(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(302, headers={"location": location}, stream=redirect)
        return httpx.Response(200, json={"keys": []})

    transport = httpx.MockTransport(handle)
    with patch.object(transport, "aclose", wraps=transport.aclose) as close:
        if accepted:
            result, _ = await async_fetch_jwks(
                _URL, "agent.test", domain_boundary=domain_boundary, transport=transport,
            )
            assert result.keys == []
            assert len(requests) == 2
        else:
            with pytest.raises(VerificationError) as error:
                await async_fetch_jwks(
                    _URL, "agent.test", domain_boundary=domain_boundary, transport=transport,
                )
            assert error.value.code == VerificationCode.TLS_ERROR
            assert len(requests) == 1
        close.assert_awaited_once()
    assert redirect.closed
    assert redirect.yielded == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body,code", [
    (201, b"{}", VerificationCode.TLS_ERROR),
    (204, b"", VerificationCode.TLS_ERROR),
    (206, b"{}", VerificationCode.TLS_ERROR),
    (503, b"{}", VerificationCode.TLS_ERROR),
    (200, b"invalid json", VerificationCode.RECORD_INVALID),
    (200, b"[]", VerificationCode.RECORD_INVALID),
    (200, b'{"keys":null}', VerificationCode.RECORD_INVALID),
    (200, b'{"keys":[null]}', VerificationCode.RECORD_INVALID),
])
async def test_response_error_taxonomy_matches_sync(status, body, code):
    def handle(request):
        return httpx.Response(status, content=body)

    with pytest.raises(VerificationError) as sync:
        fetch_jwks(_URL, "agent.test", transport=httpx.MockTransport(handle))
    with pytest.raises(VerificationError) as native:
        await async_fetch_jwks(_URL, "agent.test", transport=httpx.MockTransport(handle))
    assert native.value.code == sync.value.code == code
    assert native.value.transient == sync.value.transient


@pytest.mark.asyncio
async def test_default_transport_enforces_ssrf_policy():
    with pytest.raises(VerificationError) as error:
        await async_fetch_jwks("https://127.0.0.1/jwks", "127.0.0.1")
    assert error.value.code == VerificationCode.TLS_ERROR
    assert error.value.transient is False
