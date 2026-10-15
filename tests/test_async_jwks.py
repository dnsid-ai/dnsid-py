"""Native async key-set reads preserve HTTPS policy, bounds and TLS evidence."""

import asyncio
import gzip
from unittest.mock import patch

import httpx
import pytest

from dnsid import verification_budget
from dnsid._https_client import _MAX_JWKS_BODY_BYTES, async_fetch_jwks, fetch_jwks
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.safe_transport import SSRF_BLOCK_MARKER
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
@pytest.mark.parametrize("url", [
    "http://agent.test/jwks", "https://user:pass@agent.test/jwks",
    "https://agent.test/jwks#fragment", "https://agent.test:bad/jwks",
])
async def test_invalid_initial_url_never_fetches(url):
    transport = httpx.MockTransport(lambda request: pytest.fail("unexpected fetch"))
    with pytest.raises(VerificationError) as error:
        await async_fetch_jwks(url, "agent.test", transport=transport)
    assert error.value.code == VerificationCode.TLS_ERROR


@pytest.mark.asyncio
@pytest.mark.parametrize("overflow", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
async def test_decoded_body_limits_close_responses(overflow, compressed):
    body = b'{"keys":[]}'
    body += b" " * (_MAX_JWKS_BODY_BYTES - len(body))
    if compressed:
        stream = _Chunks([gzip.compress(body + (b"x" if overflow else b""))])
    else:
        stream = _Chunks([body, b"x", b"unread"] if overflow else [body])
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, stream=stream, headers={"content-encoding": "gzip"} if compressed else {},
    ))
    if overflow:
        with pytest.raises(VerificationError, match="too large") as error:
            await async_fetch_jwks(_URL, "agent.test", transport=transport)
        assert error.value.code == VerificationCode.RECORD_INVALID
        if not compressed:
            assert stream.yielded == 2
    else:
        assert (await async_fetch_jwks(_URL, "agent.test", transport=transport))[0].keys == []
    assert stream.closed


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
@pytest.mark.parametrize("exception,code,transient", [
    (httpx.ConnectError(SSRF_BLOCK_MARKER), VerificationCode.TLS_ERROR, False),
    (httpx.ConnectError("connection refused"), VerificationCode.TLS_ERROR, True),
    (httpx.ReadTimeout("timeout"), VerificationCode.DNS_RESOLUTION, True),
])
async def test_transport_error_taxonomy(exception, code, transient):
    def handle(request):
        raise exception

    with pytest.raises(VerificationError) as error:
        await async_fetch_jwks(_URL, "agent.test", transport=httpx.MockTransport(handle))
    assert error.value.code == code
    assert error.value.transient is transient


@pytest.mark.asyncio
async def test_default_transport_enforces_ssrf_policy():
    with pytest.raises(VerificationError) as error:
        await async_fetch_jwks("https://127.0.0.1/jwks", "127.0.0.1")
    assert error.value.code == VerificationCode.TLS_ERROR
    assert error.value.transient is False


@pytest.mark.asyncio
async def test_redirect_limit_and_caller_owned_client():
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "/again"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), follow_redirects=True) as client:
        with pytest.raises(VerificationError, match="Too many redirects"):
            await async_fetch_jwks(_URL, "agent.test", client=client)
        assert len(requests) == 6
        assert not client.is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_interrupted_read_closes_response_and_owned_client(cancel):
    started = asyncio.Event()

    class Slow(_Chunks):
        async def __aiter__(self):
            yield b'{"keys":'
            started.set()
            await asyncio.sleep(10)

    stream = Slow([])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    with patch.object(transport, "aclose", wraps=transport.aclose) as close:
        if cancel:
            call = asyncio.create_task(async_fetch_jwks(_URL, "agent.test", transport=transport))
            await asyncio.wait_for(started.wait(), 2)
            call.cancel()
            with pytest.raises(asyncio.CancelledError):
                await call
        else:
            with pytest.raises(VerificationError) as error:
                with verification_budget(0.02):
                    await async_fetch_jwks(_URL, "agent.test", transport=transport)
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        close.assert_awaited_once()
    assert stream.closed
