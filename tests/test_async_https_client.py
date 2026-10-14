"""Async status reads retain strict HTTPS, bounds, deadlines and ownership."""

import asyncio
import gzip
from unittest.mock import patch

import httpx
import pytest

from dnsid import verification_budget
from dnsid._https_client import (
    _MAX_STATUS_BODY_BYTES,
    async_fetch_agent_status,
    fetch_agent_status,
)
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.safe_transport import SSRF_BLOCK_MARKER


@pytest.mark.asyncio
@pytest.mark.parametrize("document", [
    {"state": "ACTIVE", "lastTransitionAt": "2026-10-14T00:00:00Z"},
    {"protocolStatus": {"state": "REVOKED", "revocationReason": "keyCompromise"}},
    {}, [], {"state": False},
])
async def test_status_parsing_matches_sync(document):
    sync = fetch_agent_status("https://agent.test/status", transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=document)
    ))
    native = await async_fetch_agent_status("https://agent.test/status", transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=document)
    ))
    assert native == sync


@pytest.mark.asyncio
@pytest.mark.parametrize("location", [
    "/new?version=2", "https://other.test/status", "http://agent.test/status",
    "https://user:pass@agent.test/status", "https://agent.test/status#fragment",
    "https://127.0.0.1/status",
])
async def test_redirect_rules_and_connection_cleanup(location):
    requests = []

    async def handle(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(200, json={"state": "ACTIVE"})

    transport = httpx.MockTransport(handle)
    with patch.object(transport, "aclose", wraps=transport.aclose) as close:
        if location.startswith("/") or location == "https://other.test/status":
            assert (await async_fetch_agent_status(
                "https://agent.test/status", transport=transport
            )).state == "ACTIVE"
            assert len(requests) == 2
        elif location.startswith("https://127."):
            # URL parsing permits literals; the real transport enforces their address policy.
            with pytest.raises(VerificationError) as error:
                await async_fetch_agent_status("https://127.0.0.1/status")
            assert error.value.code == VerificationCode.TLS_ERROR
            return
        else:
            with pytest.raises(VerificationError) as error:
                await async_fetch_agent_status("https://agent.test/status", transport=transport)
            assert error.value.code == VerificationCode.TLS_ERROR
            assert len(requests) == 1
        close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://agent.test/status", "https://user:pass@agent.test/status",
    "https://agent.test/status#fragment", "https://agent.test:bad/status",
])
async def test_invalid_initial_url_never_fetches(url):
    transport = httpx.MockTransport(lambda request: pytest.fail("unexpected fetch"))
    with pytest.raises(VerificationError) as error:
        await async_fetch_agent_status(url, transport=transport)
    assert error.value.code == VerificationCode.TLS_ERROR


class _Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("overflow", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
async def test_limits_apply_to_decoded_bytes_and_close_responses(overflow, compressed):
    body = b'{"state":"ACTIVE"}'
    body += b" " * (_MAX_STATUS_BODY_BYTES - len(body))
    if compressed:
        stream = _Chunks([gzip.compress(body + (b"x" if overflow else b""))])
    else:
        stream = _Chunks([body, b"x", b"unread"] if overflow else [body])
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, stream=stream, headers={"content-encoding": "gzip"} if compressed else {}
    ))
    if overflow:
        with pytest.raises(VerificationError, match="too large"):
            await async_fetch_agent_status("https://agent.test/status", transport=transport)
        if not compressed:
            assert stream.yielded == 2
    else:
        assert (await async_fetch_agent_status(
            "https://agent.test/status", transport=transport
        )).state == "ACTIVE"
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body,code,transient", [
    (201, b"{}", VerificationCode.STATUS_NOT_ACTIVE, False),
    (204, b"", VerificationCode.STATUS_NOT_ACTIVE, False),
    (206, b"{}", VerificationCode.STATUS_NOT_ACTIVE, False),
    (503, b"{}", VerificationCode.STATUS_NOT_ACTIVE, True),
    (200, b"invalid json", VerificationCode.STATUS_NOT_ACTIVE, False),
])
async def test_response_error_taxonomy(status, body, code, transient):
    with pytest.raises(VerificationError) as error:
        await async_fetch_agent_status("https://agent.test/status", transport=httpx.MockTransport(
            lambda request: httpx.Response(status, content=body)
        ))
    assert error.value.code == code
    assert error.value.transient is transient


@pytest.mark.asyncio
@pytest.mark.parametrize("exception,code,transient", [
    (httpx.ConnectError(SSRF_BLOCK_MARKER), VerificationCode.TLS_ERROR, False),
    (httpx.ConnectError("connection refused"), VerificationCode.TLS_ERROR, True),
    (httpx.ReadTimeout("timeout"), VerificationCode.DNS_RESOLUTION, True),
])
async def test_transport_error_taxonomy(exception, code, transient):
    async def handle(request):
        raise exception

    with pytest.raises(VerificationError) as error:
        await async_fetch_agent_status("https://agent.test/status", transport=httpx.MockTransport(handle))
    assert error.value.code == code
    assert error.value.transient is transient


@pytest.mark.asyncio
async def test_redirect_limit_and_caller_owned_client():
    transport = httpx.MockTransport(lambda request: httpx.Response(302, headers={"location": "/again"}))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(VerificationError, match="Too many redirects"):
            await async_fetch_agent_status("https://agent.test/status", client=client)
        assert not client.is_closed


@pytest.mark.asyncio
async def test_slow_stream_respects_overall_deadline_and_closes():
    class Slow(_Chunks):
        async def __aiter__(self):
            yield b'{"state":'
            await asyncio.sleep(10)

    stream = Slow([])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    with patch.object(transport, "aclose", wraps=transport.aclose) as close:
        with pytest.raises(VerificationError, match="deadline"):
            with verification_budget(0.02):
                await async_fetch_agent_status("https://agent.test/status", transport=transport)
        close.assert_awaited_once()
    assert stream.closed
