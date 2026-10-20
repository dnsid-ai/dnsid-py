"""Async HTTPS reads retain strict policy, bounds, deadlines and ownership."""

import asyncio
import gzip
from unittest.mock import patch

import httpx
import pytest

from dnsid import verification_budget
from dnsid._https_client import (
    _MAX_JWKS_BODY_BYTES,
    _MAX_STATUS_BODY_BYTES,
    async_fetch_agent_status,
    async_fetch_jwks,
    fetch_agent_status,
)
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.safe_transport import SSRF_BLOCK_MARKER


async def _fetch(kind, url="https://agent.test/data", **kwargs):
    if kind == "jwks":
        return await async_fetch_jwks(url, "agent.test", **kwargs)
    return await async_fetch_agent_status(url, **kwargs)


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
@pytest.mark.parametrize("kind", ["status", "jwks"])
@pytest.mark.parametrize("url", [
    "http://agent.test/status", "https://user:pass@agent.test/status",
    "https://agent.test/status#fragment", "https://agent.test:bad/status",
])
async def test_invalid_initial_url_never_fetches(kind, url):
    transport = httpx.MockTransport(lambda request: pytest.fail("unexpected fetch"))
    with pytest.raises(VerificationError) as error:
        await _fetch(kind, url, transport=transport)
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
@pytest.mark.parametrize("kind", ["status", "jwks"])
@pytest.mark.parametrize("overflow", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
async def test_limits_apply_to_decoded_bytes_and_close_responses(kind, overflow, compressed):
    body = b'{"keys":[],"state":"ACTIVE"}'
    limit = _MAX_JWKS_BODY_BYTES if kind == "jwks" else _MAX_STATUS_BODY_BYTES
    body += b" " * (limit - len(body))
    if compressed:
        stream = _Chunks([gzip.compress(body + (b"x" if overflow else b""))])
    else:
        stream = _Chunks([body, b"x", b"unread"] if overflow else [body])
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, stream=stream, headers={"content-encoding": "gzip"} if compressed else {}
    ))
    if overflow:
        with pytest.raises(VerificationError, match="too large") as error:
            await _fetch(kind, transport=transport)
        assert error.value.code == (
            VerificationCode.RECORD_INVALID if kind == "jwks" else VerificationCode.STATUS_NOT_ACTIVE
        )
        if not compressed:
            assert stream.yielded == 2
    else:
        result = await _fetch(kind, transport=transport)
        assert result[0].keys == [] if kind == "jwks" else result.state == "ACTIVE"
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
@pytest.mark.parametrize("kind", ["status", "jwks"])
@pytest.mark.parametrize("exception,code,transient", [
    (httpx.ConnectError(SSRF_BLOCK_MARKER), VerificationCode.TLS_ERROR, False),
    (httpx.ConnectError("connection refused"), VerificationCode.TLS_ERROR, True),
    (httpx.ReadTimeout("timeout"), VerificationCode.DNS_RESOLUTION, True),
])
async def test_transport_error_taxonomy(kind, exception, code, transient):
    async def handle(request):
        raise exception

    with pytest.raises(VerificationError) as error:
        await _fetch(kind, transport=httpx.MockTransport(handle))
    assert error.value.code == code
    assert error.value.transient is transient


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["status", "jwks"])
async def test_redirect_limit_and_caller_owned_client(kind):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "/again"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), follow_redirects=True) as client:
        with pytest.raises(VerificationError, match="Too many redirects"):
            await _fetch(kind, client=client)
        assert len(requests) == 6
        assert not client.is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["status", "jwks"])
@pytest.mark.parametrize("cancel", [False, True])
async def test_interrupted_read_closes_response_and_owned_client(kind, cancel):
    started = asyncio.Event()

    class Slow(_Chunks):
        async def __aiter__(self):
            yield b'{"keys":[],"state":'
            started.set()
            await asyncio.sleep(10)

    stream = Slow([])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    with patch.object(transport, "aclose", wraps=transport.aclose) as close:
        if cancel:
            call = asyncio.create_task(_fetch(kind, transport=transport))
            await asyncio.wait_for(started.wait(), 2)
            call.cancel()
            with pytest.raises(asyncio.CancelledError):
                await call
        else:
            with pytest.raises(VerificationError) as error:
                with verification_budget(0.02):
                    await _fetch(kind, transport=transport)
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        close.assert_awaited_once()
    assert stream.closed
