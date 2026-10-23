"""Native C2SP resource reads retain the bounded public transport contract."""

import asyncio
import gzip
from contextlib import AsyncExitStack
from unittest.mock import patch

import httpx
import pytest
import pytest_asyncio

from dnsid import VerificationCode, VerificationError, verification_budget
from dnsid.c2sp_tlog import C2spTlogTransportError, SafeC2spResourceFetcher
from dnsid.c2sp_tlog.resource_fetcher import async_fetch_bounded_bytes
from tests.test_async_https_client import _Chunks

_URL = "https://log.example/checkpoint"


@pytest_asyncio.fixture
async def make_fetcher():
    async with AsyncExitStack() as stack:
        async def make(**kwargs):
            return await stack.enter_async_context(SafeC2spResourceFetcher(**kwargs))
        yield make


@pytest.mark.asyncio
@pytest.mark.parametrize("status,transient", [(200, None), (204, False), (302, False), (404, False), (503, True)])
async def test_status_and_redirect_parity(make_fetcher, status, transient):
    fetcher = await make_fetcher()
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(status, content=b"ok", headers={"location": _URL + "/other"})

    with patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport",
               return_value=httpx.MockTransport(handle)):
        if transient is None:
            assert await fetcher.async_fetch_bounded(_URL, 2) == b"ok"
        else:
            with pytest.raises(C2spTlogTransportError) as error:
                await fetcher.async_fetch_bounded(_URL, 2)
            assert error.value.transient is transient
            assert error.value.status_code == (None if status == 302 else status)
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("overflow", [False, True])
async def test_decoded_limit_and_owned_resource_cleanup(make_fetcher, compressed, overflow):
    fetcher = await make_fetcher()
    body = b"a" * 4096
    stream = _Chunks([gzip.compress(body + b"x" * overflow)] if compressed else [body, b"x"][:1 + overflow])
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, stream=stream, headers={"content-encoding": "gzip"} if compressed else {},
    ))
    with (
        patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport", return_value=transport),
        patch.object(transport, "aclose", wraps=transport.aclose) as close,
        patch.object(asyncio.get_running_loop(), "run_in_executor", side_effect=AssertionError("worker")),
    ):
        if overflow:
            with pytest.raises(C2spTlogTransportError, match="byte maximum"):
                await fetcher.async_fetch_bounded(_URL, len(body))
        else:
            assert await fetcher.async_fetch_bounded(_URL, len(body)) == body
        close.assert_not_awaited()
        assert not fetcher._client.is_closed
        await fetcher.aclose()
        close.assert_awaited_once()
    assert stream.closed


@pytest.mark.asyncio
async def test_declared_limit_rejects_before_reading(make_fetcher):
    fetcher = await make_fetcher()
    stream = _Chunks([b"unread"])
    with (
        patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport",
              return_value=httpx.MockTransport(lambda request: httpx.Response(
                  200, headers={"content-length": "100"}, stream=stream,
              ))),
    ):
        with pytest.raises(C2spTlogTransportError, match="byte maximum"):
            await fetcher.async_fetch_bounded(_URL, 10)
    assert stream.yielded == 0
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["http://log.example", "https://u:p@log.example", _URL + "#fragment"])
async def test_invalid_urls_fail_before_async_transport_creation(make_fetcher, url):
    fetcher = await make_fetcher()
    with patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport") as make:
        with pytest.raises(C2spTlogTransportError):
            await fetcher.async_fetch_bounded(url, 10)
        make.assert_not_called()


@pytest.mark.asyncio
async def test_ssrf_rejection_is_non_transient(make_fetcher):
    fetcher = await make_fetcher()
    with pytest.raises(C2spTlogTransportError) as error:
        await fetcher.async_fetch_bounded("https://127.0.0.1/checkpoint", 10)
    assert error.value.transient is False


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["cancel", "request-timeout", "budget"])
async def test_interrupted_reads_close_responses_and_pool_at_shutdown(make_fetcher, mode):
    fetcher = await make_fetcher(timeout_seconds=0.02 if mode == "request-timeout" else 10)
    started = asyncio.Event()

    class Slow(_Chunks):
        async def __aiter__(self):
            started.set()
            await asyncio.sleep(10)
            yield b"ok"

    stream = Slow([])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    with (
        patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport", return_value=transport),
        patch.object(transport, "aclose", wraps=transport.aclose) as close,
    ):
        if mode == "cancel":
            task = asyncio.create_task(fetcher.async_fetch_bounded(_URL, 10))
            await asyncio.wait_for(started.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif mode == "budget":
            with pytest.raises(VerificationError) as error:
                with verification_budget(0.02):
                    await async_fetch_bounded_bytes(fetcher, _URL, 10)
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        else:
            with pytest.raises(C2spTlogTransportError) as error:
                await fetcher.async_fetch_bounded(_URL, 10)
            assert error.value.transient is True
        assert stream.closed
        close.assert_not_awaited()
        await fetcher.aclose()
        close.assert_awaited_once()
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,transient", [
    (httpx.ConnectError("dnsid-ssrf-blocked: denied"), False),
    (httpx.ConnectError("TLS unavailable"), True),
    (httpx.ReadTimeout("timed out"), True),
    (httpx.ReadError("connection lost"), True),
    (httpx.TooManyRedirects("redirects"), False),
])
async def test_network_error_taxonomy(make_fetcher, failure, transient):
    fetcher = await make_fetcher()
    def handle(request):
        raise failure

    with patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport",
               return_value=httpx.MockTransport(handle)):
        with pytest.raises(C2spTlogTransportError) as error:
            await fetcher.async_fetch_bounded(_URL, 10)
    assert error.value.transient is transient


@pytest.mark.asyncio
@pytest.mark.parametrize("response", ["not bytes", b"too long"])
async def test_injected_async_fetcher_results_are_checked(response):
    class Fetcher:
        def fetch_bounded(self, *args):
            raise AssertionError("unexpected sync fetch")

        async def async_fetch_bounded(self, *args):
            return response

    with pytest.raises(C2spTlogTransportError):
        await async_fetch_bounded_bytes(Fetcher(), _URL, 2)
