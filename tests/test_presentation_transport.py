"""Credential conflicts and replay-stream cleanup at HTTP transport boundaries."""

import gc
import weakref
from unittest.mock import MagicMock

import httpx
import pytest

from dnsid import HttpRequest
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.http_signatures import HttpMessageSignatureConfig, _build_signature_base
from dnsid.models import SignatureParams
from dnsid.web_bot_auth import WebBotAuthProfile
from tests.test_http_signing import _build_profile


@pytest.mark.parametrize("headers", [
    [("Authorization", "Basic existing")], [("AUTHORIZATION", "Bearer existing")],
    [("authorization", "")], [("Authorization", "Basic one"), ("authorization", "Bearer two")],
])
@pytest.mark.parametrize("client_defaults", [None, False, True])
def test_bearer_conflicts_reject_before_token_or_network(monkeypatch, headers, client_defaults):
    profile = WebBotAuthProfile(resolver=MagicMock(), key_provider=None, domain="agent.example.com")
    profile.create_bot_token = MagicMock(return_value="token")
    inner = MagicMock()
    monkeypatch.setattr(httpx, "HTTPTransport", lambda: inner)
    if client_defaults is None:
        request = httpx.Request("POST", "https://target.example/", headers=headers, content=b"body")
        before = list(request.headers.raw)
        with pytest.raises(ArgumentError, match="Authorization"):
            profile.sign_bot_request(request)
        assert request.headers.raw == before
        assert request.content == b"body"
    else:
        with profile.create_signed_bot_client() as client:
            if client_defaults:
                client.headers = httpx.Headers(headers)
            with pytest.raises(ArgumentError, match="Authorization"):
                client.post("https://target.example/", headers=None if client_defaults else headers)
        inner.close.assert_called_once()
    profile.create_bot_token.assert_not_called()
    inner.handle_request.assert_not_called()


@pytest.mark.parametrize("field", ["max_age", "clock_skew"])
@pytest.mark.parametrize("value", [True, False, 5, "5", float("nan"), float("inf"), None])
def test_http_duration_types_are_argument_errors(field, value):
    with pytest.raises(ArgumentError):
        HttpMessageSignatureConfig(**{field: value})


@pytest.mark.parametrize("status", [None, True, 99, 600])
def test_response_status_must_be_available_and_valid(status):
    response = HttpRequest(method="GET", url="https://target.example/", status=status)
    origin = HttpRequest(method="GET", url=response.url)
    with pytest.raises(VerificationError):
        _build_signature_base(response, SignatureParams.parse('sig1=("@status")'), origin)


def test_response_status_without_request_context():
    response = HttpRequest(method="GET", url="https://target.example/", status=201)
    params = SignatureParams.parse('sig1=("@status")')
    assert _build_signature_base(response, params).startswith(b'"@status": 201\n')
    params.components = ["@method;req"]
    with pytest.raises(VerificationError, match="originating request"):
        _build_signature_base(response, params)
    params.components = ["@method"]
    with pytest.raises(VerificationError, match="requires req"):
        _build_signature_base(response, params)


@pytest.mark.parametrize("chunks", [[b"one", b"two"], []])
def test_sync_signing_replays_stream_and_retains_cleanup(ec_provider, chunks):
    stream = MagicMock(spec=httpx.SyncByteStream)
    stream.__iter__.side_effect = lambda: iter(chunks)
    captured = []

    def handle(request):
        captured.append(request)
        assert request.content == b"".join(chunks)
        assert request.headers.get("content-digest")
        assert request.headers["x-values"] == "one, two"
        request.stream.close()
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with _build_profile(ec_provider).create_signed_http_client(base) as client:
            original = httpx.Request("POST", "https://target.example/", stream=stream,
                                     headers=[("x-values", "one"), ("X-Values", "two")])
            client.send(original)
            assert original.stream is captured[0].stream
    stream.close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("chunks", [[b"one", b"two"], []])
async def test_async_signing_replays_stream_and_retains_cleanup(ec_provider, monkeypatch, chunks):
    close = MagicMock()

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in chunks:
                yield chunk

        async def aclose(self):
            close()

    async def handle(request):
        assert request.content == b"".join(chunks)
        assert request.headers.get("content-digest")
        assert request.headers["x-values"] == "one, two"
        await request.stream.aclose()
        return httpx.Response(200)

    monkeypatch.setattr("dnsid.manager._make_async_sdk_transport",
                        lambda config: httpx.MockTransport(handle))
    async with _build_profile(ec_provider).create_signed_async_http_client() as client:
        request = httpx.Request("POST", "https://target.example/", stream=Stream(),
                                headers=[("x-values", "one"), ("X-Values", "two")])
        await client.send(request)
    close.assert_called_once()


def test_repeated_sync_sends_release_old_replay_buffers(ec_provider):
    body = b"x" * (256 * 1024)
    stream = MagicMock(spec=httpx.SyncByteStream)
    stream.__iter__.side_effect = lambda: iter([body])
    references = []

    def handle(request):
        assert request.content == body
        return httpx.Response(200)

    profile = _build_profile(ec_provider)
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with profile.create_signed_http_client(base) as first, \
                profile.create_signed_http_client(base) as second:
            request = httpx.Request("POST", "https://target.example/", stream=stream)
            for index in range(20):
                assert (first if index % 2 else second).send(request).status_code == 200
                references.append(weakref.ref(request.stream))
                gc.collect()
                assert all(reference() is None for reference in references[:-1])
                assert references[-1]() is request.stream
                stream.close.assert_not_called()
            request.stream.close()
    stream.close.assert_called_once()


@pytest.mark.asyncio
async def test_repeated_async_sends_release_old_replay_buffers(ec_provider, monkeypatch):
    body = b"x" * (256 * 1024)
    close = MagicMock()
    references = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield body

        async def aclose(self):
            close()

    async def handle(request):
        assert request.content == body
        return httpx.Response(200)

    monkeypatch.setattr("dnsid.manager._make_async_sdk_transport",
                        lambda config: httpx.MockTransport(handle))
    profile = _build_profile(ec_provider)
    async with profile.create_signed_async_http_client() as first, \
            profile.create_signed_async_http_client() as second:
        request = httpx.Request("POST", "https://target.example/", stream=Stream())
        for index in range(20):
            response = await (first if index % 2 else second).send(request)
            assert response.status_code == 200
            del response
            references.append(weakref.ref(request.stream))
            gc.collect()
            assert all(reference() is None for reference in references[:-1])
            assert references[-1]() is request.stream
            close.assert_not_called()
        await request.stream.aclose()
    close.assert_called_once()


def test_signing_rejects_oversized_stream_and_closes_it(ec_provider):
    stream = MagicMock(spec=httpx.SyncByteStream)
    stream.__iter__.side_effect = lambda: iter([b"x" * (8 * 1024 * 1024), b"x"])
    network = MagicMock()
    with httpx.Client(transport=httpx.MockTransport(network)) as base:
        with _build_profile(ec_provider).create_signed_http_client(base) as client:
            request = httpx.Request("POST", "https://target.example/", stream=stream)
            with pytest.raises(ArgumentError, match="8 MiB"):
                client.send(request)
    network.assert_not_called()
    stream.close.assert_called_once()


def test_shared_builder_combines_header_lines_and_strips_outer_whitespace():
    request = HttpRequest(method="GET", url="https://target.example/",
                          headers={"X-Values": " one\t", "x-values": "two "})
    params = SignatureParams.parse('sig1=("x-values")')
    assert _build_signature_base(request, params).startswith(b'"x-values": one, two\n')


@pytest.mark.asyncio
async def test_async_signing_rejects_oversized_stream_and_closes_it(ec_provider, monkeypatch):
    close = MagicMock()
    network = MagicMock()

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * (8 * 1024 * 1024)
            yield b"x"

        async def aclose(self):
            close()

    monkeypatch.setattr("dnsid.manager._make_async_sdk_transport",
                        lambda config: httpx.MockTransport(network))
    async with _build_profile(ec_provider).create_signed_async_http_client() as client:
        request = httpx.Request("POST", "https://target.example/", stream=Stream())
        with pytest.raises(ArgumentError, match="8 MiB"):
            await client.send(request)
    network.assert_not_called()
    close.assert_called_once()
