"""HTTPX transports for fail-closed negotiated response authentication.

Only built-in non-replaying transports are accepted. Base-client authentication,
redirect handling, hooks, mounts, and caches are not used in this mode.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import httpx

from ._bounded_response import ACCEPT_ENCODING, BoundedBody
from ._https_client import _extract_tls_cert
from ._verification_budget import (
    async_run_blocking,
    async_verification_operation,
    bounded_http_timeout,
    remaining_seconds,
    verification_operation,
)
from .exceptions import ArgumentError
from .http_signatures import (
    _MAX_BODY,
    HttpSignatureProfile,
    _check_message_limits,
    _require_https,
    _response_error,
    _response_policy,
)
from .models import HttpRequest, HttpSigningOptions
from .safe_transport import _AsyncHttpcoreTransport, _HttpcoreTransport


def _validate_transport(transport: object) -> None:
    if type(transport) is httpx.MockTransport:
        return
    if type(transport) not in {
        httpx.HTTPTransport, httpx.AsyncHTTPTransport, _HttpcoreTransport, _AsyncHttpcoreTransport,
    } or getattr(getattr(transport, "_pool", None), "_retries", None) != 0:
        raise ArgumentError(
            "negotiated responses require a supported transport with retries disabled",
        )


def _snapshot_options(opts: HttpSigningOptions) -> HttpSigningOptions:
    snapshot = deepcopy(opts)
    assert snapshot.response_signature is not None
    snapshot.response_signature = _response_policy(snapshot.response_signature)
    return snapshot


def _request_snapshot(request: httpx.Request) -> HttpRequest:
    snapshot = HttpRequest(request.method, str(request.url), dict(request.headers))
    _require_https(snapshot)
    if snapshot.has_header("accept-signature"):
        raise ArgumentError("Accept-Signature is already present")
    return snapshot


def _append(body: bytearray, chunk: bytes) -> None:
    remaining_seconds()
    if len(body) + len(chunk) > _MAX_BODY:
        raise _response_error("negotiated HTTP content exceeds 8 MiB")
    body.extend(chunk)


def _outgoing(
    profile: HttpSignatureProfile, request: httpx.Request, saved: HttpRequest,
    body: bytes, opts: HttpSigningOptions,
) -> tuple[httpx.Request, HttpRequest]:
    supplied = bool(body) or bool(request.extensions.get(
        "dnsid.content_supplied", type(request.stream) is not httpx.ByteStream,
    ))
    saved.body = body if supplied else None
    profile.create_signed_http_request(saved, opts)
    extensions = {**request.extensions, "timeout": bounded_http_timeout(
        httpx.Timeout(**request.extensions.get("timeout", {}))
        if request.extensions.get("timeout") else None,
    ).as_dict()}
    outgoing = httpx.Request(saved.method, saved.url, headers=saved.headers,
                             content=body, extensions=extensions)
    # The transport receives a separate object; its mutations cannot change verification context.
    return outgoing, deepcopy(saved)


def _buffered_content(response: httpx.Response, *, no_content: bool) -> bytes | None:
    if response.is_stream_consumed:
        if (not no_content
                and response.headers.get("content-encoding", "identity").lower() != "identity"):
            raise _response_error("transport decoded response content before authentication")
        try:
            content = response.content
        except httpx.ResponseNotRead as exc:
            raise _response_error("response content is unavailable") from exc
        if len(content) > _MAX_BODY:
            raise _response_error("negotiated response content exceeds 8 MiB")
        return content
    return None


def _response_message(response: httpx.Response, content: bytes) -> HttpRequest:
    return HttpRequest("", "", dict(response.headers), content, status=response.status_code)


def _restore(response: httpx.Response, content: bytes, *, no_content: bool) -> None:
    if no_content:
        response._content = b""
    elif not hasattr(response, "_content"):
        # Decode only authenticated raw bytes, with the existing bounded decoder.
        undecoded = httpx.Response(200, headers=response.headers, stream=httpx.ByteStream(content))
        reader = BoundedBody(
            undecoded, _MAX_BODY,
            lambda: _response_error("decoded negotiated response content exceeds 8 MiB"),
            invalid=_response_error,
        )
        for offset in range(0, len(content), 65536):
            reader.append(content[offset:offset + 65536])
        response._content = reader.finish()


def signed_client(
    profile: HttpSignatureProfile, base: httpx.Client, opts: HttpSigningOptions,
) -> httpx.Client:
    """Create a synchronous client without taking ownership of the base transport."""
    policy = _snapshot_options(opts)
    inner = base._transport
    _validate_transport(inner)

    class Transport(httpx.BaseTransport):
        @verification_operation
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            response: httpx.Response | None = None
            try:
                saved = _request_snapshot(request)
                invocation = deepcopy(policy)
                body = bytearray()
                assert isinstance(request.stream, httpx.SyncByteStream)
                for chunk in request.stream:
                    _append(body, chunk)
                outgoing, saved = _outgoing(profile, request, saved, bytes(body), invocation)
                _validate_transport(inner)
                response = inner.handle_request(outgoing)
                peer = _extract_tls_cert(response)
                _check_message_limits(_response_message(response, b""))
                no_content = saved.method == "HEAD" or response.status_code in {204, 304}
                content = _buffered_content(response, no_content=no_content)
                if content is None:
                    body = bytearray()
                    for chunk in response.iter_raw():
                        _append(body, chunk)
                    content = bytes(body)
                assert invocation.response_signature is not None
                profile.verify_signed_http_response(
                    saved, _response_message(response, content), invocation.response_signature,
                    peer_cert=peer,
                )
                _restore(response, content, no_content=no_content)
                remaining_seconds()
                return response
            except BaseException:
                if response is not None:
                    response.close()
                raise
            finally:
                assert isinstance(request.stream, httpx.SyncByteStream)
                request.stream.close()

    class Client(httpx.Client):
        def build_request(self, method: str, url: Any, **kwargs: Any) -> httpx.Request:
            request = super().build_request(method, url, **kwargs)
            request.extensions["dnsid.content_supplied"] = any(
                kwargs.get(name) is not None for name in ("content", "data", "files", "json")
            )
            return request

        def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
            # Disable HTTPX auth resends and redirects even when per-send settings ask for them.
            kwargs.update(auth=None, follow_redirects=False)
            return super().send(request, **kwargs)

    return Client(transport=Transport(), headers={"accept-encoding": ACCEPT_ENCODING})


def signed_async_client(
    profile: HttpSignatureProfile, inner: httpx.AsyncBaseTransport,
    opts: HttpSigningOptions, headers: dict[str, str] | None,
) -> httpx.AsyncClient:
    """Create an asynchronous client that owns the accepted transport."""
    policy = _snapshot_options(opts)
    _validate_transport(inner)

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return await self._handle(request)

        @async_verification_operation
        async def _handle(self, request: httpx.Request) -> httpx.Response:
            response: httpx.Response | None = None
            try:
                saved = _request_snapshot(request)
                invocation = deepcopy(policy)
                body = bytearray()
                assert isinstance(request.stream, httpx.AsyncByteStream)
                async for chunk in request.stream:
                    _append(body, chunk)
                outgoing, saved = await async_run_blocking(
                    _outgoing, profile, request, saved, bytes(body), invocation,
                )
                _validate_transport(inner)
                response = await inner.handle_async_request(outgoing)
                peer = _extract_tls_cert(response)
                _check_message_limits(_response_message(response, b""))
                no_content = saved.method == "HEAD" or response.status_code in {204, 304}
                content = _buffered_content(response, no_content=no_content)
                if content is None:
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        _append(body, chunk)
                    content = bytes(body)
                assert invocation.response_signature is not None
                await profile.async_verify_signed_http_response(
                    saved, _response_message(response, content), invocation.response_signature,
                    peer_cert=peer,
                )
                _restore(response, content, no_content=no_content)
                remaining_seconds()
                return response
            except BaseException:
                if response is not None:
                    await response.aclose()
                raise
            finally:
                assert isinstance(request.stream, httpx.AsyncByteStream)
                await request.stream.aclose()

        async def aclose(self) -> None:
            await inner.aclose()

    class Client(httpx.AsyncClient):
        def build_request(self, method: str, url: Any, **kwargs: Any) -> httpx.Request:
            request = super().build_request(method, url, **kwargs)
            request.extensions["dnsid.content_supplied"] = any(
                kwargs.get(name) is not None for name in ("content", "data", "files", "json")
            )
            return request

        async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
            kwargs.update(auth=None, follow_redirects=False)
            return await super().send(request, **kwargs)

    return Client(
        headers={"accept-encoding": ACCEPT_ENCODING, **(headers or {})}, transport=Transport(),
    )
