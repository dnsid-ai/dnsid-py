"""ASGI middleware that signs negotiated responses before any header is sent."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, MutableMapping
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from .http_signatures import _MAX_BODY, _NO_CONTENT_STATUSES
from .models import HttpRequest

if TYPE_CHECKING:
    from .http_signatures import HttpSignatureProfile

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# Fields that sign_requested_http_response sets; all other response fields pass through as sent.
_SIGNED_FIELDS = ("content-digest", "cache-control", "signature-input", "signature")


def _combined(raw: list[tuple[bytes, bytes]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in raw:
        key, text = name.decode("latin-1").lower(), value.decode("latin-1")
        headers[key] = f"{headers[key]}, {text}" if key in headers else text
    return headers


def _request(scope: Scope) -> HttpRequest:
    headers = _combined(list(scope.get("headers", [])))
    host = headers.get("host")
    if not host and scope.get("server"):
        server_host, port = scope["server"]
        host = f"{server_host}:{port}" if port else server_host
    path = scope.get("raw_path") or quote(scope.get("path", "/")).encode()
    target = path.decode("latin-1")
    if scope.get("query_string"):
        target += "?" + scope["query_string"].decode("latin-1")
    url = f"{scope.get('scheme', 'http')}://{host}{target}"
    return HttpRequest(scope["method"], url, headers)


class ResponseSigningMiddleware:
    """Sign responses for requests that carry Accept-Signature.

    Requests without negotiation pass through unbuffered. Negotiated responses
    are buffered up to 8 MiB and signed before any header is sent. On a signing
    failure or an exceeded bound, the middleware sends a 500 without the
    application's headers or content; it never sends the unsigned response.
    Place it after request verification and authorization, and outside any
    middleware that changes the status, covered headers, or content coding.
    The request URL uses the ASGI scope scheme and Host header: behind a
    TLS-terminating proxy, apply trusted proxy-header handling first.
    """

    def __init__(self, app: ASGIApp, profile: HttpSignatureProfile) -> None:
        self.app = app
        self.profile = profile

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not any(
            name.lower() == b"accept-signature" for name, _ in scope.get("headers", [])
        ):
            await self.app(scope, receive, send)
            return
        start: Message | None = None
        body = bytearray()
        overflow = False

        async def buffer(message: Message) -> None:
            nonlocal start, overflow
            if message["type"] == "http.response.start":
                start = message
            elif message["type"] == "http.response.body":
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > _MAX_BODY:
                    overflow = True
                else:
                    body.extend(chunk)

        await self.app(scope, receive, buffer)
        if start is None or overflow:
            await self._fail(send)
            return
        raw = list(start.get("headers", []))
        request = _request(scope)
        response = HttpRequest("", "", _combined(raw), bytes(body), status=start["status"])
        try:
            signed = await asyncio.to_thread(
                self.profile.sign_requested_http_response, request, response,
            )
        except Exception:  # noqa: BLE001 - every failure must replace the unsigned response.
            await self._fail(send)
            return
        headers = [(k, v) for k, v in raw if k.decode("latin-1").lower() not in _SIGNED_FIELDS]
        headers += [
            (name.encode(), signed.get_header(name).encode("latin-1"))
            for name in _SIGNED_FIELDS if signed.has_header(name)
        ]
        await send({"type": "http.response.start", "status": start["status"], "headers": headers})
        empty = request.method.upper() == "HEAD" or start["status"] in _NO_CONTENT_STATUSES
        await send({"type": "http.response.body", "body": b"" if empty else bytes(body)})

    @staticmethod
    async def _fail(send: Send) -> None:
        await send({
            "type": "http.response.start", "status": 500, "headers": [(b"content-length", b"0")],
        })
        await send({"type": "http.response.body", "body": b""})
