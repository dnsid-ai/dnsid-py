"""Bounded, SSRF-resistant transport for C2SP verification resources."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from .._async_client_pool import _AsyncClientPool
from .._bounded_response import ACCEPT_ENCODING, BoundedBody
from .._verification_budget import (
    async_verification_operation,
    remaining_seconds,
    verification_operation,
)
from ..exceptions import ArgumentError, VerificationError
from ..models import TransportConfig
from ..safe_transport import (
    SSRF_BLOCK_MARKER,
    make_ssrf_safe_async_transport,
    make_ssrf_safe_transport,
)
from .errors import C2spTlogTransportError


@dataclass(frozen=True)
class C2spResourceFetchGuarantees:
    """Capabilities required for policy and public standard-resource reads."""

    https_only: bool
    rejects_redirects: bool
    validates_all_resolved_addresses: bool
    connects_to_validated_address: bool
    bounds_response_during_read: bool


class C2spBoundedResourceFetcher(Protocol):
    """Fetcher that enforces a decoded response limit during each read.

    Implementations also provide cancellation or finite request deadlines so a
    resource read cannot wait indefinitely.
    """

    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        """Fetch exactly *url* and return at most *max_bytes* decoded bytes."""
        ...

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        """Declare the public-read security capabilities enforced by the fetcher."""
        ...


class AsyncC2spBoundedResourceFetcher(C2spBoundedResourceFetcher, Protocol):
    """Optional native async capability of a synchronous bounded fetcher.

    Apply the same URL, decoded-byte, DNS/TLS and redirect guarantees. Honor the
    verification budget and close in-progress responses on cancellation. Injected
    resources remain caller-owned and must support concurrent calls on their
    supported event loops.
    """

    async def async_fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        """Fetch bounded decoded bytes, closing the response on cancellation."""
        ...


class SafeC2spResourceFetcher:
    """WebPKI fetcher with fixed deadlines, no redirects, and SSRF protection."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        transport_config: TransportConfig | None = None,
        allow_loopback_host: str | None = None,
    ) -> None:
        """Create a fetcher with a finite timeout and optional DNS/TLS configuration.

        Args:
            timeout_seconds: Finite timeout for each resource request.
            transport_config: Optional custom DNS server, additional CA bundle,
                and ``private_address_hosts`` allowlist, applied exactly as the
                core HTTPS fetcher does.
            allow_loopback_host: Exact hostname allowed to resolve to loopback for
                an explicitly configured local testnet.
        """
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ArgumentError("c2sp-tlog timeout_seconds must be a finite positive number")
        self._timeout_seconds = float(timeout_seconds)
        self._clock = time.monotonic
        self._transport_config = transport_config
        self._allow_loopback_host = allow_loopback_host
        self._client = httpx.Client(
            transport=make_ssrf_safe_transport(
                transport_config, allow_loopback_host=allow_loopback_host
            ),
            follow_redirects=False,
            timeout=self._timeout_seconds,
        )
        self._async_clients = _AsyncClientPool(lambda: httpx.AsyncClient(
            transport=make_ssrf_safe_async_transport(
                self._transport_config, allow_loopback_host=self._allow_loopback_host,
            ),
            follow_redirects=False, trust_env=False, timeout=self._timeout_seconds,
        ))

    @verification_operation
    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        """Fetch one HTTPS resource, requiring HTTP 200 and an exact byte bound."""
        _require_positive_integer(max_bytes, "max_bytes")
        _validate_resource_url(url)
        timeout = remaining_seconds(self._timeout_seconds)
        deadline = self._clock() + timeout
        try:
            with self._client.stream(
                "GET", url,
                headers={"Cache-Control": "no-cache", "Accept-Encoding": ACCEPT_ENCODING},
                timeout=timeout,
            ) as response:
                _validate_resource_response(response, url, max_bytes)
                body = BoundedBody(
                    response, max_bytes, lambda: _response_limit_error(url, max_bytes),
                    invalid=lambda detail: C2spTlogTransportError(detail, transient=False),
                )
                chunks = (response.iter_bytes() if response.is_stream_consumed
                          else response.iter_raw())
                for chunk in chunks:
                    remaining_seconds()
                    if self._clock() > deadline:
                        raise C2spTlogTransportError(
                            f"deadline exceeded fetching C2SP resource: {url}",
                            transient=True,
                        )
                    body.append(chunk)
                return body.finish()
        except C2spTlogTransportError:
            raise
        except httpx.ConnectError as exc:
            raise C2spTlogTransportError(
                f"failed to connect while fetching C2SP resource: {url}",
                transient=SSRF_BLOCK_MARKER not in str(exc),
                cause=exc,
            ) from exc
        except httpx.TimeoutException as exc:
            raise C2spTlogTransportError(
                f"timed out fetching C2SP resource: {url}",
                transient=True,
                cause=exc,
            ) from exc
        except (httpx.TransportError, httpx.TooManyRedirects) as exc:
            raise C2spTlogTransportError(
                f"failed to fetch C2SP resource: {url}",
                transient=False if isinstance(exc, httpx.TooManyRedirects) else True,
                cause=exc,
            ) from exc

    @async_verification_operation
    async def async_fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        """Read natively with the sync guarantees and one pool per event loop.

        Responses close after each read, including on cancellation. Finish all
        reads before ``aclose()``; keep owning loops running until it completes.
        Injected fetchers remain caller-owned.
        """
        _require_positive_integer(max_bytes, "max_bytes")
        _validate_resource_url(url)
        timeout = remaining_seconds(self._timeout_seconds)
        try:
            async with asyncio.timeout(timeout):
                async with self._async_clients.get().stream(
                    "GET", url,
                    headers={"Cache-Control": "no-cache", "Accept-Encoding": ACCEPT_ENCODING},
                    timeout=timeout,
                ) as response:
                    _validate_resource_response(response, url, max_bytes)
                    body = BoundedBody(
                        response, max_bytes, lambda: _response_limit_error(url, max_bytes),
                        invalid=lambda detail: C2spTlogTransportError(detail, transient=False),
                    )
                    chunks = (response.aiter_bytes() if response.is_stream_consumed
                              else response.aiter_raw())
                    async for chunk in chunks:
                        body.append(chunk)
                    return body.finish()
        except httpx.ConnectError as exc:
            raise C2spTlogTransportError(
                f"failed to connect while fetching C2SP resource: {url}",
                transient=SSRF_BLOCK_MARKER not in str(exc), cause=exc,
            ) from exc
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise C2spTlogTransportError(
                f"timed out fetching C2SP resource: {url}", transient=True, cause=exc,
            ) from exc
        except (httpx.TransportError, httpx.TooManyRedirects) as exc:
            raise C2spTlogTransportError(
                f"failed to fetch C2SP resource: {url}",
                transient=not isinstance(exc, httpx.TooManyRedirects), cause=exc,
            ) from exc

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        """Return the capabilities enforced by this implementation."""
        return C2spResourceFetchGuarantees(
            https_only=True,
            rejects_redirects=True,
            validates_all_resolved_addresses=True,
            connects_to_validated_address=True,
            bounds_response_during_read=True,
        )

    def close(self) -> None:
        """Close synchronous connections; use aclose after async reads."""
        self._async_clients.close()
        self._client.close()

    async def aclose(self) -> None:
        """Close all owned pools after reads finish, with owning loops running."""
        await self._async_clients.aclose()
        self._client.close()

    async def __aenter__(self) -> SafeC2spResourceFetcher:
        """Return this fetcher for asynchronous resource cleanup."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Close owned pools on leaving an async context."""
        await self.aclose()

    def __enter__(self) -> SafeC2spResourceFetcher:
        """Return this fetcher as a context-managed resource."""
        return self

    def __exit__(self, *args: object) -> None:
        """Close this fetcher when leaving a context."""
        self.close()


def validate_resource_fetcher_capabilities(fetcher: object) -> None:
    """Eagerly validate the common bounded public-read capability contract."""
    if not callable(getattr(fetcher, "fetch_bounded", None)):
        raise ArgumentError(
            "c2sp-tlog resource_fetcher must implement fetch_bounded(url, max_bytes)"
        )
    provider = getattr(fetcher, "security_guarantees", None)
    if not callable(provider):
        raise ArgumentError(
            "c2sp-tlog resource_fetcher must implement security_guarantees()"
        )
    try:
        guarantees = provider()
    except Exception as exc:
        raise ArgumentError(
            "c2sp-tlog resource_fetcher security guarantees could not be read"
        ) from exc
    if not isinstance(guarantees, C2spResourceFetchGuarantees):
        raise ArgumentError(
            "c2sp-tlog security_guarantees() must return C2spResourceFetchGuarantees"
        )
    missing = [
        description
        for enabled, description in (
            (guarantees.https_only, "HTTPS-only transport"),
            (guarantees.rejects_redirects, "redirect rejection"),
            (
                guarantees.validates_all_resolved_addresses,
                "validation of every resolved address",
            ),
            (
                guarantees.connects_to_validated_address,
                "connection to a validated address",
            ),
            (
                guarantees.bounds_response_during_read,
                "response bounding during reads",
            ),
        )
        if enabled is not True
    ]
    if missing:
        raise ArgumentError(
            "c2sp-tlog resource_fetcher lacks " + ", ".join(missing)
        )


@verification_operation
def fetch_bounded_bytes(fetcher: object, url: str, max_bytes: int) -> bytes:
    """Invoke a validated fetcher and defensively enforce its returned length."""
    with _resource_fetch_boundary(fetcher, url, max_bytes) as fetch:
        return _checked_resource_response(fetch(url, max_bytes), url, max_bytes)


@async_verification_operation
async def async_fetch_bounded_bytes(fetcher: object, url: str, max_bytes: int) -> bytes:
    """Invoke a validated fetcher and defensively enforce its returned length."""
    from ._async import call_async

    with _resource_fetch_boundary(fetcher, url, max_bytes):
        response = await call_async(fetcher, "fetch_bounded", url, max_bytes)
        return _checked_resource_response(response, url, max_bytes)


@contextmanager
def _resource_fetch_boundary(
    fetcher: object, url: str, max_bytes: int,
) -> Iterator[Callable[[str, int], bytes]]:
    _require_positive_integer(max_bytes, "max_bytes")
    method = getattr(fetcher, "fetch_bounded", None)
    if not callable(method):
        raise C2spTlogTransportError(
            "C2SP resource fetcher does not implement fetch_bounded",
            transient=False,
        )
    try:
        yield method
    except (C2spTlogTransportError, VerificationError):
        raise
    except httpx.ConnectError as exc:
        raise C2spTlogTransportError(
            f"failed to connect while fetching C2SP resource: {url}",
            transient=SSRF_BLOCK_MARKER not in str(exc),
            cause=exc,
        ) from exc
    except (TimeoutError, httpx.TimeoutException) as exc:
        raise C2spTlogTransportError(
            f"timed out fetching C2SP resource: {url}",
            transient=True,
            cause=exc,
        ) from exc
    except (ConnectionError, OSError, httpx.TransportError) as exc:
        raise C2spTlogTransportError(
            f"failed to fetch C2SP resource: {url}",
            transient=False
            if SSRF_BLOCK_MARKER in str(exc) or isinstance(exc, httpx.TooManyRedirects)
            else True,
            cause=exc,
        ) from exc
    except Exception as exc:
        raise C2spTlogTransportError(
            f"failed to fetch C2SP resource: {url}",
            transient=False,
            cause=exc,
        ) from exc


def _checked_resource_response(response: object, url: str, max_bytes: int) -> bytes:
    if not isinstance(response, bytes):
        raise C2spTlogTransportError(
            f"C2SP resource fetcher returned a non-bytes response: {url}",
            transient=False,
        )
    if len(response) > max_bytes:
        raise _response_limit_error(url, max_bytes)
    return response


def _validate_resource_response(response: httpx.Response, url: str, max_bytes: int) -> None:
    if response.is_redirect:
        raise C2spTlogTransportError(
            f"C2SP resource redirect rejected for {url}",
            transient=False,
        )
    if response.status_code != 200:
        raise C2spTlogTransportError(
            f"C2SP resource returned HTTP {response.status_code}: {url}",
            transient=response.status_code >= 500,
            status_code=response.status_code,
        )
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = None
        if declared_length is not None and declared_length > max_bytes:
            raise _response_limit_error(url, max_bytes)


def _validate_resource_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        parsed.port
    except (TypeError, ValueError) as exc:
        raise C2spTlogTransportError(
            f"invalid C2SP resource URL: {url}", transient=False, cause=exc
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise C2spTlogTransportError(
            f"C2SP resource URL must be absolute HTTPS without credentials or fragment: {url}",
            transient=False,
        )


def _response_limit_error(url: str, max_bytes: int) -> C2spTlogTransportError:
    return C2spTlogTransportError(
        f"C2SP response exceeds configured byte maximum {max_bytes}: {url}",
        transient=False,
    )


def _require_positive_integer(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ArgumentError(f"c2sp-tlog {name} must be a positive integer")
    return value
