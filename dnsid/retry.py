"""Retry helpers for transient VerificationError failures."""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def retry_transient(
    fn: Callable[[], T],
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> T:
    """Call *fn* and retry on transient VerificationError with exponential backoff.

    Only retries when the raised :class:`~dnsid.exceptions.VerificationError` has
    ``transient=True``; any other exception — including non-transient
    ``VerificationError`` — propagates immediately.

    Args:
        fn: Zero-argument callable to call (use ``functools.partial`` or a lambda
            to bind arguments).
        max_attempts: Total number of attempts before re-raising the last error.
        base_delay: Initial delay in seconds; doubles each retry.
        max_delay: Upper cap on the per-retry delay before jitter.

    Example::

        result = retry_transient(lambda: idm.verify_domain("example.com"))
    """
    from .exceptions import VerificationError

    last_exc: VerificationError | None = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except VerificationError as exc:
            if not exc.transient:
                raise
            last_exc = exc
            if attempt < max_attempts - 1:
                delay = min(base_delay * (2**attempt), max_delay) + random.uniform(0, 1)
                time.sleep(delay)

    raise last_exc  # type: ignore[misc]


async def async_retry_transient(
    fn: Callable[[], object],
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> object:
    """Async variant of :func:`retry_transient`.

    *fn* must return an awaitable (e.g. a coroutine function call).
    Sleeps with ``asyncio.sleep`` between retries so the event loop is not blocked.

    Example::

        result = await async_retry_transient(lambda: some_async_fn("example.com"))
    """
    import asyncio

    from .exceptions import VerificationError

    last_exc: VerificationError | None = None
    for attempt in range(max_attempts):
        try:
            return await fn()  # type: ignore[misc]
        except VerificationError as exc:
            if not exc.transient:
                raise
            last_exc = exc
            if attempt < max_attempts - 1:
                delay = min(base_delay * (2**attempt), max_delay) + random.uniform(0, 1)
                await asyncio.sleep(delay)

    raise last_exc  # type: ignore[misc]
