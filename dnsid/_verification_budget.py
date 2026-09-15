"""One cooperative, monotonic budget shared by nested verification operations.

Injected blocking dependencies must honor ``remaining_seconds()`` and check
cancellation between reads; Python cannot forcibly interrupt arbitrary callbacks.
"""

import math
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import Future
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import ParamSpec, TypeVar

import httpx

from .enums import VerificationCode
from .exceptions import ArgumentError, VerificationError

_budget: ContextVar[tuple[float, tuple[threading.Event, ...]] | None] = ContextVar(
    "dnsid_verification_budget", default=None
)
P = ParamSpec("P")
T = TypeVar("T")


def remaining_seconds(maximum: float = 30.0) -> float:
    """Return a child timeout without restarting the invocation's clock."""
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int | float)
        or not math.isfinite(maximum)
        or maximum < 0
    ):
        raise ArgumentError("child timeout must be finite and non-negative")
    current = _budget.get()
    if current is None:
        return maximum
    deadline, cancelled = current
    remaining = deadline - time.monotonic()
    if remaining <= 0 or any(event.is_set() for event in cancelled):
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            "verification deadline exceeded or cancelled",
            transient=True,
        )
    return min(maximum, remaining)


@contextmanager
def verification_budget(
    timeout: float = 30.0, *, cancelled: threading.Event | None = None
) -> Iterator[None]:
    """Set a finite overall timeout; nested budgets cannot extend their parent."""
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ArgumentError("verification timeout must be a finite positive number")
    parent = _budget.get()
    deadline = time.monotonic() + timeout
    events: tuple[threading.Event, ...] = (cancelled,) if cancelled is not None else ()
    if parent is not None:
        deadline = min(deadline, parent[0])
        events += parent[1]
    token = _budget.set((deadline, events))
    try:
        remaining_seconds()
        yield
        remaining_seconds()
    finally:
        _budget.reset(token)


def wait_for_verification(future: Future[T]) -> T:
    """Wait using this caller's budget, without cancelling another caller's work."""
    while True:
        try:
            return future.result(timeout=remaining_seconds(0.05))
        except TimeoutError:
            if future.done():
                raise


def bounded_http_timeout(timeout: float | httpx.Timeout | None = None) -> httpx.Timeout:
    """Clamp every HTTP phase to the remaining invocation budget."""
    value = httpx.Timeout(timeout) if timeout is not None else httpx.Timeout(10.0)
    return httpx.Timeout(
        **{
            name: remaining_seconds(limit if limit is not None else 30.0)
            for name, limit in value.as_dict().items()
        }
    )


def verification_operation(function: Callable[P, T]) -> Callable[P, T]:
    """Start the default 30-second budget only at the outermost entry point."""

    @wraps(function)
    def bounded(*args: P.args, **kwargs: P.kwargs) -> T:
        if _budget.get() is not None:
            remaining_seconds()
            result = function(*args, **kwargs)
            remaining_seconds()
            return result
        with verification_budget():
            return function(*args, **kwargs)

    return bounded
