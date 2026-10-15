"""One cooperative, monotonic budget shared by nested verification operations.

Injected blocking dependencies must honor ``remaining_seconds()`` and check
cancellation between reads; Python cannot forcibly interrupt arbitrary callbacks.
"""

import asyncio
import contextvars
import math
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from functools import wraps
from typing import Any, ParamSpec, TypeVar

import httpx

from .enums import VerificationCode
from .exceptions import ArgumentError, VerificationError

_budget: ContextVar[tuple[float, tuple[threading.Event, ...]] | None] = ContextVar(
    "dnsid_verification_budget", default=None
)
_background_work: ContextVar[Callable[[Future[Any]], None] | None] = ContextVar(
    "dnsid_background_work", default=None
)
P = ParamSpec("P")
T = TypeVar("T")
U = TypeVar("U")


class BudgetExhausted(VerificationError):
    """The invocation deadline passed or a sibling cancelled this work.

    Never a definitive verification result; concurrent branches use it to
    tell "cancelled because my sibling failed" apart from a real failure.
    """

    def __init__(self) -> None:
        super().__init__(
            VerificationCode.DEADLINE_EXCEEDED,
            "verification deadline exceeded or cancelled",
            transient=True,
        )


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
        raise BudgetExhausted()
    return min(maximum, remaining)


@contextmanager
def verification_budget(
    timeout: float = 30.0, *, cancelled: threading.Event | None = None
) -> Iterator[None]:
    """Limit this caller; nested budgets cannot extend their parent.

    Exceeding the budget raises VerificationError with DEADLINE_EXCEEDED and
    transient=True. Shared identity evidence has a separate 30-second budget;
    ending this caller's wait does not end work needed by another caller.
    """
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


def verification_work_context(
    track_work: Callable[[Future[Any]], None], *, independent: bool = False,
) -> contextvars.Context:
    """Track worker branches and optionally detach the shared-work budget."""
    context = contextvars.copy_context()
    if independent:
        context.run(_budget.set, (time.monotonic() + 30.0, ()))
    context.run(_background_work.set, track_work)
    return context


async def async_run_blocking(function: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    """Offload an atomic blocking operation and track it through cancellation."""
    context = contextvars.copy_context()
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(context.run, lambda: function(*args, **kwargs))
    pool.shutdown(wait=False)
    track_work = _background_work.get()
    if track_work is not None:
        track_work(future)
    return await async_wait_for_verification(future)


async def async_wait_for_verification(future: Future[T]) -> T:
    """Await shared work without cancelling it; observe failures after cancellation."""
    waiter = asyncio.wrap_future(future)
    waiter.add_done_callback(lambda done: None if done.cancelled() else done.exception())
    return await asyncio.shield(waiter)


def wait_for_verification(future: Future[T]) -> T:
    """Wait using this caller's budget, without cancelling another caller's work."""
    while True:
        try:
            return future.result(timeout=remaining_seconds(0.05))
        except TimeoutError:
            if future.done():
                raise


def run_concurrently(primary: Callable[[], T], secondary: Callable[[], U]) -> tuple[T, U]:
    """Run two independent verification branches under the caller's budget.

    ``secondary`` runs on a helper thread with a copy of the caller's context so
    it inherits, and cannot extend, the invocation deadline. The first
    definitive failure cancels the sibling through the shared budget. Error
    precedence is fixed so callers see the same code regardless of which branch
    settled first: primary failure, then secondary failure, then cancellation.

    A cancelled sibling that is blocked inside a network call is abandoned to
    finish on its own bounded timeout; Python cannot interrupt it.
    """
    cancel = threading.Event()
    context = contextvars.copy_context()

    def guarded_secondary() -> U:
        try:
            with verification_budget(cancelled=cancel):
                return secondary()
        except BaseException:
            cancel.set()
            raise

    pool = ThreadPoolExecutor(max_workers=1)
    future: Future[U] = pool.submit(context.run, guarded_secondary)
    pool.shutdown(wait=False)
    track_work = _background_work.get()
    if track_work is not None:
        track_work(future)
    try:
        with verification_budget(cancelled=cancel):
            primary_result = primary()
    except BudgetExhausted:
        # Only the secondary can have set the flag so far. It does so before
        # re-raising, so its future settles momentarily.
        if cancel.is_set():
            secondary_error = future.exception()
            if secondary_error is not None and not isinstance(secondary_error, BudgetExhausted):
                raise secondary_error
        cancel.set()
        raise
    except BaseException:
        cancel.set()
        raise
    return primary_result, wait_for_verification(future)


async def async_run_concurrently(
    primary: Callable[[], Awaitable[T]], secondary: Callable[[], Awaitable[U]],
) -> tuple[T, U]:
    """Await native branches with the same failure precedence and worker cancellation."""
    cancel = threading.Event()
    tasks: list[asyncio.Task[Any]] = []
    cancelled: asyncio.CancelledError | None = None

    async def guarded(work: Callable[[], Awaitable[Any]]) -> Any:
        try:
            with verification_budget(cancelled=cancel):
                return await work()
        except BaseException:
            cancel.set()
            raise

    try:
        for work in (primary, secondary):
            coroutine = guarded(work)
            try:
                tasks.append(asyncio.create_task(coroutine))
            except BaseException:
                coroutine.close()
                raise
        pending = set(tasks)
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            if any(task.cancelled() or task.exception() is not None for task in done):
                break
    except asyncio.CancelledError as exc:
        cancelled = exc
    finally:
        for task in tasks:
            if not task.done():
                cancel.set()
                task.cancel()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError as exc:
            cancelled = exc
    # Preserve settled nested failures even when a sibling cancelled their parent.
    errors = [asyncio.CancelledError() if task.cancelled() else task.exception() for task in tasks]
    for error in errors:
        if error is not None and not isinstance(error, (BudgetExhausted, asyncio.CancelledError)):
            raise error
    if cancelled is not None:
        raise cancelled
    for error in errors:
        if error is not None:
            raise error
    return tasks[0].result(), tasks[1].result()


def bounded_http_timeout(timeout: float | httpx.Timeout | None = None) -> httpx.Timeout:
    """Clamp every HTTP phase to the remaining invocation budget."""
    value = httpx.Timeout(timeout) if timeout is not None else httpx.Timeout(10.0)
    return httpx.Timeout(
        **{
            name: remaining_seconds(limit if limit is not None else 30.0)
            for name, limit in value.as_dict().items()
        }
    )


def async_verification_operation(
    function: Callable[P, Awaitable[T]],
) -> Callable[P, Awaitable[T]]:
    """Apply the shared verification budget without blocking the event loop."""

    @wraps(function)
    async def bounded(*args: P.args, **kwargs: P.kwargs) -> T:
        with verification_budget() if _budget.get() is None else nullcontext():
            remaining_seconds()
            current = _budget.get()
            assert current is not None
            try:
                async with asyncio.timeout(current[0] - time.monotonic()):
                    result = await function(*args, **kwargs)
                    remaining_seconds()
                    return result
            except TimeoutError as exc:
                raise BudgetExhausted() from exc

    return bounded


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
