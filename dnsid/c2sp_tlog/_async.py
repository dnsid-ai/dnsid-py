"""Shared sync/async lifecycle execution and compatibility with blocking adapters."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Generator
from concurrent.futures import Future
from functools import partial
from typing import Any, TypeVar, cast

from .._verification_budget import async_run_blocking, async_wait_for_verification, submit_blocking
from ..enums import VerificationCode
from ..exceptions import VerificationError

T = TypeVar("T")
E = TypeVar("E")
R = TypeVar("R")


async def call_async(target: object, method: str, *args: Any, **kwargs: Any) -> Any:
    """Prefer an optional async capability; offload a sync-only injected adapter."""
    native = getattr(target, "async_" + method, None)
    if callable(native):
        return await native(*args, **kwargs)
    return await async_run_blocking(getattr(target, method), *args, **kwargs)


def run_verification(
    steps: Generator[E, R, T],
    resolve: Callable[[E], R] | None,
) -> T:
    """Resolve resource/predecessor reads where the shared verifier requests them."""
    try:
        event = next(steps)
        while True:
            assert resolve is not None
            try:
                result = resolve(event)
            except Exception as exc:
                if (isinstance(exc, VerificationError)
                        and exc.code == VerificationCode.DEADLINE_EXCEEDED):
                    raise
                event = steps.throw(exc)
            else:
                event = steps.send(result)
    except StopIteration as done:
        return cast(T, done.value)
    finally:
        steps.close()


def _advance(advance: Callable[[], Any]) -> tuple[bool, Any]:
    # StopIteration cannot pass through an asyncio Future.
    try:
        return False, advance()
    except StopIteration as done:
        return True, done.value


async def async_run_verification(
    steps: Generator[E, R, T],
    resolve: Callable[[E], Awaitable[R]] | None,
) -> T:
    """Await native reads and offload deterministic validation to bounded workers."""
    advance: Callable[[], E] = steps.__next__
    future: Future[tuple[bool, Any]] | None = None
    try:
        while True:
            future = submit_blocking(_advance, advance)
            finished, value = await async_wait_for_verification(future)
            if finished:
                return cast(T, value)
            assert resolve is not None
            try:
                result = await resolve(value)
            except Exception as exc:
                if (isinstance(exc, VerificationError)
                        and exc.code == VerificationCode.DEADLINE_EXCEEDED):
                    raise
                advance = partial(steps.throw, exc)
            else:
                advance = partial(steps.send, result)
    finally:
        # A cancelled wait does not stop its worker; never close an executing generator.
        if future is not None and not future.done():
            future.add_done_callback(lambda _: steps.close())
        else:
            steps.close()
