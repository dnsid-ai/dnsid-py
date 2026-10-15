"""Shared sync/async lifecycle execution and compatibility with blocking adapters."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Generator
from typing import TYPE_CHECKING, Any, TypeVar, cast

from .._verification_budget import async_run_blocking
from ..enums import VerificationCode
from ..exceptions import VerificationError
from ..models import MigrationEvent

if TYPE_CHECKING:
    from .stream_verifier import MigrationVerificationResult

T = TypeVar("T")


async def call_async(target: object, method: str, *args: Any, **kwargs: Any) -> Any:
    """Prefer an optional async capability; offload a sync-only injected adapter."""
    native = getattr(target, "async_" + method, None)
    if callable(native):
        return await native(*args, **kwargs)
    return await async_run_blocking(getattr(target, method), *args, **kwargs)


def run_verification(
    steps: Generator[MigrationEvent, MigrationVerificationResult, T],
    resolve: Callable[[MigrationEvent], MigrationVerificationResult] | None,
) -> T:
    """Resolve predecessor reads where the shared verifier requests them."""
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


async def async_run_verification(
    steps: Generator[MigrationEvent, MigrationVerificationResult, T],
    resolve: Callable[[MigrationEvent], Awaitable[MigrationVerificationResult]] | None,
) -> T:
    """Await predecessor reads without duplicating deterministic verification."""
    try:
        event = next(steps)
        while True:
            assert resolve is not None
            try:
                result = await resolve(event)
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
