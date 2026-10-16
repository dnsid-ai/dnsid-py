"""Persisted trusted-checkpoint state for append-only consistency.

A checkpoint verified in isolation proves nothing about history: a forked or
rolled-back log can serve a validly-signed checkpoint that silently drops a
rotation or revocation.  The reader remembers the highest checkpoint it has
accepted per log origin and requires every later checkpoint to extend it (the
old tree must be a prefix of the new one), rejecting a shrunk or divergent
tree.

The store is shared across reader instances (a fresh reader is built per
verification), so it must outlive a single ``verify_domain`` call.  Register
one store via :class:`C2spTlogReaderOptions` and reuse the options across all
readers so the trusted state accumulates.
"""

from __future__ import annotations

import datetime
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .._verification_budget import remaining_seconds
from .errors import C2spCheckpointConsistencyError, C2spLifecycleErrorCategory


@dataclass(frozen=True)
class TrustedCheckpoint:
    """The highest checkpoint accepted for one log origin."""

    origin: str
    tree_size: int
    root_hash: bytes
    witness_time: datetime.datetime


def _checkpoint_snapshot(checkpoint: TrustedCheckpoint) -> TrustedCheckpoint:
    """Validate caller input and retain only immutable values, with a fixed UTC zone."""
    if not isinstance(checkpoint, TrustedCheckpoint):
        raise ValueError("checkpoint must be a TrustedCheckpoint")
    _validate_origin(checkpoint.origin)
    if type(checkpoint.tree_size) is not int or checkpoint.tree_size < 0:
        raise ValueError("checkpoint tree size must be a non-negative integer")
    if type(checkpoint.root_hash) is not bytes or len(checkpoint.root_hash) != 32:
        raise ValueError("checkpoint root must be a 32-byte SHA-256 hash")
    if (
        not isinstance(checkpoint.witness_time, datetime.datetime)
        or checkpoint.witness_time.utcoffset() is None
    ):
        raise ValueError("checkpoint witness time must be timezone-aware")
    try:
        instant = checkpoint.witness_time.astimezone(datetime.UTC)
    except OverflowError as exc:
        raise ValueError("checkpoint witness time is outside the supported range") from exc
    return TrustedCheckpoint(checkpoint.origin, checkpoint.tree_size, checkpoint.root_hash, instant)


def _validate_origin(origin: str) -> None:
    if not isinstance(origin, str) or not origin.strip():
        raise ValueError("checkpoint origin must be nonempty")


@contextmanager
def _checkpoint_lock(lock: threading.Lock) -> Iterator[None]:
    while not lock.acquire(timeout=remaining_seconds(0.05)):
        pass
    try:
        remaining_seconds()
        yield
    finally:
        lock.release()


class CheckpointStore(ABC):
    """Record of the highest trusted checkpoint per origin.

    Implementations MUST be safe for concurrent use.  Consistency enforcement
    and advancement MUST be atomic per origin (see :meth:`verify_and_advance`):
    checking a new checkpoint against the trusted one and recording it cannot
    be split, or two concurrent verifications could each accept a different
    forked extension of the same trusted checkpoint.
    """

    @abstractmethod
    def get(self, origin: str) -> TrustedCheckpoint | None:
        """Return the trusted checkpoint for *origin*, or None if unseen."""

    @abstractmethod
    def put(self, checkpoint: TrustedCheckpoint) -> None:
        """Unconditionally record *checkpoint* if it advances *origin*.

        Bypasses consistency checking; intended for seeding trusted state, not
        for the verification path (use :meth:`verify_and_advance`).
        """

    @abstractmethod
    def verify_and_advance(
        self,
        candidate: TrustedCheckpoint,
        verify: Callable[[TrustedCheckpoint | None], None],
    ) -> None:
        """Atomically check consistency and advance the trusted checkpoint.

        Under the per-origin lock: load the trusted checkpoint, call *verify*
        with it (which MUST raise if *candidate* is a rollback or fork of that
        trusted state), then record *candidate* if it advances the tree.
        Implementations must validate inputs and stored records, return immutable
        snapshots, and check the invocation budget before publication and while
        waiting for locks. Storage failures raise C2spCheckpointStoreError;
        callback failures retain their original type and cause.

        Holding the lock across verify and advance serializes concurrent
        verifications of one origin, so an equivocating log cannot get two
        forked extensions accepted against the same trusted checkpoint.
        """


class InMemoryCheckpointStore(CheckpointStore):
    """Process-lifetime trusted-checkpoint store (the default).

    Resists rollback and fork only while this same store instance is retained.
    Creating a new store or registry loses remembered trust even without a
    process restart; the next checkpoint is trusted on first contact. A verifier
    that must resist cross-restart rollback MUST inject a durable
    ``CheckpointStore`` such as :class:`SQLiteCheckpointStore`. The SDK does not
    emit a runtime warning when this in-memory default is selected; production
    deployments must explicitly configure and monitor persistent trust storage.
    """

    def __init__(self) -> None:
        """Create an empty store with no trusted checkpoints."""
        self._by_origin: dict[str, TrustedCheckpoint] = {}
        self._meta = threading.Lock()
        self._origin_locks: dict[str, threading.Lock] = {}

    def _lock_for(self, origin: str) -> threading.Lock:
        with _checkpoint_lock(self._meta):
            lock = self._origin_locks.get(origin)
            if lock is None:
                lock = threading.Lock()
                self._origin_locks[origin] = lock
            return lock

    @contextmanager
    def _locked(self, origin: str) -> Iterator[None]:
        _validate_origin(origin)
        with _checkpoint_lock(self._lock_for(origin)):
            yield

    def get(self, origin: str) -> TrustedCheckpoint | None:
        """Return the immutable trusted checkpoint for *origin*, or None if unseen."""
        with self._locked(origin):
            return self._by_origin.get(origin)

    def put(self, checkpoint: TrustedCheckpoint) -> None:
        """Seed advancing state without proof checks; reject equal-size conflicts."""
        self.verify_and_advance(checkpoint, lambda stored: None)

    def verify_and_advance(
        self,
        candidate: TrustedCheckpoint,
        verify: Callable[[TrustedCheckpoint | None], None],
    ) -> None:
        """Run *verify* and record *candidate* under the per-origin lock.

        Exceptions raised by *verify* propagate and leave the trusted
        checkpoint for the origin unchanged.
        """
        candidate = _checkpoint_snapshot(candidate)
        with self._locked(candidate.origin):
            verify(self._by_origin.get(candidate.origin))
            remaining_seconds()
            self._advance_locked(candidate)

    def _advance_locked(self, checkpoint: TrustedCheckpoint) -> None:
        current = self._by_origin.get(checkpoint.origin)
        if (
            current is not None
            and checkpoint.tree_size == current.tree_size
            and checkpoint.root_hash != current.root_hash
        ):
            raise C2spCheckpointConsistencyError(
                "equal-size checkpoint has a conflicting root",
                category=C2spLifecycleErrorCategory.LOG_FORK,
                trusted=current,
                observed=checkpoint,
            )
        if current is None or checkpoint.tree_size >= current.tree_size:
            self._by_origin[checkpoint.origin] = checkpoint
