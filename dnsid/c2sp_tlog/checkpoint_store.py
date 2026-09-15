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
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class TrustedCheckpoint:
    """The highest checkpoint accepted for one log origin."""

    origin: str
    tree_size: int
    root_hash: bytes
    witness_time: datetime.datetime


class CheckpointStore(ABC):
    """Durable record of the highest trusted checkpoint per origin.

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
        Holding the lock across verify and advance serializes concurrent
        verifications of one origin, so an equivocating log cannot get two
        forked extensions accepted against the same trusted checkpoint.
        """


class InMemoryCheckpointStore(CheckpointStore):
    """Process-lifetime trusted-checkpoint store (the default).

    Resists rollback and fork *within a process*.  It does NOT survive a
    restart: afterward the first checkpoint for an origin is trusted on first
    contact, so a rollback served post-restart would be accepted.  A verifier
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
        with self._meta:
            lock = self._origin_locks.get(origin)
            if lock is None:
                lock = threading.Lock()
                self._origin_locks[origin] = lock
            return lock

    def get(self, origin: str) -> TrustedCheckpoint | None:
        """Return the trusted checkpoint for *origin*, or None if unseen."""
        with self._lock_for(origin):
            return self._by_origin.get(origin)

    def put(self, checkpoint: TrustedCheckpoint) -> None:
        """Record *checkpoint* if it advances its origin, without verifying."""
        with self._lock_for(checkpoint.origin):
            self._advance_locked(checkpoint)

    def verify_and_advance(
        self,
        candidate: TrustedCheckpoint,
        verify: Callable[[TrustedCheckpoint | None], None],
    ) -> None:
        """Run *verify* and record *candidate* under the per-origin lock.

        Exceptions raised by *verify* propagate and leave the trusted
        checkpoint for the origin unchanged.
        """
        with self._lock_for(candidate.origin):
            verify(self._by_origin.get(candidate.origin))
            self._advance_locked(candidate)

    def _advance_locked(self, checkpoint: TrustedCheckpoint) -> None:
        current = self._by_origin.get(checkpoint.origin)
        if current is None or checkpoint.tree_size >= current.tree_size:
            self._by_origin[checkpoint.origin] = checkpoint
