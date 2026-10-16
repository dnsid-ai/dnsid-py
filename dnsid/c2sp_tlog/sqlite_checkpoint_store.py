"""SQLite-backed checkpoint continuity and explicit, audited re-baselining."""

from __future__ import annotations

import datetime
import os
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from .._verification_budget import remaining_seconds
from .checkpoint_store import (
    CheckpointStore,
    TrustedCheckpoint,
    _checkpoint_snapshot,
    _validate_origin,
)
from .errors import (
    C2spCheckpointConsistencyError,
    C2spCheckpointStoreError,
    C2spLifecycleErrorCategory,
)


class SQLiteCheckpointStore(CheckpointStore):
    """Durable checkpoint store shared by threads and processes.

    Requires a local persistent filesystem with working SQLite locks and sync
    semantics, not a network filesystem. Uses rollback journaling,
    ``synchronous=EXTRA`` and ``fullfsync``. Success follows durable commit.
    SQLite owns locks for the entire transaction; lock age never permits theft.

    Open existing storage by default; ``create=True`` exclusively initializes a
    NEW namespace. Missing, corrupt, or unsupported storage is never recreated.
    Schema 2 keeps a separate origin inventory to detect missing checkpoint rows.
    Removing both the inventory and its data, or replacing the entire database,
    requires independently controlled evidence to detect. Schema 1 is unsupported:
    retain it and use fenced, authorized recovery into a new namespace.

    Transactions lock the database during the callback, which must not re-enter
    the store. Lock waits stop at five seconds or the invocation budget, whichever
    is earlier. Budget cancellation is checked before commit, not by abandoning a
    queued write. An uncertain commit raises C2spCheckpointStoreError with
    ``indeterminate=True`` and a fresh read-back or reconciliation error.
    No connection is retained and no explicit close is needed.
    """

    def __init__(self, path: Path | str, *, create: bool = False) -> None:
        """Open existing trust or explicitly initialize a new protected namespace.

        Args:
            path: Database path in an existing, access-controlled directory.
            create: Exclusively initialize a new database; fail if it exists.

        Raises:
            C2spCheckpointStoreError: Initialization, opening or validation failed.
        """
        self._path = Path(path).resolve()
        if create:
            try:
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            except OSError as exc:
                raise C2spCheckpointStoreError("cannot create checkpoint store") from exc
            # Leave failed initialization in place; never silently bootstrap again.
            with self._transaction(write=True, initialize=True) as connection:
                connection.execute(
                    "CREATE TABLE checkpoints (origin TEXT PRIMARY KEY, "
                    "tree_size INTEGER NOT NULL, "
                    "root_hash BLOB NOT NULL, witness_time TEXT NOT NULL)"
                )
                connection.execute("CREATE TABLE origins (origin TEXT PRIMARY KEY)")
                connection.execute(
                    "CREATE TABLE rebaselines (origin TEXT NOT NULL, "
                    "previous_size INTEGER NOT NULL, previous_root BLOB NOT NULL, "
                    "previous_time TEXT NOT NULL, tree_size INTEGER NOT NULL, "
                    "root_hash BLOB NOT NULL, witness_time TEXT NOT NULL, "
                    "authorized_by TEXT NOT NULL, evidence TEXT NOT NULL, "
                    "recorded_at TEXT NOT NULL)"
                )
                connection.execute("PRAGMA user_version = 2")
        with self._transaction() as connection:
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise C2spCheckpointStoreError("checkpoint database integrity check failed")
            for (origin,) in connection.execute("SELECT origin FROM origins"):
                self._read(connection, origin)

    @contextmanager
    def _transaction(
        self, *, write: bool = False, initialize: bool = False, origin: str | None = None
    ) -> Iterator[sqlite3.Connection]:
        publication_started = False
        try:
            remaining_seconds()
            # mode=rw prevents a deleted database from becoming first contact.
            with closing(sqlite3.connect(
                self._path.as_uri() + "?mode=rw", uri=True, timeout=0
            )) as connection:
                connection.execute("PRAGMA synchronous = EXTRA")
                connection.execute("PRAGMA fullfsync = ON")
                if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                    raise C2spCheckpointStoreError("checkpoint store requires rollback journaling")
                self._begin(connection, write)
                try:
                    remaining_seconds()
                    if not initialize:
                        if connection.execute("PRAGMA user_version").fetchone()[0] != 2:
                            raise C2spCheckpointStoreError("unsupported checkpoint store schema")
                        connection.execute("SELECT * FROM rebaselines LIMIT 0")
                        lost = connection.execute(
                            "SELECT origin FROM origins EXCEPT SELECT origin FROM checkpoints"
                        ).fetchone()
                        unrecorded = connection.execute(
                            "SELECT origin FROM checkpoints EXCEPT SELECT origin FROM origins"
                        ).fetchone()
                        if lost or unrecorded:
                            raise C2spCheckpointStoreError("checkpoint origin inventory is damaged")
                    yield connection
                    remaining_seconds()
                    publication_started = write
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
        except (sqlite3.Error, OSError) as exc:
            error = C2spCheckpointStoreError(
                "checkpoint storage operation failed", indeterminate=publication_started
            )
            if publication_started and origin is not None:
                try:
                    error.reconciled_checkpoint = self.get(origin)
                except Exception as reconciliation_error:
                    error.reconciliation_error = reconciliation_error
            raise error from exc

    @staticmethod
    def _begin(connection: sqlite3.Connection, write: bool) -> None:
        deadline = time.monotonic() + remaining_seconds(5.0)
        while True:
            remaining_seconds()
            try:
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                return
            except sqlite3.OperationalError as exc:
                if exc.sqlite_errorcode != sqlite3.SQLITE_BUSY or time.monotonic() >= deadline:
                    raise
                time.sleep(remaining_seconds(min(0.01, max(0, deadline - time.monotonic()))))

    def get(self, origin: str) -> TrustedCheckpoint | None:
        """Read trusted state; storage failures never become first contact."""
        _validate_origin(origin)
        with self._transaction() as connection:
            return self._read(connection, origin)

    def put(self, checkpoint: TrustedCheckpoint) -> None:
        """Seed advancing authenticated state; ignore smaller sizes, reject forks."""
        self.verify_and_advance(checkpoint, lambda stored: None)

    def verify_and_advance(
        self,
        candidate: TrustedCheckpoint,
        verify: Callable[[TrustedCheckpoint | None], None],
    ) -> None:
        """Verify and durably advance under one transaction and invocation budget."""
        candidate = _sqlite_checkpoint(candidate)
        with self._transaction(write=True, origin=candidate.origin) as connection:
            stored = self._read(connection, candidate.origin)
            verify(stored)
            if (
                stored is not None
                and candidate.tree_size == stored.tree_size
                and candidate.root_hash != stored.root_hash
            ):
                raise C2spCheckpointConsistencyError(
                    "equal-size checkpoint has a conflicting root; explicit rebaseline required",
                    category=C2spLifecycleErrorCategory.LOG_FORK,
                    trusted=stored,
                    observed=candidate,
                )
            remaining_seconds()
            if stored is None or candidate.tree_size >= stored.tree_size:
                self._write(connection, candidate)

    def rebaseline(
        self,
        checkpoint: TrustedCheckpoint,
        *,
        expected: TrustedCheckpoint,
        authorized_by: str,
        evidence: str,
    ) -> None:
        """Replace only the reviewed tuple, never automatically retrying recovery.

        This method does NOT authenticate an operator or authorize rollback. Before
        calling, fence and drain all affected writers; externally archive signed
        checkpoints, witness/proof evidence and incident logs; authenticate recovery
        authority independently of the failing log; retain approval for the exact
        old/replacement tuples and trust policy, reason and authorization time.
        Independently verify replacement signatures, quorum and freshness against
        that approval. ``evidence`` references this retained authorization/archive;
        ``authorized_by`` identifies its approver, not an SDK authentication check.

        Both tuples and the references are committed in the same transaction as
        replacement. On ANY failure stop for reconciliation, not reload/retry.
        Read-back is required before success. Keep the external archive protected
        from database rollback, including approval recorded BEFORE replacement and
        its reconciled outcome afterward. Discard affected caches/verified objects,
        rebuild readers and complete fresh identity/lifecycle verification before
        resuming; checkpoint recovery does not repair lost lifecycle history.

        Args:
            checkpoint: Independently verified, authorized replacement.
            expected: Exact reviewed old tuple, including witnessed time.
            authorized_by: Approver identity from the external authorization.
            evidence: Reference to retained authorization and signed evidence.

        Raises:
            ValueError: Invalid checkpoint or missing audit reference.
            C2spCheckpointStoreError: Stale expected state, storage or read-back failure.
        """
        checkpoint = _sqlite_checkpoint(checkpoint)
        expected = _sqlite_checkpoint(expected)
        if checkpoint.origin != expected.origin:
            raise ValueError("rebaseline checkpoints must have the same origin")
        if not isinstance(authorized_by, str) or not authorized_by.strip():
            raise ValueError("rebaseline requires an authorizing operator")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError("rebaseline requires an evidence reference")
        with self._transaction(write=True, origin=checkpoint.origin) as connection:
            if self._read(connection, checkpoint.origin) != expected:
                raise C2spCheckpointStoreError("trusted checkpoint changed; review recovery again")
            connection.execute(
                "INSERT INTO rebaselines VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (checkpoint.origin, expected.tree_size, expected.root_hash,
                 expected.witness_time.isoformat(), checkpoint.tree_size, checkpoint.root_hash,
                 checkpoint.witness_time.isoformat(), authorized_by, evidence,
                 datetime.datetime.now(datetime.UTC).isoformat()),
            )
            self._write(connection, checkpoint)
        try:
            observed = self.get(checkpoint.origin)
        except C2spCheckpointStoreError as exc:
            error = C2spCheckpointStoreError("replacement read-back failed", indeterminate=True)
            error.reconciliation_error = exc
            raise error from exc
        if observed != checkpoint:
            error = C2spCheckpointStoreError(
                "replacement read-back differs; reconcile recovery", indeterminate=True
            )
            error.reconciled_checkpoint = observed
            raise error

    @staticmethod
    def _read(connection: sqlite3.Connection, origin: str) -> TrustedCheckpoint | None:
        try:
            _validate_origin(origin)
        except ValueError as exc:
            raise C2spCheckpointStoreError("invalid persisted checkpoint origin") from exc
        row = connection.execute(
            "SELECT tree_size, root_hash, witness_time FROM checkpoints WHERE origin = ?", (origin,)
        ).fetchone()
        if row is None:
            return None
        try:
            checkpoint = _sqlite_checkpoint(TrustedCheckpoint(
                origin, row[0], row[1], datetime.datetime.fromisoformat(row[2])
            ))
            if checkpoint.witness_time.isoformat() != row[2]:
                raise ValueError("persisted witness time is not canonical UTC")
            return checkpoint
        except (TypeError, ValueError, OverflowError) as exc:
            raise C2spCheckpointStoreError("invalid persisted checkpoint") from exc

    @staticmethod
    def _write(connection: sqlite3.Connection, checkpoint: TrustedCheckpoint) -> None:
        connection.execute("INSERT OR IGNORE INTO origins VALUES (?)", (checkpoint.origin,))
        connection.execute(
            "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?)",
            (checkpoint.origin, checkpoint.tree_size, checkpoint.root_hash,
             checkpoint.witness_time.isoformat()),
        )


def _sqlite_checkpoint(checkpoint: TrustedCheckpoint) -> TrustedCheckpoint:
    checkpoint = _checkpoint_snapshot(checkpoint)
    if checkpoint.tree_size >= 2**63:
        raise ValueError("checkpoint tree size must be a non-negative SQLite integer")
    return checkpoint
