"""SQLite-backed checkpoint continuity and explicit, audited re-baselining."""

from __future__ import annotations

import datetime
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from .checkpoint_store import CheckpointStore, TrustedCheckpoint
from .errors import (
    C2spCheckpointConsistencyError,
    C2spCheckpointStoreError,
    C2spLifecycleErrorCategory,
)


class SQLiteCheckpointStore(CheckpointStore):
    """Durable checkpoint store shared by threads and processes.

    SQLite transactions serialize verification and advancement and commit before
    success. Uses rollback journaling with ``synchronous=EXTRA`` and enables
    ``fullfsync`` where SQLite supports it. Use a local persistent filesystem
    with working SQLite locks and sync semantics, not a network filesystem.

    Open an existing store by default; ``create=True`` exclusively initializes a
    NEW file. Never automatically recreate a missing/corrupt store on startup:
    losing the database loses the trust history. An empty store still uses first
    contact trust; seed an independently authenticated checkpoint with ``put``
    if that is unsuitable. ``put`` does not authorize lowering a trusted size.

    Transactions lock the whole database, including during the verification
    callback. Callbacks must not re-enter this store. Operations wait up to five
    seconds for contention, then fail closed. No connection is retained between
    calls and no explicit close is needed.
    """

    def __init__(self, path: Path | str, *, create: bool = False) -> None:
        """Open or explicitly initialize persistent trust state.

        Args:
            path: Database path in an existing, access-controlled directory.
            create: Exclusively create a new database; fails if it exists.

        Raises:
            C2spCheckpointStoreError: Creation/opening or schema validation fails.
        """
        self._path = Path(path).resolve()
        if create:
            try:
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            except OSError as exc:
                raise C2spCheckpointStoreError("cannot create checkpoint store") from exc
            # Leave failed initialization in place: do not silently bootstrap again.
            with self._transaction(write=True, initialize=True) as connection:
                connection.execute(
                    "CREATE TABLE checkpoints (origin TEXT PRIMARY KEY, "
                    "tree_size INTEGER NOT NULL, "
                    "root_hash BLOB NOT NULL, witness_time TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE rebaselines (origin TEXT NOT NULL, "
                    "previous_size INTEGER NOT NULL, previous_root BLOB NOT NULL, "
                    "previous_time TEXT NOT NULL, tree_size INTEGER NOT NULL, "
                    "root_hash BLOB NOT NULL, witness_time TEXT NOT NULL, "
                    "authorized_by TEXT NOT NULL, evidence TEXT NOT NULL, "
                    "recorded_at TEXT NOT NULL)"
                )
                connection.execute("PRAGMA user_version = 1")
        with self._transaction() as connection:
            connection.execute("SELECT origin, tree_size, root_hash, witness_time FROM checkpoints")
            connection.execute("SELECT * FROM rebaselines LIMIT 0")

    @contextmanager
    def _transaction(
        self, *, write: bool = False, initialize: bool = False
    ) -> Iterator[sqlite3.Connection]:
        try:
            # mode=rw prevents a deleted database from silently becoming first contact.
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=rw", uri=True)) as connection:
                connection.execute("PRAGMA synchronous = EXTRA")
                connection.execute("PRAGMA fullfsync = ON")
                with connection:
                    # ponytail: database-wide lock; shard stores if origins contend.
                    connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                    if not initialize:
                        version = connection.execute("PRAGMA user_version").fetchone()[0]
                        if version != 1:
                            raise C2spCheckpointStoreError("unsupported checkpoint store schema")
                    yield connection
        except (sqlite3.Error, OSError) as exc:
            raise C2spCheckpointStoreError("checkpoint storage operation failed") from exc

    def get(self, origin: str) -> TrustedCheckpoint | None:
        """Read the trusted checkpoint; storage failures never become first contact."""
        with self._transaction() as connection:
            return self._read(connection, origin)

    def put(self, checkpoint: TrustedCheckpoint) -> None:
        """Seed externally authenticated state if its size advances (or equals) trust.

        Bypasses proof verification. A smaller size is ignored; an equal-size
        conflicting root is rejected. Use ``rebaseline`` to explicitly reset trust.
        """
        self.verify_and_advance(checkpoint, lambda stored: None)

    def verify_and_advance(
        self,
        candidate: TrustedCheckpoint,
        verify: Callable[[TrustedCheckpoint | None], None],
    ) -> None:
        """Verify and durably advance in one transaction, rolling back on failure."""
        _validate_checkpoint(candidate)
        with self._transaction(write=True) as connection:
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
        """Explicitly replace trust after independently authorized operator recovery.

        NEVER call automatically on verification failure. This method records the
        operator's assertion of authorization; it cannot authenticate a person or
        recovery evidence. The caller must do that independently beforehand.

        Args:
            checkpoint: Independently authenticated replacement checkpoint.
            expected: Exact previous checkpoint reviewed by the operator. A
                concurrent change aborts the reset rather than overwriting it.
            authorized_by: Nonempty identity of the authorizing incident/security owner.
            evidence: Nonempty incident/evidence reference justifying this trust change.

        Raises:
            ValueError: Invalid checkpoint, origin mismatch, or missing audit fields.
            C2spCheckpointStoreError: Stored state changed or persistence failed.

        The previous and replacement checkpoints, authorization, evidence reference,
        and UTC time are appended to the ``rebaselines`` SQL table in the SAME
        transaction as the replacement. Preserve an external incident archive too:
        someone with filesystem write access can alter this database and its audit.
        """
        _validate_checkpoint(checkpoint)
        _validate_checkpoint(expected)
        if checkpoint.origin != expected.origin:
            raise ValueError("rebaseline checkpoints must have the same origin")
        if not isinstance(authorized_by, str) or not authorized_by.strip():
            raise ValueError("rebaseline requires an authorizing operator")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError("rebaseline requires an evidence reference")
        with self._transaction(write=True) as connection:
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

    @staticmethod
    def _read(connection: sqlite3.Connection, origin: str) -> TrustedCheckpoint | None:
        row = connection.execute(
            "SELECT tree_size, root_hash, witness_time FROM checkpoints WHERE origin = ?", (origin,)
        ).fetchone()
        if row is None:
            return None
        try:
            checkpoint = TrustedCheckpoint(
                origin, row[0], row[1], datetime.datetime.fromisoformat(row[2])
            )
            _validate_checkpoint(checkpoint)
            return checkpoint
        except (TypeError, ValueError, OverflowError) as exc:
            raise C2spCheckpointStoreError("invalid persisted checkpoint") from exc

    @staticmethod
    def _write(connection: sqlite3.Connection, checkpoint: TrustedCheckpoint) -> None:
        connection.execute(
            "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?)",
            (checkpoint.origin, checkpoint.tree_size, checkpoint.root_hash,
             checkpoint.witness_time.isoformat()),
        )


def _validate_checkpoint(checkpoint: TrustedCheckpoint) -> None:
    if not isinstance(checkpoint.origin, str) or not checkpoint.origin:
        raise ValueError("checkpoint origin must be nonempty")
    if type(checkpoint.tree_size) is not int or not 0 <= checkpoint.tree_size < 2**63:
        raise ValueError("checkpoint tree size must be a non-negative SQLite integer")
    if not isinstance(checkpoint.root_hash, bytes) or len(checkpoint.root_hash) != 32:
        raise ValueError("checkpoint root must be a 32-byte SHA-256 hash")
    if (
        not isinstance(checkpoint.witness_time, datetime.datetime)
        or checkpoint.witness_time.utcoffset() is None
    ):
        raise ValueError("checkpoint witness time must be timezone-aware")
