"""Durable trust, transactional concurrency, and authorized recovery checks."""

import datetime
import os
import sqlite3
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import replace
from multiprocessing import get_context

import pytest

from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError,
    C2spCheckpointStoreError,
    C2spLifecycleErrorCategory,
    SQLiteCheckpointStore,
    TrustedCheckpoint,
)

BASE = TrustedCheckpoint("log.example", 1, b"a" * 32, datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
NEXT = replace(BASE, tree_size=2, root_hash=b"b" * 32)


def _competing_advance(args):
    path, root = args
    store = SQLiteCheckpointStore(path)

    def verify(stored):
        if stored != BASE:
            raise ValueError("another fork already advanced")
        time.sleep(0.01)  # Exposes a split read/verify/write transaction.

    try:
        store.verify_and_advance(replace(NEXT, root_hash=bytes([root]) * 32), verify)
        return True
    except ValueError:
        return False


def _crash_before_commit(path):
    store = SQLiteCheckpointStore(path)
    write = store._write

    def crash(connection, checkpoint):
        write(connection, checkpoint)
        os._exit(17)

    store._write = crash
    store.put(NEXT)


@pytest.fixture
def store(tmp_path):
    result = SQLiteCheckpointStore(tmp_path / "trust.db", create=True)
    result.put(BASE)
    return result


def test_reopen_preserves_trust_and_put_does_not_reset(store, tmp_path):
    store.put(NEXT)
    reopened = SQLiteCheckpointStore(tmp_path / "trust.db")
    assert reopened.get(BASE.origin) == NEXT
    reopened.put(BASE)
    assert reopened.get(BASE.origin) == NEXT
    assert reopened.get("another.origin") is None


@pytest.mark.parametrize("operation", ["put", "verify_and_advance"])
def test_equal_size_fork_requires_audited_rebaseline(store, tmp_path, operation):
    candidate = replace(BASE, root_hash=b"c" * 32)
    args = () if operation == "put" else (lambda stored: None,)
    getattr(store, operation)(BASE, *args)  # Repeating the same root is allowed.
    with pytest.raises(C2spCheckpointConsistencyError) as error:
        getattr(store, operation)(candidate, *args)
    assert error.value.category == C2spLifecycleErrorCategory.LOG_FORK
    assert SQLiteCheckpointStore(tmp_path / "trust.db").get(BASE.origin) == BASE
    with sqlite3.connect(tmp_path / "trust.db") as connection:
        assert connection.execute("SELECT count(*) FROM rebaselines").fetchone()[0] == 0
    store.rebaseline(candidate, expected=BASE, authorized_by="owner", evidence="incident-123")
    assert SQLiteCheckpointStore(tmp_path / "trust.db").get(BASE.origin) == candidate
    with sqlite3.connect(tmp_path / "trust.db") as connection:
        assert connection.execute("SELECT count(*) FROM rebaselines").fetchone()[0] == 1


def test_creation_is_explicit_and_exclusive(tmp_path):
    path = tmp_path / "trust.db"
    with pytest.raises(C2spCheckpointStoreError):
        SQLiteCheckpointStore(path)
    assert not path.exists()
    store = SQLiteCheckpointStore(path, create=True)
    store.put(BASE)
    with pytest.raises(C2spCheckpointStoreError):
        SQLiteCheckpointStore(path, create=True)
    assert store.get(BASE.origin) == BASE


def test_deleted_store_does_not_rebootstrap(store, tmp_path):
    path = tmp_path / "trust.db"
    path.unlink()
    with pytest.raises(C2spCheckpointStoreError):
        store.get(BASE.origin)
    assert not path.exists()


@pytest.mark.parametrize("data", [b"", b"not a sqlite database"])
def test_corrupt_store_fails_closed(tmp_path, data):
    path = tmp_path / "trust.db"
    path.write_bytes(data)
    with pytest.raises(C2spCheckpointStoreError):
        SQLiteCheckpointStore(path)
    assert path.read_bytes() == data


@pytest.mark.parametrize("column,value", [
    ("tree_size", -1), ("tree_size", "invalid"), ("root_hash", b"short"),
    ("witness_time", "not a time"), ("witness_time", "2026-01-01"),
])
def test_invalid_persisted_checkpoint_fails_closed(store, tmp_path, column, value):
    with sqlite3.connect(tmp_path / "trust.db") as connection:
        connection.execute(f"UPDATE checkpoints SET {column} = ?", (value,))
    with pytest.raises(C2spCheckpointStoreError, match="invalid persisted checkpoint"):
        store.get(BASE.origin)


def test_rejected_verification_does_not_advance(store):
    def reject(stored):
        assert stored == BASE
        raise ValueError("invalid prefix")

    with pytest.raises(ValueError, match="invalid prefix"):
        store.verify_and_advance(NEXT, reject)
    assert store.get(BASE.origin) == BASE


def test_sqlite_write_failure_does_not_advance(store, tmp_path):
    with sqlite3.connect(tmp_path / "trust.db") as connection:
        connection.execute(
            "CREATE TRIGGER reject_write BEFORE INSERT ON checkpoints "
            "BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"
        )
    with pytest.raises(C2spCheckpointStoreError):
        store.put(NEXT)
    assert store.get(BASE.origin) == BASE


@pytest.mark.parametrize("executor", ["threads", "processes"])
def test_competing_forks_cannot_both_succeed(store, tmp_path, executor):
    pool_type = ThreadPoolExecutor if executor == "threads" else ProcessPoolExecutor
    kwargs = {} if executor == "threads" else {"mp_context": get_context("spawn")}
    with pool_type(max_workers=4, **kwargs) as pool:
        results = list(pool.map(_competing_advance, [(str(tmp_path / "trust.db"), n) for n in range(8)]))
    assert sum(results) == 1
    trusted = store.get(BASE.origin)
    assert trusted.tree_size == 2
    assert trusted.root_hash == bytes([results.index(True)]) * 32


def test_process_death_before_commit_preserves_old_trust(store, tmp_path):
    process = get_context("spawn").Process(target=_crash_before_commit, args=(str(tmp_path / "trust.db"),))
    process.start()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join()
        pytest.fail("crash worker hung")
    assert process.exitcode == 17
    process.close()
    assert SQLiteCheckpointStore(tmp_path / "trust.db").get(BASE.origin) == BASE


def test_rebaseline_requires_reviewed_state_and_records_both_checkpoints(store, tmp_path):
    store.put(NEXT)
    store.rebaseline(BASE, expected=NEXT, authorized_by="security-owner", evidence="incident-123")
    assert store.get(BASE.origin) == BASE
    with sqlite3.connect(tmp_path / "trust.db") as connection:
        audit = connection.execute("SELECT * FROM rebaselines").fetchone()
    assert audit[:9] == (
        BASE.origin, NEXT.tree_size, NEXT.root_hash, NEXT.witness_time.isoformat(),
        BASE.tree_size, BASE.root_hash, BASE.witness_time.isoformat(), "security-owner", "incident-123",
    )
    assert datetime.datetime.fromisoformat(audit[9]).utcoffset() == datetime.timedelta(0)
    with pytest.raises(C2spCheckpointStoreError, match="changed"):
        store.rebaseline(BASE, expected=NEXT, authorized_by="security-owner", evidence="incident-123")


@pytest.mark.parametrize("fields", [
    {"authorized_by": " "}, {"evidence": ""}, {"checkpoint": replace(BASE, origin="other")},
    {"checkpoint": replace(BASE, root_hash=b"invalid")},
])
def test_rebaseline_validates_audit_and_checkpoint(store, fields):
    args = dict(checkpoint=BASE, expected=BASE, authorized_by="owner", evidence="incident-123")
    args.update(fields)
    with pytest.raises(ValueError):
        store.rebaseline(**args)
    assert store.get(BASE.origin) == BASE


def test_failed_rebaseline_rolls_back_audit_and_trust(store, tmp_path):
    with sqlite3.connect(tmp_path / "trust.db") as connection:
        connection.execute(
            "CREATE TRIGGER reject_write BEFORE INSERT ON checkpoints "
            "BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"
        )
    with pytest.raises(C2spCheckpointStoreError):
        store.rebaseline(NEXT, expected=BASE, authorized_by="owner", evidence="incident-123")
    assert store.get(BASE.origin) == BASE
    with sqlite3.connect(tmp_path / "trust.db") as connection:
        assert connection.execute("SELECT count(*) FROM rebaselines").fetchone()[0] == 0
