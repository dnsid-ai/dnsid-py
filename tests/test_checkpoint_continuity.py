"""Native continuity checks through signed public readers and in-memory storage."""

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace

import pytest

from dnsid._verification_budget import BudgetExhausted, verification_budget
from dnsid.c2sp_tlog import (
    InMemoryCheckpointStore,
    TrustedCheckpoint,
)
from dnsid.c2sp_tlog.merkle import merkle_root_from_entries
from dnsid.exceptions import VerificationError
from tests.test_c2sp_tlog import TestEndToEndReader as _ReaderFixture

BASE = TrustedCheckpoint("log.example", 0, merkle_root_from_entries([]),
                         datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))


@pytest.fixture
def store():
    result = InMemoryCheckpointStore()
    result.put(BASE)
    return result


def _reader(store):
    reader, _ = _ReaderFixture()._build_log()
    reader._options.checkpoint_store = store
    return reader


@pytest.mark.parametrize("field,value", [
    ("origin", ""), ("origin", " "), ("tree_size", True), ("tree_size", 1.0),
    ("tree_size", -1), ("root_hash", bytes(32)), ("root_hash", b"short"), ("root_hash", bytearray(32)),
    ("witness_time", datetime.datetime(2026, 1, 1)), ("witness_time", "2026-01-01"),
])
def test_store_rejects_invalid_input_without_changing_trust(store, field, value):
    with pytest.raises(ValueError):
        store.put(replace(BASE, **{field: value}))
    assert store.get(BASE.origin) == BASE


def test_store_snapshots_have_immutable_roots_and_fixed_timezones(store):
    class MutableZone(datetime.tzinfo):
        offset = datetime.timedelta(hours=1)

        def utcoffset(self, dt):
            return self.offset

        def dst(self, dt):
            return datetime.timedelta(0)

    zone = MutableZone()
    candidate = replace(BASE, witness_time=datetime.datetime(2026, 1, 2, tzinfo=zone))
    expected = replace(candidate, witness_time=candidate.witness_time.astimezone(datetime.UTC))
    store.put(candidate)
    zone.offset = datetime.timedelta(hours=2)
    snapshot = store.get(BASE.origin)
    assert snapshot == expected
    with pytest.raises(FrozenInstanceError):
        snapshot.root_hash = b"z" * 32
    with pytest.raises(TypeError):
        snapshot.root_hash[0] = 0
    assert store.get(BASE.origin) == expected


@pytest.mark.parametrize("index", [True, 0.0, -1, None, "0"])
def test_signed_scan_rejects_invalid_indexes_before_continuity(store, index):
    reader = _reader(store)
    load = reader._source.load_stream

    def invalid(reference, fqdn):
        evidence = load(reference, fqdn)
        evidence.entries[0].index = index
        return evidence

    reader._source.load_stream = invalid
    with pytest.raises(VerificationError) as caught:
        reader.rebuild_history(_ReaderFixture.DOMAIN)
    assert caught.value.category == "INVALID_EVIDENCE"
    assert not caught.value.transient
    assert store.get(BASE.origin) == BASE


@pytest.mark.parametrize("fault", ["missing", "duplicate", "wrong-root"])
def test_candidate_invalid_scan_takes_precedence_over_prefix_conflict(store, fault):
    trusted = replace(BASE, tree_size=1, root_hash=b"x" * 32)
    store.put(trusted)
    reader, _ = _ReaderFixture()._build_log(lambda entry: [entry])
    reader._options.checkpoint_store = store
    load = reader._source.load_stream

    def invalid(reference, fqdn):
        evidence = load(reference, fqdn)
        if fault == "missing":
            evidence.entries.pop()
        elif fault == "duplicate":
            evidence.entries[1].index = 0
        else:
            evidence.entries[0].data = b"wrong leaf"
        return evidence

    reader._source.load_stream = invalid
    with pytest.raises(VerificationError) as caught:
        reader.rebuild_history(_ReaderFixture.DOMAIN)
    assert caught.value.category == "INVALID_EVIDENCE"
    assert store.get(BASE.origin) == trusted


def test_conflicting_signed_extensions_cannot_both_succeed(store):
    readers = [_reader(store), _reader(store)]
    ready = threading.Barrier(2)
    for reader in readers:
        load = reader._source.load_stream

        def synchronized(reference, fqdn, load=load):
            evidence = load(reference, fqdn)
            ready.wait(timeout=5)
            return evidence

        reader._source.load_stream = synchronized

    def verify(reader):
        try:
            reader.rebuild_history(_ReaderFixture.DOMAIN)
            return None
        except VerificationError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(verify, readers))
    assert sum(result is None for result in results) == 1
    failure = next(result for result in results if result is not None)
    assert failure.category == "LOG_FORK"
    assert failure.__cause__.trusted_root_hash == store.get(BASE.origin).root_hash
    assert failure.__cause__.observed_root_hash != store.get(BASE.origin).root_hash


@pytest.mark.parametrize("termination", ["cancellation", "deadline"])
def test_public_reader_abort_after_verification_prevents_publication(store, monkeypatch, termination):
    reader = _reader(store)
    cancel = threading.Event()
    clock = [0.0]
    monkeypatch.setattr("dnsid._verification_budget.time.monotonic", lambda: clock[0])
    advance = store.verify_and_advance

    def cancelling(candidate, verify):
        def checked(stored):
            verify(stored)
            if termination == "cancellation":
                cancel.set()
            else:
                clock[0] = 2.0
        advance(candidate, checked)

    monkeypatch.setattr(store, "verify_and_advance", cancelling)
    with pytest.raises(BudgetExhausted), verification_budget(timeout=1, cancelled=cancel):
        reader.rebuild_history(_ReaderFixture.DOMAIN)
    assert store.get(BASE.origin) == BASE


def test_public_reader_cancellation_while_waiting_does_not_queue_publication(store, monkeypatch):
    reader = _reader(store)
    waiting = threading.Event()
    cancel = threading.Event()
    lock = store._lock_for(BASE.origin)
    lock.acquire()
    original = store._lock_for

    def lock_for(origin):
        waiting.set()
        return original(origin)

    monkeypatch.setattr(store, "_lock_for", lock_for)

    def verify():
        with verification_budget(cancelled=cancel):
            reader.rebuild_history(_ReaderFixture.DOMAIN)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(verify)
            assert waiting.wait(timeout=5)
            cancel.set()
            with pytest.raises(BudgetExhausted):
                future.result(timeout=5)
    finally:
        lock.release()
    assert store.get(BASE.origin) == BASE
