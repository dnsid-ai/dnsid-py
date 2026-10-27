"""Signed bundle continuity through factories, sync/async readers, and atomic storage."""

import asyncio
import base64
import datetime
import json
import threading
from dataclasses import replace

import pytest

from dnsid._utils import b64url_decode_strict
from dnsid._verification_budget import BudgetExhausted, verification_budget
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError,
    C2spResourceFetchGuarantees,
    C2spScanLimits,
    C2spTlogTransportError,
    C2spTlogVerificationError,
    C2spTlogVerificationOptions,
    Checkpoint,
    IndexedEntry,
    ScanStreamSource,
    TrustedCheckpoint,
    create_c2sp_tlog_verification_registry,
    enforce_checkpoint_policy,
    leaf_hash,
    merkle_root_from_entries,
    parse_c2sp_policy_file,
    parse_checkpoint,
    verify_c2sp_stream_bundle,
)
from dnsid.c2sp_tlog.stream_bundle import (
    _async_verify_and_advance_checkpoint,
    _verify_and_advance_checkpoint,
)
from dnsid.exceptions import VerificationError
from tests.test_c2sp_hash_tiles import Tree
from tests.test_c2sp_stream_bundle import _options, _seed_old_checkpoint, _vector
from tests.vectors.generate_c2sp_stream_bundle import (
    _cosignature,
    _note_signature,
    _private,
    _verifier,
)


def setup_reader(*, required=False, trusted_size=1, async_only=False, max_tree_size=2):
    vector = _vector()
    options = _options(vector)
    bundle = json.loads(vector["bundle"])
    entries = [b64url_decode_strict(item["entry"]) for item in bundle["events"]]
    if trusted_size == 1:
        _seed_old_checkpoint(vector, options)
    elif trusted_size is not None:
        options.checkpoint_store.put(TrustedCheckpoint(
            "log.example", trusted_size, merkle_root_from_entries(entries[:trusted_size]),
            datetime.datetime.fromtimestamp(vector["trust"]["now"] - 120, tz=datetime.UTC),
        ))

    class Fetcher:
        calls = None
        tile_read = None

        def __init__(self):
            self.calls = []

        def response(self, url, maximum):
            self.calls.append((url, maximum))
            if url.endswith("?format=bundle"):
                return vector["bundle"].encode()
            assert url in ("https://log.example/tile/0/000.p/2",
                           "https://log.example/tile/0/000"), "unexpected raw scan"
            if self.tile_read is not None:
                return self.tile_read(url, maximum)
            assert maximum == 64
            return b"".join(leaf_hash(entry) for entry in entries)

        def fetch_bounded(self, url, maximum):
            assert not async_only, "sync network on async verification"
            return self.response(url, maximum)

        async def async_fetch_bounded(self, url, maximum):
            return self.response(url, maximum)

        def security_guarantees(self):
            return C2spResourceFetchGuarantees(True, True, True, True, True)

    fetcher = Fetcher()
    registry = create_c2sp_tlog_verification_registry(C2spTlogVerificationOptions(
        policy_document=options.policy_bytes,
        bundle_verifier_keys=options.bundle_keys,
        max_bundle_lifetime_ms=options.max_bundle_lifetime_ms,
        resource_fetcher=fetcher,
        trusted_checkpoint_store=options.checkpoint_store,
        require_stream_bundle=required,
        scan_limits=C2spScanLimits(max_tree_size=max_tree_size, max_total_entry_bytes=1),
    ))
    reader = registry.new_reader(bundle["lr"])
    reader._source._now = options.now
    reader._options.entity_key = options.entity_key
    return reader, fetcher, options, bundle, entries


@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("trusted_size", [None, 0, 1, 2])
def test_factory_uses_tiles_only_for_nonempty_growth(required, trusted_size):
    reader, fetcher, options, bundle, _ = setup_reader(required=required, trusted_size=trusted_size)
    assert len(reader.rebuild_history(bundle["fqdn"])) == 2
    assert options.checkpoint_store.get("log.example").tree_size == 2
    assert len(fetcher.calls) == (2 if trusted_size == 1 else 1)
    # A fresh reader for another verification shares origin trust; equality needs no tiles.
    reader._history_cache.clear()
    assert len(reader.rebuild_history(bundle["fqdn"])) == 2
    assert fetcher.calls[-1][0].endswith("?format=bundle")
    assert all("/entries/" not in url and not url.endswith("/checkpoint")
               for url, _ in fetcher.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("trusted_size", [None, 0, 1, 2])
async def test_async_factory_uses_native_tile_reads(required, trusted_size):
    reader, fetcher, options, bundle, _ = setup_reader(
        required=required, trusted_size=trusted_size, async_only=True,
    )
    assert len(await reader.async_rebuild_history(bundle["fqdn"])) == 2
    assert options.checkpoint_store.get("log.example").tree_size == 2
    assert len(fetcher.calls) == (2 if trusted_size == 1 else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("fault", ["short", "long", "corrupt", "fetch", "failed-retry"])
async def test_tile_failures_never_scan_or_replace_trust(asynchronous, required, fault):
    reader, fetcher, options, bundle, _ = setup_reader(
        required=required, async_only=asynchronous,
    )
    trusted = options.checkpoint_store.get("log.example")
    cause = OSError("tile offline")
    failure = C2spTlogTransportError("tile offline", transient=True, cause=cause, status_code=503)

    def tile_read(url, maximum):
        if fault == "failed-retry" and ".p/" in url:
            raise C2spTlogTransportError("missing partial", transient=False, status_code=404)
        if fault in ("fetch", "failed-retry"):
            raise failure
        return bytes({"short": 63, "long": 65, "corrupt": 64}[fault])

    fetcher.tile_read = tile_read
    with pytest.raises(VerificationError) as error:
        if asynchronous:
            await reader.async_rebuild_history(bundle["fqdn"])
        else:
            reader.rebuild_history(bundle["fqdn"])
    assert error.value.category == "INVALID_EVIDENCE"
    assert error.value.transient == (fault in ("fetch", "failed-retry"))
    if fault in ("fetch", "failed-retry"):
        assert error.value.__cause__ is failure
        assert failure.__cause__ is cause
    else:
        diagnostic = error.value.__cause__
        if fault != "long":
            assert diagnostic.trusted_root_hash == trusted.root_hash
            assert diagnostic.observed_tree_size == 2
    assert options.checkpoint_store.get("log.example") == trusted
    assert len(fetcher.calls) == (3 if fault == "failed-retry" else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_partial_404_recovers_through_full_tile_in_required_mode(asynchronous):
    reader, fetcher, options, bundle, entries = setup_reader(
        required=True, async_only=asynchronous,
    )

    def tile_read(url, maximum):
        if ".p/" in url:
            raise C2spTlogTransportError("missing", transient=False, status_code=404)
        assert maximum == 8192
        return b"".join(leaf_hash(entry) for entry in entries) + bytes(8192 - 64)

    fetcher.tile_read = tile_read
    if asynchronous:
        await reader.async_rebuild_history(bundle["fqdn"])
    else:
        reader.rebuild_history(bundle["fqdn"])
    assert options.checkpoint_store.get("log.example").tree_size == 2
    assert len(fetcher.calls) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("mode", ["valid", "invalid", "fetch-failure"])
async def test_explicit_proof_precedes_tiles_and_never_falls_back(asynchronous, mode):
    reader, fetcher, options, bundle, _ = setup_reader(async_only=asynchronous)
    original = reader._source._verifier_options
    trusted = options.checkpoint_store.get("log.example")
    failure = C2spTlogTransportError("proof failed", transient=True, cause=TimeoutError())
    calls = []

    class Proof:
        def fetch_consistency_proof(self, reference, m, n):
            calls.append((m, n))
            if mode == "fetch-failure":
                raise failure
            if mode == "invalid":
                return []
            return [b64url_decode_strict(bundle["events"][0]["proof"])]

    def verifier_options(key):
        result = original(key)
        result.consistency_source = Proof()
        return result

    reader._source._verifier_options = verifier_options

    async def verify():
        if asynchronous:
            await reader.async_rebuild_history(bundle["fqdn"])
        else:
            reader.rebuild_history(bundle["fqdn"])

    if mode == "valid":
        await verify()
        assert options.checkpoint_store.get("log.example").tree_size == 2
    else:
        with pytest.raises(VerificationError) as error:
            await verify()
        assert error.value.category == ("LOG_INCONSISTENT" if mode == "invalid" else "INVALID_EVIDENCE")
        if mode == "fetch-failure":
            assert error.value.__cause__ is failure
            assert error.value.transient
        assert options.checkpoint_store.get("log.example") == trusted
    assert calls == [(1, 2)]
    assert len(fetcher.calls) == 1


@pytest.mark.parametrize("fault", [None, "trusted", "candidate", "missing", "index"])
def test_complete_scan_precedes_explicit_source_and_tiles(fault):
    vector = _vector()
    options = _options(vector)
    verified = verify_c2sp_stream_bundle(vector["bundle"].encode(), _options(vector))
    _seed_old_checkpoint(vector, options, root=bytes(32) if fault == "trusted" else None)
    entries = [IndexedEntry(event.index, event.data) for event in verified.events]
    if fault == "candidate":
        entries[1].data = b"wrong entry"
    elif fault == "missing":
        entries.pop()
    elif fault == "index":
        entries[0].index = 0.0

    class Proof:
        def fetch_consistency_proof(self, *args):
            raise AssertionError("unnecessary proof call")

    def tiles(*args):
        raise AssertionError("unnecessary tile reads")

    options.consistency_source = Proof()
    trusted = options.checkpoint_store.get("log.example")

    def verify():
        _verify_and_advance_checkpoint(
            verified.reference, verified.checkpoint, verified.checkpoint_witness_time,
            options, complete_entries=entries, tile_consistency=tiles,
        )

    if fault is None:
        verify()
        assert options.checkpoint_store.get("log.example").tree_size == 2
    else:
        with pytest.raises(C2spTlogVerificationError) as error:
            verify()
        assert error.value.category == ("LOG_INCONSISTENT" if fault == "trusted" else "INVALID_EVIDENCE")
        assert options.checkpoint_store.get("log.example") == trusted


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["witness-time", "conflicting-extension"])
async def test_async_tile_advancement_rechecks_the_exact_winning_state(change):
    vector = _vector()
    options = _options(vector)
    verified = verify_c2sp_stream_bundle(vector["bundle"].encode(), _options(vector))
    tree = Tree(70_000)
    verified = replace(verified, checkpoint=Checkpoint("log.example", 70_000, tree.root(70_000)))
    initial = tree.checkpoint(300)
    options.checkpoint_store.put(initial)
    winner = replace(initial, witness_time=initial.witness_time + datetime.timedelta(seconds=1))
    if change == "conflicting-extension":
        winner = replace(winner, tree_size=500, root_hash=bytes(32))
    calls = []

    class Fetcher:
        def fetch_bounded(self, *args):
            raise AssertionError("sync network")

        async def async_fetch_bounded(self, url, maximum):
            calls.append((url, maximum))
            if len(calls) == 1:
                options.checkpoint_store.put(winner)
            return tree.read((url, maximum))

    source = ScanStreamSource(Fetcher(), lambda checkpoint: None)
    if change == "witness-time":
        await _async_verify_and_advance_checkpoint(verified, options, source)
        assert options.checkpoint_store.get("log.example").tree_size == 70_000
    else:
        with pytest.raises(C2spCheckpointConsistencyError) as error:
            await _async_verify_and_advance_checkpoint(verified, options, source)
        assert error.value.category == "LOG_INCONSISTENT"
        assert error.value.trusted_tree_size == 500
        assert options.checkpoint_store.get("log.example") == winner
    assert len(calls) == 10  # Five tiles per attempt, including re-verification.


@pytest.mark.parametrize("root", [bytes(32), merkle_root_from_entries([])])
def test_signed_size_zero_checkpoint_root_validation(root):
    vector = _vector()
    text = f"log.example\n0\n{base64.b64encode(root).decode()}\n"
    _, log_hash = _verifier("log.example", _private(4), 1)
    _, witness_hash = _verifier("witness.example", _private(5), 4)
    signed = text + "\n" + _note_signature("log.example", log_hash, _private(4), text)
    signed += "\n" + _cosignature("witness.example", witness_hash, _private(5), text) + "\n"

    def verify():
        return enforce_checkpoint_policy(
            parse_checkpoint(signed), "log.example",
            parse_c2sp_policy_file(vector["policy"]), "public", vector["trust"]["now"] * 1000,
        )

    if root == bytes(32):
        with pytest.raises(C2spTlogVerificationError) as error:
            verify()
        assert error.value.category == "INVALID_EVIDENCE"
    else:
        assert verify().checkpoint_witness_time is not None

    reader, fetcher, options, bundle, _ = setup_reader()
    trusted = options.checkpoint_store.get("log.example")
    fetcher.response = lambda url, maximum: signed.encode()
    reader._source = ScanStreamSource(fetcher, reader._authenticate_checkpoint)
    with pytest.raises(VerificationError) as error:
        reader.rebuild_history(bundle["fqdn"])
    assert error.value.category == ("INVALID_EVIDENCE" if root == bytes(32) else "LOG_ROLLBACK")
    assert options.checkpoint_store.get("log.example") == trusted


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_malformed_stored_empty_root_is_store_failure(asynchronous):
    reader, fetcher, options, bundle, _ = setup_reader(async_only=asynchronous)
    malformed = replace(options.checkpoint_store.get("log.example"), tree_size=0)
    options.checkpoint_store._by_origin["log.example"] = malformed
    with pytest.raises(VerificationError) as error:
        if asynchronous:
            await reader.async_rebuild_history(bundle["fqdn"])
        else:
            reader.rebuild_history(bundle["fqdn"])
    assert error.value.category == "CHECKPOINT_STORE_ERROR"
    assert not error.value.transient
    assert options.checkpoint_store._by_origin["log.example"] == malformed
    assert len(fetcher.calls) == 1


@pytest.mark.parametrize("required", [False, True])
def test_candidate_tree_limit_prevents_tile_fetch_or_trust_change(required):
    reader, fetcher, options, bundle, _ = setup_reader(required=required, max_tree_size=1)
    trusted = options.checkpoint_store.get("log.example")
    with pytest.raises(VerificationError):
        reader.rebuild_history(bundle["fqdn"])
    assert options.checkpoint_store.get("log.example") == trusted
    assert len(fetcher.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("on_retry", [False, True])
async def test_tile_cancellation_prevents_publication(asynchronous, on_retry):
    reader, fetcher, options, bundle, _ = setup_reader(async_only=asynchronous)
    trusted = options.checkpoint_store.get("log.example")
    cancel = threading.Event()

    def read(url, maximum):
        if on_retry and ".p/" in url:
            raise C2spTlogTransportError("missing", transient=False, status_code=404)
        cancel.set()
        return bytes(maximum)

    fetcher.tile_read = read
    with pytest.raises(BudgetExhausted), verification_budget(cancelled=cancel):
        if asynchronous:
            await reader.async_rebuild_history(bundle["fqdn"])
        else:
            reader.rebuild_history(bundle["fqdn"])
    assert options.checkpoint_store.get("log.example") == trusted
    assert len(fetcher.calls) == (3 if on_retry else 2)


@pytest.mark.asyncio
async def test_native_async_cancellation_during_tile_read_does_not_publish():
    reader, fetcher, options, bundle, _ = setup_reader(async_only=True)
    trusted = options.checkpoint_store.get("log.example")
    started = asyncio.Event()
    original = fetcher.async_fetch_bounded

    async def read(url, maximum):
        if "/tile/" in url:
            started.set()
            await asyncio.Event().wait()
        return await original(url, maximum)

    fetcher.async_fetch_bounded = read
    task = asyncio.create_task(reader.async_rebuild_history(bundle["fqdn"]))
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert options.checkpoint_store.get("log.example") == trusted


@pytest.mark.asyncio
async def test_native_async_cancellation_waiting_for_store_cannot_publish_later():
    reader, fetcher, options, bundle, entries = setup_reader(async_only=True)
    store = options.checkpoint_store
    trusted = store.get("log.example")
    lock = store._lock_for("log.example")
    waiting = threading.Event()
    finished = threading.Event()
    advance = store.verify_and_advance

    def read(url, maximum):
        lock.acquire()
        return b"".join(leaf_hash(entry) for entry in entries)

    def blocked(candidate, verify):
        waiting.set()
        try:
            advance(candidate, verify)
        finally:
            finished.set()

    fetcher.tile_read = read
    store.verify_and_advance = blocked
    task = asyncio.create_task(reader.async_rebuild_history(bundle["fqdn"]))
    try:
        assert await asyncio.to_thread(waiting.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        lock.release()
    assert await asyncio.to_thread(finished.wait, 5)
    assert store.get("log.example") == trusted


@pytest.mark.asyncio
@pytest.mark.parametrize("on_retry", [False, True])
async def test_overall_deadline_during_native_tile_read_fails_closed(on_retry):
    reader, fetcher, options, bundle, _ = setup_reader(async_only=True)
    trusted = options.checkpoint_store.get("log.example")
    original = fetcher.async_fetch_bounded
    tile_calls = []

    async def read(url, maximum):
        if "/tile/" not in url:
            return await original(url, maximum)
        tile_calls.append(url)
        if on_retry and ".p/" in url:
            raise C2spTlogTransportError("missing partial", transient=False, status_code=404)
        await asyncio.Event().wait()

    fetcher.async_fetch_bounded = read
    with pytest.raises(BudgetExhausted), verification_budget(timeout=0.2):
        await reader.async_rebuild_history(bundle["fqdn"])
    assert options.checkpoint_store.get("log.example") == trusted
    assert len(tile_calls) == (2 if on_retry else 1)
