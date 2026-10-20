"""Async C2SP histories share the sync verifier, cache and checkpoint guarantees."""

import asyncio
import dataclasses
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dnsid import AsyncLogReader, VerificationCode, VerificationError, verification_budget
from dnsid.c2sp_tlog import (
    C2spMigrationVerificationLimits,
    C2spTlogTransportError,
    InMemoryCheckpointStore,
    TlogProofV1,
    parse_checkpoint,
)
from tests.test_c2sp_migration import _DOMAIN, _NOW, _Fetcher, _key, _Logs, _signed_entry


@pytest.fixture
def native(monkeypatch):
    loop_thread = threading.get_ident()

    async def fetch(self, url, max_bytes):
        assert threading.get_ident() == loop_thread
        await asyncio.sleep(0)
        self.calls.append(url)
        if url not in self.resources:
            raise C2spTlogTransportError("missing", transient=False, status_code=404)
        result = self.resources[url]
        assert len(result) <= max_bytes
        return result

    monkeypatch.setattr(_Fetcher, "async_fetch_bounded", fetch, raising=False)
    return fetch


def _reader(logs, destination, **kwargs):
    registry, fetcher = logs.registry(**kwargs)
    reader = registry.new_reader(destination)
    reader._options.entity_key = logs.entity_key
    return reader, fetcher


@pytest.mark.asyncio
@pytest.mark.parametrize("bundles", [False, True])
async def test_recursive_history_checks_cache_and_sync_parity(native, bundles):
    logs = _Logs.create()
    old = logs.issuance("old")
    logs.terminate(old)
    middle = logs.migration("middle", old, 0)
    destination = logs.migration("new", middle, 0)
    reader, fetcher = _reader(logs, destination, bundles=bundles)
    assert isinstance(reader, AsyncLogReader)
    with (
        patch.object(fetcher, "fetch_bounded", side_effect=AssertionError("sync network")),
        patch.object(asyncio.get_running_loop(), "run_in_executor", side_effect=AssertionError("worker")),
    ):
        await reader.async_preload_history(_DOMAIN, logs.entity_key)
        history = await reader.async_rebuild_history(_DOMAIN)
        assert [event.event_type for event in history] == ["ISSUANCE", "MIGRATION", "MIGRATION"]
        binding = await reader.async_verify_bilateral_binding(
            SimpleNamespace(identity_fqdn=_DOMAIN, gi="example"), logs.entity_key, logs.operational_key,
        )
        await reader.async_verify_operational_continuity(
            _DOMAIN, binding.initial_operational_thumbprint, logs.operational_key.thumbprint(),
        )
        evidence = await reader.async_verify_non_revocation(_DOMAIN, _NOW)
        assert evidence.history_start == f"{old}@0"
        assert evidence.history_end == f"{destination}@0"
        assert await reader.async_key_timestamp(_DOMAIN, logs.operational_key.thumbprint()) == history[0].timestamp
        assert reader.rebuild_history(_DOMAIN) == history
        assert reader.verify_non_revocation(_DOMAIN, _NOW) == evidence
    assert len(fetcher.calls) == (3 if bundles else 6)
    assert all(("?format=bundle" in url) == bundles for url in fetcher.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("bundles", [False, True])
async def test_exact_cutoff_and_inclusion_proof(native, bundles):
    logs = _Logs.create()
    old = logs.issuance("old")
    logs.terminate(old)
    destination = logs.migration("new", old, 0)
    reader, fetcher = _reader(logs, destination, bundles=bundles)
    checkpoint = parse_checkpoint(fetcher.resources[reader.parsed.log_prefix + "/checkpoint"].decode())
    reader._options.proofs["0"] = TlogProofV1(0, [], checkpoint)
    with patch.object(fetcher, "fetch_bounded", side_effect=AssertionError("sync network")):
        event = await reader.async_read_event(f"{destination}@0")
        assert event.event_type == "MIGRATION"
        history = await reader.async_rebuild_history_through(
            _DOMAIN, f"{destination}@0", logs.entity_key, max_depth=8, max_events=10_000,
            max_response_bytes=8 * 1024 * 1024, seen_log_references=frozenset(),
        )
    assert history.event_refs == [f"{old}@0", f"{destination}@0"]
    assert history.response_bytes > 0
    with pytest.raises(VerificationError):
        await reader.async_read_event(f"{destination}@1")


@pytest.mark.asyncio
async def test_incomplete_single_event_evidence_preserves_error_category(native, monkeypatch):
    from unittest.mock import AsyncMock

    logs = _Logs.create()
    reader, _ = _reader(logs, logs.issuance("first"))
    evidence = await reader._source.async_load_stream(reader.parsed, _DOMAIN)
    reader._options.proofs["0"] = TlogProofV1(0, [], evidence.checkpoint)
    evidence.complete = False
    monkeypatch.setattr(reader._source, "load_stream", lambda *args: evidence)
    monkeypatch.setattr(reader._source, "async_load_stream", AsyncMock(return_value=evidence))
    with pytest.raises(VerificationError, match="complete lifecycle evidence") as native_error:
        await reader.async_read_event(reader.lr + "@0")
    with pytest.raises(VerificationError, match="complete lifecycle evidence") as sync_error:
        reader.read_event(reader.lr + "@0")
    assert native_error.value.category == sync_error.value.category == "INVALID_EVIDENCE"


@pytest.mark.asyncio
@pytest.mark.parametrize("bundles", [False, True])
@pytest.mark.parametrize("field,value,message", [
    ("max_depth", 1, "depth maximum"),
    ("max_history_events", 2, "event maximum"),
    ("max_response_bytes", 1, "byte maximum"),
])
async def test_recursive_limits_match_sync(native, bundles, field, value, message):
    logs = _Logs.create()
    first = logs.issuance("first")
    second = logs.migration("second", first, 0)
    destination = logs.migration("third", second, 0)
    reader, _ = _reader(
        logs, destination, bundles=bundles, limits=C2spMigrationVerificationLimits(**{field: value}),
    )
    with pytest.raises(VerificationError, match=message) as native_error:
        await reader.async_rebuild_history(_DOMAIN)
    with pytest.raises(VerificationError, match=message) as sync_error:
        reader.rebuild_history(_DOMAIN)
    assert native_error.value.code == sync_error.value.code
    assert native_error.value.category == sync_error.value.category


@pytest.mark.asyncio
@pytest.mark.parametrize("bundles", [False, True])
async def test_cycles_fail_closed(native, bundles):
    logs = _Logs.create()
    second = logs.migration("second", logs.lr("first"), 0)
    logs.migration("first", second, 0)
    reader, _ = _reader(logs, second, bundles=bundles)
    with pytest.raises(VerificationError, match="cycle"):
        await reader.async_rebuild_history(_DOMAIN)


@pytest.mark.asyncio
@pytest.mark.parametrize("bundles", [False, True])
async def test_unauthenticated_migration_does_not_read_predecessor(native, bundles):
    from dnsid.models import MigrationEvent

    logs = _Logs.create()
    old = logs.issuance("old")
    destination = logs.migration("new", old, 0)
    _, unrelated = _key("unrelated")
    invalid = MigrationEvent(
        domain=_DOMAIN, previous_log=logs.lr("missing"), new_log=destination,
        final_entry_ref=f"{logs.lr('missing')}@0", timestamp=_NOW,
    )
    logs.entries[destination].insert(0, _signed_entry(invalid, destination, unrelated))
    reader, fetcher = _reader(logs, destination, bundles=bundles)
    if bundles:
        with pytest.raises(VerificationError, match="state does not match replay"):
            await reader.async_rebuild_history(_DOMAIN)
    else:
        assert len(await reader.async_rebuild_history(_DOMAIN)) == 2
    assert not any("missing.example" in url for url in fetcher.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["missing", "invalid", "required"])
async def test_bundle_fallback_rules(native, mode):
    logs = _Logs.create()
    destination = logs.issuance("first")
    reader, fetcher = _reader(logs, destination, bundles=True, require_bundles=mode == "required")
    url = f"{reader.parsed.log_prefix}/streams/{_DOMAIN}?format=bundle"
    if mode == "invalid":
        fetcher.resources[url] = b"{}"
    else:
        del fetcher.resources[url]
    if mode == "missing":
        assert len(await reader.async_rebuild_history(_DOMAIN)) == 1
        assert len(fetcher.calls) == 3
    else:
        with pytest.raises(VerificationError):
            await reader.async_rebuild_history(_DOMAIN)
        assert fetcher.calls == [url]


@pytest.mark.asyncio
async def test_sync_only_adapters_use_worker_fallback():
    logs = _Logs.create()
    destination = logs.issuance("first")
    reader, fetcher = _reader(logs, destination)
    thread = threading.get_ident()
    sync_fetch = fetcher.fetch_bounded

    def fetch(*args):
        assert threading.get_ident() != thread
        return sync_fetch(*args)

    with patch.object(fetcher, "fetch_bounded", fetch):
        assert len(await reader.async_rebuild_history(_DOMAIN)) == 1


@pytest.mark.asyncio
async def test_concurrent_forks_are_serialized_atomically(native):
    first, second = _Logs.create(), _Logs.create()
    destination = first.issuance("first")
    second.issuance("first")
    store = InMemoryCheckpointStore()
    readers = [_reader(logs, destination)[0] for logs in (first, second)]
    for reader in readers:
        reader._options.checkpoint_store = store
    outcomes = await asyncio.gather(
        *(reader.async_rebuild_history(_DOMAIN) for reader in readers), return_exceptions=True,
    )
    assert sum(isinstance(result, list) for result in outcomes) == 1
    error = next(result for result in outcomes if isinstance(result, VerificationError))
    assert error.category == "LOG_FORK"
    assert store.get(readers[0].parsed.origin).tree_size == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_interruption_does_not_cache_partial_history(native, monkeypatch, cancel):
    logs = _Logs.create()
    old = logs.issuance("old")
    destination = logs.migration("new", old, 0)
    reader, _ = _reader(logs, destination)
    started = asyncio.Event()

    async def fetch(self, url, maximum):
        if "old.example" in url:
            started.set()
            await asyncio.sleep(10)
        return await native(self, url, maximum)

    monkeypatch.setattr(_Fetcher, "async_fetch_bounded", fetch)
    if cancel:
        task = asyncio.create_task(reader.async_rebuild_history(_DOMAIN))
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(VerificationError) as error:
            with verification_budget(0.02):
                await reader.async_rebuild_history(_DOMAIN)
        assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
    assert not reader._history_cache
    monkeypatch.setattr(_Fetcher, "async_fetch_bounded", native)
    assert len(await reader.async_rebuild_history(_DOMAIN)) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("native_previous", [False, True])
@pytest.mark.parametrize("valid", [False, True])
async def test_other_log_methods_keep_exact_cutoff_and_optional_async(native, native_previous, valid):
    from dnsid.c2sp_tlog import parse_c2sp_event_entry
    from dnsid.interfaces import NoopLogReader
    from dnsid.models import VerifiedCutoffHistory

    logs = _Logs.create()
    old = logs.issuance("old")
    issuance = parse_c2sp_event_entry(logs.entries[old][0])
    destination = logs.migration("new", "other:history", 0, final_ref="other:cutoff")
    registry, _ = logs.registry()
    main_thread = threading.get_ident()

    class Other(NoopLogReader):
        def rebuild_history_through(self, domain, final_ref, key, **limits):
            assert not native_previous
            assert threading.get_ident() != main_thread
            return self.result(domain, final_ref, key, limits)

        def result(self, domain, final_ref, key, limits):
            assert domain == _DOMAIN and final_ref == "other:cutoff"
            assert key.thumbprint() == logs.entity_key.thumbprint()
            assert destination in limits["seen_log_references"]
            return VerifiedCutoffHistory([issuance], [final_ref if valid else "other:wrong"], 1)

    other = Other("other")
    if native_previous:
        async def cutoff(domain, final_ref, key, **limits):
            assert threading.get_ident() == main_thread
            return other.result(domain, final_ref, key, limits)
        other.async_rebuild_history_through = cutoff
    registry.register("other", lambda lr: other)
    reader = registry.new_reader(destination)
    reader._options.entity_key = logs.entity_key
    if valid:
        assert len(await reader.async_rebuild_history(_DOMAIN)) == 2
    else:
        with pytest.raises(VerificationError, match="exact cutoff or bounds"):
            await reader.async_rebuild_history(_DOMAIN)


@pytest.mark.asyncio
async def test_cancelled_atomic_store_work_remains_tracked(native):
    from dnsid._verification_budget import async_wait_for_verification, verification_work_context

    started, release = threading.Event(), threading.Event()
    main_thread = threading.get_ident()

    class Store(InMemoryCheckpointStore):
        def verify_and_advance(self, candidate, verify):
            assert threading.get_ident() != main_thread
            started.set()
            assert release.wait(2)
            super().verify_and_advance(candidate, verify)

    logs = _Logs.create()
    reader, _ = _reader(logs, logs.issuance("first"))
    reader._options.checkpoint_store = Store()
    tracked = []
    context = verification_work_context(tracked.append)
    task = context.run(asyncio.create_task, reader.async_rebuild_history(_DOMAIN))
    try:
        async with asyncio.timeout(2):
            while not started.is_set():
                await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert sum(not future.done() for future in tracked) == 1
        assert not reader._history_cache
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        for future in tracked:
            await async_wait_for_verification(future)
    assert reader._options.checkpoint_store.get(reader.parsed.origin).tree_size == 1


@pytest.mark.asyncio
async def test_checkpoint_authentication_precedes_tile_fetch(native):
    logs = _Logs.create()
    reader, fetcher = _reader(logs, logs.issuance("first"))
    url = reader.parsed.log_prefix + "/checkpoint"
    fetcher.resources[url] = fetcher.resources[url].replace(b"first.example\n", b"other.example\n", 1)
    with pytest.raises(VerificationError):
        await reader.async_rebuild_history(_DOMAIN)
    assert fetcher.calls == [url]
    assert not reader._history_cache


@pytest.mark.asyncio
async def test_expired_bundle_cache_is_reloaded(native):
    logs = _Logs.create()
    destination = logs.issuance("first")
    reader, fetcher = _reader(logs, destination, bundles=True)
    await reader.async_preload_history(_DOMAIN, logs.entity_key)
    key, history = next(iter(reader._history_cache.items()))
    reader._history_cache[key] = dataclasses.replace(history, evidence_expires_at=_NOW)
    await reader.async_rebuild_history(_DOMAIN)
    assert len(fetcher.calls) == 2
