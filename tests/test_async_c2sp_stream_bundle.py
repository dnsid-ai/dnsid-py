"""Async stream bundles retain bounded raw consistency fallback."""

import json
from dataclasses import replace

import pytest

from dnsid._utils import b64url_decode_strict
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError,
    C2spTlogError,
    Checkpoint,
    IndexedEntry,
    InMemoryCheckpointStore,
    StreamEvidence,
    merkle_root_from_entries,
    parse_c2sp_tlog_lr,
    parse_checkpoint,
)
from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource
from tests.test_c2sp_stream_bundle import _options, _seed_old_checkpoint, _vector


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["valid", "newer", "conflict", "short", "required", "trusted-fork"])
async def test_consistency_fallback_keeps_atomic_store_checks(mode):
    vector = _vector()
    bundle = json.loads(vector["bundle"])
    reference = parse_c2sp_tlog_lr(bundle["lr"])
    entries = [b64url_decode_strict(item["entry"]) for item in bundle["events"]]
    checkpoint = parse_checkpoint(b64url_decode_strict(bundle["checkpoint"]).decode())
    options = _options(vector)
    _seed_old_checkpoint(vector, options)
    if mode == "trusted-fork":
        trusted = options.checkpoint_store.get(reference.origin)
        options.checkpoint_store = InMemoryCheckpointStore()
        options.checkpoint_store.put(replace(trusted, root_hash=bytes(32)))
    trusted = options.checkpoint_store.get(reference.origin)
    raw = entries
    if mode == "newer":
        raw = [*entries, b"later entry"]
    elif mode == "conflict":
        raw = [entries[0], b"fork"]
    elif mode == "short":
        raw = entries[:1]

    class Fetcher:
        def fetch_bounded(self, *args):
            raise AssertionError("sync network")

        async def async_fetch_bounded(self, *args):
            return vector["bundle"].encode()

    class Fallback:
        calls = 0

        def load_stream(self, *args):
            raise AssertionError("sync network")

        async def async_load_stream(self, *args):
            self.calls += 1
            assert options.checkpoint_store.get(reference.origin) == trusted
            return StreamEvidence(
                checkpoint=Checkpoint(
                    origin=checkpoint.origin, tree_size=len(raw),
                    root_hash=merkle_root_from_entries(raw),
                ),
                entries=[IndexedEntry(index, entry) for index, entry in enumerate(raw)],
                complete=True,
            )

    fallback = Fallback()
    source = _FetchedStreamBundleSource(
        Fetcher(), fallback, policy_bytes=vector["policy"].encode(),
        bundle_keys=options.bundle_keys,
        checkpoint_freshness_ms=options.checkpoint_freshness_ms,
        max_bundle_lifetime_ms=options.max_bundle_lifetime_ms,
        max_bundle_bytes=options.max_bundle_bytes, max_events=options.max_events,
        checkpoint_store=options.checkpoint_store, require_bundle=mode == "required", now=options.now,
    )
    accounted = []
    if mode in ("valid", "newer"):
        verified = await source.async_load_verified_bundle(
            reference, bundle["fqdn"], options.entity_key, None, account_response=accounted.append,
        )
        assert verified.checkpoint == checkpoint
        assert options.checkpoint_store.get(reference.origin).tree_size == checkpoint.tree_size
        assert len(accounted) == 2
    else:
        with pytest.raises(C2spTlogError) as error:
            await source.async_load_verified_bundle(reference, bundle["fqdn"], options.entity_key, None)
        if mode == "trusted-fork":
            assert isinstance(error.value, C2spCheckpointConsistencyError)
            assert error.value.category == "LOG_INCONSISTENT"
        assert options.checkpoint_store.get(reference.origin) == trusted
    assert fallback.calls == (0 if mode == "required" else 1)
