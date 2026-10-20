"""Pool dependencies, zero-TTL concurrency, and CPU work must not block async callers."""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch

import pytest

from dnsid import VerificationCode, VerificationError
from dnsid._verification_budget import async_wait_for_verification
from dnsid.c2sp_tlog._async import async_run_verification
from tests.test_async_cold_verification import native as native
from tests.test_verification_lifecycle import _started
from tests.test_verification_lifecycle import verifier as verifier


@pytest.mark.asyncio
async def test_sync_refresh_does_not_occupy_worker_needed_by_older_lookup(verifier):
    manager, _, _, domain = verifier
    cached = manager.verify_domain(domain)
    manager.evict_domain(domain)
    entered, release = asyncio.Event(), asyncio.Event()

    async def cold(*args, **kwargs):
        entered.set()
        await release.wait()
        return await manager._async_run_blocking(lambda: cached)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with (
            patch.object(manager, "_verification_executor", pool),
            patch.object(manager, "_async_verify_domain_uncached", side_effect=cold),
            patch.object(manager, "_verify_domain_uncached", return_value=cached),
        ):
            lookup = asyncio.create_task(manager.async_verify_domain(domain))
            await entered.wait()
            refresh = asyncio.create_task(asyncio.to_thread(manager.refresh_domain, domain))
            try:
                while domain not in manager._refresh_futures:
                    await asyncio.sleep(0)
                release.set()
                assert await asyncio.wait_for(asyncio.gather(lookup, refresh), .5) == [cached, cached]
            finally:
                release.set()
                # Settle the old lookup if the regression left the sole worker waiting for it.
                future = manager._verification_futures.get(domain)
                if future is not None and not future.done():
                    manager._finish_verification(domain, manager._verification_futures, future, cached)
                await asyncio.gather(lookup, refresh, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("refresh", [False, True])
async def test_zero_ttl_followers_acquire_concurrently_and_drain_after_cancellation(verifier, refresh):
    manager, _, _, domain = verifier
    cached = manager.verify_domain(domain)
    manager.evict_domain(domain)
    entered, release = asyncio.Event(), asyncio.Event()
    reads = 0

    async def cold(*args, **kwargs):
        nonlocal reads
        reads += 1
        if reads > 1:
            if reads == 8:
                entered.set()
            await release.wait()
        return replace(cached, dns_ttl=0)

    method = manager.async_refresh_domain if refresh else manager.async_verify_domain
    with patch.object(manager, "_async_verify_domain_uncached", side_effect=cold):
        calls = [asyncio.create_task(method(domain)) for _ in range(8)]
        try:
            await asyncio.wait_for(entered.wait(), .5)
            for call in calls:
                if not call.done():
                    call.cancel()
            await asyncio.gather(*calls, return_exceptions=True)
            shutdown = asyncio.create_task(manager.aclose())
            await asyncio.sleep(0)
            assert not shutdown.done()
        finally:
            release.set()
            await asyncio.gather(*calls, return_exceptions=True)
            await manager.aclose()
        await shutdown
    assert reads == 8
    assert not manager._verification_workers


@pytest.mark.asyncio
async def test_async_driver_runs_validation_off_loop_and_resolves_on_loop():
    loop_thread = threading.get_ident()
    started, release = threading.Event(), threading.Event()
    observed = []

    def steps():
        observed.append(threading.get_ident())
        started.set()
        assert release.wait(2)
        value = yield "read"
        observed.append(threading.get_ident())
        return value

    async def resolve(value):
        assert threading.get_ident() == loop_thread
        assert value == "read"
        return "verified"

    task = asyncio.create_task(async_run_verification(steps(), resolve))
    try:
        await asyncio.wait_for(_started(started), .5)
        assert not task.done()
    finally:
        release.set()
    assert await task == "verified"
    assert all(thread != loop_thread for thread in observed)


@pytest.mark.asyncio
async def test_cancelled_async_driver_closes_generator_only_after_worker_finishes():
    started, release, closed = threading.Event(), threading.Event(), threading.Event()

    def steps():
        try:
            started.set()
            assert release.wait(2)
            yield "unused"
        finally:
            closed.set()

    task = asyncio.create_task(async_run_verification(steps(), None))
    try:
        await asyncio.wait_for(_started(started), .5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not closed.is_set()
    finally:
        release.set()
    await _started(closed)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["active", "zero-ttl", "error"])
async def test_status_cache_miss_joins_refresh_without_holding_a_worker(verifier, outcome):
    from concurrent.futures import Future

    manager, _, _, domain = verifier
    cached = manager.verify_domain(domain)
    manager.evict_domain(domain)
    refresh = Future()
    manager._refresh_futures[domain] = refresh
    entered = threading.Event()
    original = manager._refresh_status

    def status():
        entered.set()
        return original(domain, cached)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with (
            patch.object(manager, "_verification_executor", pool),
            patch.object(manager, "_verify_domain_uncached", return_value=cached) as read,
        ):
            call = asyncio.create_task(asyncio.to_thread(
                manager._coalesce, domain, manager._status_futures, status,
            ))
            try:
                await _started(entered)
                assert await asyncio.wait_for(
                    async_wait_for_verification(pool.submit(lambda: "free")), .5,
                ) == "free"
            finally:
                value = (VerificationError(VerificationCode.LOG_ERROR, "failed")
                         if outcome == "error" else
                         replace(cached, dns_ttl=0) if outcome == "zero-ttl" else cached)
                manager._finish_verification(domain, manager._refresh_futures, refresh, value)
                results = await asyncio.gather(call, return_exceptions=True)
            if outcome == "error":
                assert results == [value]
            else:
                assert results == [cached]
            assert read.call_count == (outcome == "zero-ttl")
    assert not manager._status_futures


@pytest.mark.asyncio
@pytest.mark.parametrize("warm", [False, True])
async def test_private_retry_cannot_replace_or_populate_shared_cache(native, warm):
    from tests.test_c2sp_migration import _DOMAIN

    manager = native.manager
    cached = await manager.async_verify_domain(_DOMAIN)
    if not warm:
        manager.evict_domain(_DOMAIN)
    fresh = await manager._async_independent_verification(_DOMAIN, revalidate=True)
    assert fresh is not cached
    assert fresh.dns_ttl > 0
    assert manager._cache.get(_DOMAIN) is (cached if warm else None)
