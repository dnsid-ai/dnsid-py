"""Shared async work has bounded retry depth and worker capacity."""

import asyncio
import contextvars
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch

import pytest

from dnsid import VerificationCode, VerificationError, verification_budget
from dnsid._verification_budget import (
    async_run_blocking,
    async_wait_for_verification,
    verification_work_context,
)
from tests.test_verification_lifecycle import _started
from tests.test_verification_lifecycle import verifier as verifier


@pytest.mark.asyncio
async def test_large_zero_ttl_burst_does_not_grow_the_retry_stack(verifier):
    manager, _, _, domain = verifier
    cached = manager.verify_domain(domain)
    manager.evict_domain(domain)

    async def cold(domain):
        await asyncio.sleep(0)
        return replace(cached, dns_ttl=0)

    with patch.object(manager, "_async_verify_domain_uncached", side_effect=cold) as read:
        results = await asyncio.gather(*(manager.async_verify_domain(domain) for _ in range(600)))
    assert read.await_count == len(results) == len({id(result) for result in results})
    assert manager._cache.get(domain) is None
    assert not manager._verification_futures


@pytest.mark.asyncio
async def test_status_refresh_retries_zero_ttl_without_joining_its_own_future(verifier):
    manager, _, _, domain = verifier
    cached = manager.verify_domain(domain)
    manager.evict_domain(domain)
    previous = Future()
    with (
        patch.dict(manager._verification_futures, {domain: previous}),
        patch.dict(manager._status_futures, {domain: Future()}),
        patch.object(manager, "_async_verify_domain_uncached",
                     return_value=replace(cached, dns_ttl=0)) as read,
    ):
        call = asyncio.create_task(manager._async_refresh_status(domain, cached))
        await asyncio.sleep(0)
        manager._finish_verification(
            domain, manager._verification_futures, previous, replace(cached, dns_ttl=0),
        )
        assert (await asyncio.wait_for(call, 1)).dns_ttl == 0
        read.assert_awaited_once_with(domain)


@pytest.mark.asyncio
async def test_blocking_work_reuses_bounded_pool_and_survives_caller_cancellation():
    trace = contextvars.ContextVar("trace")
    started, release = threading.Event(), threading.Event()
    tracked, observations = [], []

    def block():
        observations.append((threading.get_ident(), trace.get()))
        started.set()
        assert release.wait(5)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with (
            patch("dnsid._verification_budget._blocking_executor", pool, create=True),
            patch("dnsid._verification_budget.ThreadPoolExecutor",
                  side_effect=AssertionError("per-call executor")),
        ):
            trace.set("caller")
            context = verification_work_context(tracked.append)
            first = asyncio.create_task(async_run_blocking(block), context=context.copy())
            try:
                await _started(started)
                second = asyncio.create_task(async_run_blocking(block), context=context.copy())
                await asyncio.sleep(0)
                assert len(tracked) == 2
                assert len(observations) == 1
                first.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await first
                assert not tracked[0].done()
            finally:
                release.set()
            await second
            await async_wait_for_verification(tracked[0])
    assert len({thread for thread, _ in observations}) == 1
    assert [value for _, value in observations] == ["caller", "caller"]


@pytest.mark.asyncio
async def test_queued_blocking_work_checks_budget_before_starting():
    started, release = threading.Event(), threading.Event()
    ran, tracked = [], []

    def occupy():
        started.set()
        assert release.wait(5)

    async def queued():
        with verification_budget(0.02):
            return await async_run_blocking(lambda: ran.append(True))

    with ThreadPoolExecutor(max_workers=1) as pool:
        with patch("dnsid._verification_budget._blocking_executor", pool, create=True):
            blocker = pool.submit(occupy)
            try:
                await _started(started)
                caller = asyncio.create_task(queued(), context=verification_work_context(tracked.append))
                await asyncio.sleep(0.04)
            finally:
                release.set()
            with pytest.raises(VerificationError) as error:
                await caller
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
            blocker.result()
    assert len(tracked) == 1 and tracked[0].done()
    assert not ran
