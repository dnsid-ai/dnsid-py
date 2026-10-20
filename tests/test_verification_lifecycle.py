"""Owned verification work has independent deadlines and drains before shutdown."""

import asyncio
import contextvars
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from dnsid import JWKS, HTTPSFetcher, VerificationCode, remaining_seconds, verification_budget
from dnsid.exceptions import VerificationError
from tests.test_verification_coalescing import _manager_fixture

_ACTIVE = {"state": "ACTIVE", "lastTransitionAt": "2026-10-14T00:00:00Z"}


async def _started(event):
    async with asyncio.timeout(2):
        while not event.is_set():
            await asyncio.sleep(0)


@pytest_asyncio.fixture
async def verifier(ec_pair):
    manager, resolver, counters, domain, keys, status, _ = _manager_fixture(
        ec_pair, interval=datetime.timedelta(0)
    )
    with (
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
        patch("dnsid.manager.async_fetch_jwks", side_effect=keys),
    ):
        async with manager:
            yield manager, resolver, counters, domain


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["cold", "native", "injected"])
async def test_short_async_leader_cannot_shorten_followers_deadline(verifier, mode):
    manager, resolver, counters, domain = verifier
    trace = contextvars.ContextVar("request_trace", default=None)
    observed = []
    started, release = threading.Event(), threading.Event()
    native_release = asyncio.Event()

    if mode != "cold":
        manager.verify_domain(domain)

    def fetch(*args, **kwargs):
        observed.append((trace.get(), remaining_seconds()))
        started.set()
        assert release.wait(2)
        return _ACTIVE, None

    async def handle(request):
        observed.append((trace.get(), remaining_seconds()))
        started.set()
        await native_release.wait()
        return httpx.Response(200, json=_ACTIVE)

    if mode == "cold":
        resolver.started, resolver.release = started, release
    elif mode == "injected":
        manager._https_fetcher = MagicMock(spec=HTTPSFetcher)
        manager._https_fetcher.fetch_strict_json.side_effect = fetch

    async def short_call():
        trace.set("leader")
        with verification_budget(0.03):
            return await manager.async_verify_domain(domain)

    with patch("dnsid.manager.make_ssrf_safe_async_transport",
               side_effect=lambda config: httpx.MockTransport(handle)):
        leader = asyncio.create_task(short_call())
        await _started(started)
        follower = asyncio.create_task(manager.async_verify_domain(domain))
        try:
            with pytest.raises(VerificationError) as error:
                await leader
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
            assert error.value.transient
            assert not follower.done()
        finally:
            release.set()
            native_release.set()
        assert (await follower).domain == domain
    if observed:
        assert observed[0][0] == "leader"
        assert 0.03 < observed[0][1] <= 30
    assert counters["dns"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("warm", [False, True])
async def test_short_sync_leader_cannot_shorten_async_followers_deadline(verifier, warm):
    manager, resolver, counters, domain = verifier
    started, release = threading.Event(), threading.Event()
    if warm:
        manager.verify_domain(domain)

    def status(*args, **kwargs):
        started.set()
        assert release.wait(2)
        from dnsid.models import AgentStatus
        return AgentStatus(state="ACTIVE", last_transition_at=datetime.datetime.now(datetime.UTC))

    if not warm:
        resolver.started, resolver.release = started, release

    def short_call():
        with verification_budget(0.03):
            return manager.verify_domain(domain)

    with patch("dnsid.manager._fetch_strict_json_status", side_effect=status):
        leader = asyncio.create_task(asyncio.to_thread(short_call))
        await _started(started)
        follower = asyncio.create_task(manager.async_verify_domain(domain))
        try:
            with pytest.raises(VerificationError) as error:
                await leader
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
            assert not follower.done()
        finally:
            release.set()
        assert (await follower).domain == domain
    assert counters["dns"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("warm", [False, True])
async def test_status_deadline_errors_are_not_reclassified_as_unavailable(verifier, warm):
    manager, _, _, domain = verifier
    if warm:
        manager.verify_domain(domain)
    failure = VerificationError(VerificationCode.DEADLINE_EXCEEDED, "status deadline", transient=True)
    target = "dnsid.manager.async_fetch_agent_status"
    with patch(target, side_effect=failure):
        with pytest.raises(VerificationError) as error:
            await manager.async_verify_domain(domain)
    assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
    assert error.value.transient


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_aclose_drains_cancelled_cold_work_and_rejects_new_calls(verifier, fails):
    manager, _, _, domain = verifier
    started, release = threading.Event(), threading.Event()
    original = manager._async_verify_domain_uncached

    async def cold(domain):
        started.set()
        assert await asyncio.to_thread(release.wait, 2)
        if fails:
            raise VerificationError(VerificationCode.DNS_RESOLUTION, "late failure", transient=True)
        return await original(domain)

    with (
        patch.object(manager, "_async_verify_domain_uncached", side_effect=cold),
        patch("dnsid.manager.async_fetch_agent_status",
              side_effect=lambda su, **kwargs: manager._fetch_status(su)),
        patch.object(manager._http_client, "close", wraps=manager._http_client.close) as close,
    ):
        call = asyncio.create_task(manager.async_verify_domain(domain))
        await _started(started)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        with pytest.raises(RuntimeError, match="await aclose"):
            manager.close()
        shutdown = asyncio.create_task(manager.aclose())
        try:
            await asyncio.sleep(0)
            assert not shutdown.done()
            close.assert_not_called()
            with pytest.raises(RuntimeError, match="closing"):
                await manager.async_verify_domain(domain)
            with pytest.raises(RuntimeError, match="closing"):
                manager.verify_domain(domain)
        finally:
            release.set()
        await shutdown
        await manager.aclose()
        close.assert_called_once()
        assert not manager._verification_futures
        with pytest.raises(RuntimeError, match="closed"):
            async with manager:
                pass


@pytest.mark.asyncio
async def test_aclose_drains_native_refresh_even_if_shutdown_wait_is_cancelled(verifier):
    manager, _, _, domain = verifier
    manager.verify_domain(domain)
    started, release = asyncio.Event(), asyncio.Event()

    async def handle(request):
        started.set()
        await release.wait()
        return httpx.Response(200, json=_ACTIVE)

    transport = httpx.MockTransport(handle)
    with (
        patch("dnsid.manager.make_ssrf_safe_async_transport", return_value=transport),
        patch.object(transport, "aclose", wraps=transport.aclose) as close,
    ):
        call = asyncio.create_task(manager.async_verify_domain(domain))
        await asyncio.wait_for(started.wait(), 2)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        shutdown = asyncio.create_task(manager.aclose())
        await asyncio.sleep(0)
        shutdown.cancel()
        with pytest.raises(asyncio.CancelledError):
            await shutdown
        assert manager._closing and not manager._closed
        close.assert_not_awaited()
        assert not next(iter(manager._status_futures.values())).cancelled()
        release.set()
        await manager.aclose()
        close.assert_awaited_once()
        assert manager._http_client.is_closed


@pytest.mark.asyncio
async def test_aclose_drains_abandoned_status_branch_after_identity_failure(verifier, ec_pair):
    manager, _, _, domain = verifier
    started, release = threading.Event(), threading.Event()
    _, entity_key = ec_pair

    def keys(uri, allowed_host, **kwargs):
        if uri.startswith(f"https://{domain}/"):
            assert started.wait(2)
        return JWKS(keys=[entity_key]), None

    def status(*args, **kwargs):
        started.set()
        assert release.wait(2)
        remaining_seconds()

    async def async_keys(*args, **kwargs):
        return await manager._async_run_blocking(lambda: keys(*args, **kwargs))

    async def async_status(*args, **kwargs):
        return await manager._async_run_blocking(lambda: status(*args, **kwargs))

    with (
        patch.object(manager, "_async_fetch_key_set", side_effect=async_keys),
        patch.object(manager, "_async_fetch_status", side_effect=async_status),
    ):
        try:
            with pytest.raises(VerificationError) as error:
                await manager.async_verify_domain(domain)
            assert error.value.code == VerificationCode.RECORD_INVALID
            assert not manager._verification_futures
            shutdown = asyncio.create_task(manager.aclose())
            await asyncio.sleep(0)
            assert not shutdown.done()
            assert not manager._http_client.is_closed
        finally:
            release.set()
        await shutdown
    assert manager._http_client.is_closed


@pytest.mark.asyncio
async def test_cancelled_zero_ttl_followup_worker_is_drained(verifier):
    manager, resolver, counters, domain = verifier
    resolver.records[f"_dnsid.{domain}"].ttl = 0
    resolver.started, resolver.release = threading.Event(), threading.Event()
    started, release = threading.Event(), threading.Event()
    original, calls = manager._async_verify_domain_uncached, []

    async def cold(domain):
        calls.append(domain)
        if len(calls) == 2:
            started.set()
            assert await asyncio.to_thread(release.wait, 2)
        return await original(domain)

    with (
        patch.object(manager, "_async_verify_domain_uncached", side_effect=cold),
        patch("dnsid.manager.async_fetch_agent_status",
              side_effect=lambda su, **kwargs: manager._fetch_status(su)),
    ):
        leader = asyncio.create_task(manager.async_verify_domain(domain))
        await _started(resolver.started)
        follower = asyncio.create_task(manager.async_verify_domain(domain))
        await asyncio.sleep(0)
        resolver.release.set()
        await leader
        await _started(started)
        follower.cancel()
        with pytest.raises(asyncio.CancelledError):
            await follower
        shutdown = asyncio.create_task(manager.aclose())
        try:
            await asyncio.sleep(0)
            assert not shutdown.done()
            assert not manager._http_client.is_closed
        finally:
            release.set()
        await shutdown
    assert counters["dns"] == 2


def test_sync_context_exit_drains_work_after_a_wait_deadline(ec_pair):
    manager, resolver, _, domain, keys, status, _ = _manager_fixture(ec_pair)
    resolver.started, resolver.release = threading.Event(), threading.Event()
    with (
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        try:
            with pytest.raises(VerificationError) as error:
                with verification_budget(0.03):
                    manager.verify_domain(domain)
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
            shutdown = pool.submit(manager.close)
            assert not manager._http_client.is_closed
        finally:
            resolver.release.set()
        shutdown.result(timeout=2)
    assert manager._http_client.is_closed
    manager.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("warm", [False, True])
async def test_native_task_cancelled_before_start_does_not_leave_pending_future(verifier, warm):
    manager, _, _, domain = verifier
    if warm:
        manager.verify_domain(domain)
    create_task = asyncio.create_task

    def cancelled(coroutine, **kwargs):
        task = create_task(coroutine, **kwargs)
        task.cancel()
        return task

    with patch("dnsid.manager.asyncio.create_task", side_effect=cancelled):
        with pytest.raises(asyncio.CancelledError):
            await manager.async_verify_domain(domain)
    assert not manager._status_futures
    assert not manager._verification_futures
    assert not manager._async_verification_tasks
    await manager.aclose()
