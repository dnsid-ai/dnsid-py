"""Native status refreshes share work and retain per-caller verification checks."""

import asyncio
import datetime
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dnsid import (
    AsyncHTTPSFetcher,
    HTTPSFetcher,
    TrustedEntity,
    remaining_seconds,
    verification_budget,
)
from dnsid._verification_budget import wait_for_verification
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.models import TLSCertificate
from tests.test_verification_coalescing import _manager_fixture

_ACTIVE = {"state": "ACTIVE", "lastTransitionAt": "2026-10-14T00:00:00Z"}


@pytest.fixture
def warmed(ec_pair):
    manager, _, counters, domain, keys, status, active = _manager_fixture(
        ec_pair, mtls=True, interval=datetime.timedelta(0)
    )
    cert = TLSCertificate(san_dns_names=[domain])
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
        patch("dnsid.manager.async_fetch_jwks", side_effect=keys),
    ):
        cached = manager.verify_domain(domain, peer_cert=cert)
        yield manager, counters, domain, cert, cached, active


@pytest.mark.asyncio
async def test_native_refresh_coalesces_and_needs_no_workers(warmed):
    manager, counters, domain, cert, cached, _ = warmed
    started, release = asyncio.Event(), asyncio.Event()
    requests = []

    async def handle(request):
        requests.append(request)
        started.set()
        await release.wait()
        return httpx.Response(200, json=_ACTIVE)

    with (
        patch("dnsid.manager.make_ssrf_safe_async_transport",
              side_effect=lambda config: httpx.MockTransport(handle)),
        patch.object(asyncio.get_running_loop(), "run_in_executor",
                     side_effect=AssertionError("unexpected worker")),
    ):
        calls = [asyncio.create_task(manager.async_verify_domain(domain, peer_cert=cert))
                 for _ in range(32)]
        await asyncio.wait_for(started.wait(), 2)
        try:
            assert len(requests) == 1
            assert manager._cache.get(domain) is cached
        finally:
            release.set()
        results = await asyncio.gather(*calls)
    assert all(result is results[0] for result in results)
    assert results[0] is not cached
    assert counters["dns"] == 1
    assert not manager._status_futures
    assert not manager._async_verification_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", [False, True])
async def test_cancelled_or_expired_waiter_leaves_refresh_for_sync_caller(warmed, deadline):
    manager, _, domain, cert, _, _ = warmed
    started, release = asyncio.Event(), asyncio.Event()
    sync_waiting = threading.Event()

    async def handle(request):
        started.set()
        await release.wait()
        return httpx.Response(200, json=_ACTIVE)

    async def lead():
        with verification_budget(0.05 if deadline else 2):
            return await manager.async_verify_domain(domain, peer_cert=cert)

    with patch("dnsid.manager.make_ssrf_safe_async_transport",
               side_effect=lambda config: httpx.MockTransport(handle)):
        # A short-budget follower must not shorten the shared leader's budget.
        leader = asyncio.create_task(manager.async_verify_domain(domain, peer_cert=cert))
        await asyncio.wait_for(started.wait(), 2)
        follower = asyncio.create_task(lead())

        def wait(future):
            sync_waiting.set()
            return wait_for_verification(future)

        with patch("dnsid.manager.wait_for_verification", side_effect=wait):
            sync_call = asyncio.create_task(asyncio.to_thread(manager.verify_domain, domain, cert))
            try:
                async with asyncio.timeout(2):
                    while not sync_waiting.is_set():
                        await asyncio.sleep(0)
                if deadline:
                    with pytest.raises(VerificationError, match="deadline"):
                        await follower
                else:
                    follower.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await follower
                    leader.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await leader
                assert not manager._status_futures[domain].cancelled()
            finally:
                release.set()
            sync_result = await sync_call
            if deadline:
                assert await leader is sync_result
    assert sync_result.domain == domain
    assert not manager._status_futures


@pytest.mark.asyncio
@pytest.mark.parametrize("document,expected,evicted", [
    ({"state": "REVOKED", "revocationReason": "keyCompromise"}, VerificationCode.STATUS_NOT_ACTIVE, True),
    ({"state": "unknown"}, VerificationCode.RECORD_INVALID, False),
    (None, VerificationCode.STATUS_UNAVAILABLE, False),
])
async def test_refresh_failure_is_shared_and_later_calls_retry(warmed, document, expected, evicted):
    manager, _, domain, cert, _, _ = warmed
    started, release = asyncio.Event(), asyncio.Event()

    async def handle(request):
        started.set()
        await release.wait()
        return httpx.Response(503) if document is None else httpx.Response(200, json={**_ACTIVE, **document})

    with patch("dnsid.manager.make_ssrf_safe_async_transport",
               side_effect=lambda config: httpx.MockTransport(handle)):
        calls = [asyncio.create_task(manager.async_verify_domain(domain, peer_cert=cert))
                 for _ in range(2)]
        await asyncio.wait_for(started.wait(), 2)
        release.set()
        results = await asyncio.gather(*calls, return_exceptions=True)
    assert all(isinstance(error, VerificationError) and error.code == expected for error in results)
    assert (manager._cache.get(domain) is None) is evicted
    assert not manager._status_futures
    # A retry must run again, not remain attached to the failed future.
    with patch("dnsid.manager.make_ssrf_safe_async_transport",
               side_effect=lambda config: httpx.MockTransport(
                   lambda request: httpx.Response(200, json=_ACTIVE)
               )):
        assert (await manager.async_verify_domain(domain, peer_cert=cert)).domain == domain


@pytest.mark.asyncio
async def test_refresh_keeps_peer_binding_and_acceptance_per_caller(warmed):
    manager, _, domain, cert, _, _ = warmed
    with patch("dnsid.manager.make_ssrf_safe_async_transport",
               side_effect=lambda config: httpx.MockTransport(
                   lambda request: httpx.Response(200, json=_ACTIVE)
               )):
        results = await asyncio.gather(
            manager.async_verify_domain(domain, peer_cert=cert),
            manager.async_verify_domain(domain), return_exceptions=True,
        )
        assert results[0].domain == domain
        assert isinstance(results[1], VerificationError)
        manager._config.verification.trusted_entities = [TrustedEntity(governance_id="other.test")]
        with pytest.raises(VerificationError) as error:
            await manager.async_verify_domain(domain, peer_cert=cert)
        assert error.value.code == VerificationCode.COUNTERPARTY_NOT_ACCEPTED


@pytest.mark.asyncio
async def test_expired_dns_during_refresh_leadership_uses_cold_verification(warmed):
    manager, counters, domain, cert, _, _ = warmed
    original = manager._async_refresh_status

    async def expire(*args):
        manager.evict_domain(domain)
        return await original(*args)

    with (
        patch.object(manager, "_async_refresh_status", side_effect=expire),
        patch("dnsid.manager.async_fetch_agent_status",
              side_effect=lambda su, **kwargs: manager._fetch_status(su)),
    ):
        assert (await manager.async_verify_domain(domain, peer_cert=cert)).domain == domain
    assert counters["dns"] == 2


@pytest.mark.asyncio
async def test_injected_sync_fetcher_stays_off_the_event_loop(warmed):
    manager, _, domain, cert, _, _ = warmed
    started, release = threading.Event(), threading.Event()
    manager._https_fetcher = MagicMock(spec=HTTPSFetcher)

    def fetch(*args):
        started.set()
        assert release.wait(2)
        return _ACTIVE, None

    manager._https_fetcher.fetch_strict_json.side_effect = fetch
    task = asyncio.create_task(manager.async_verify_domain(domain, peer_cert=cert))
    try:
        async with asyncio.timeout(2):
            while not started.is_set():
                await asyncio.sleep(0)
    finally:
        release.set()
    assert (await task).domain == domain


@pytest.mark.asyncio
async def test_cancelled_native_task_closes_transport_and_removes_shared_future(warmed):
    manager, _, domain, cert, _, _ = warmed
    started = asyncio.Event()

    async def handle(request):
        started.set()
        await asyncio.sleep(10)

    transport = httpx.MockTransport(handle)
    with (
        patch("dnsid.manager.make_ssrf_safe_async_transport", return_value=transport),
        patch.object(transport, "aclose", wraps=transport.aclose) as close,
    ):
        call = asyncio.create_task(manager.async_verify_domain(domain, peer_cert=cert))
        await asyncio.wait_for(started.wait(), 2)
        next(iter(manager._async_verification_tasks)).cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        assert not manager._status_futures
        assert not manager._async_verification_tasks
        close.assert_awaited_once()


@pytest.mark.asyncio
async def test_task_submission_failure_cleans_up_and_can_retry(warmed):
    manager, _, domain, cert, _, _ = warmed
    with patch("dnsid.manager.asyncio.create_task", side_effect=RuntimeError("task rejected")):
        with pytest.raises(RuntimeError, match="task rejected"):
            await manager.async_verify_domain(domain, peer_cert=cert)
    assert not manager._status_futures
    with patch("dnsid.manager.make_ssrf_safe_async_transport",
               side_effect=lambda config: httpx.MockTransport(
                   lambda request: httpx.Response(200, json=_ACTIVE)
               )):
        assert (await manager.async_verify_domain(domain, peer_cert=cert)).domain == domain


class DualFetcher(HTTPSFetcher):
    def fetch_strict_json(self, url, allowed_host=None, domain_boundary=False):
        raise AssertionError("unexpected synchronous fetch")

    async def async_fetch_strict_json(self, url, allowed_host=None, domain_boundary=False):
        return _ACTIVE, TLSCertificate()


@pytest.mark.asyncio
async def test_injected_async_fetcher_shares_work_without_workers(warmed):
    manager, counters, domain, cert, cached, _ = warmed
    fetcher = DualFetcher()
    assert isinstance(fetcher, AsyncHTTPSFetcher)
    manager._https_fetcher = fetcher
    started, release = asyncio.Event(), asyncio.Event()

    async def fetch(url):
        assert url == cached.record.su
        started.set()
        await release.wait()
        return _ACTIVE, TLSCertificate()

    with (
        patch.object(fetcher, "async_fetch_strict_json", side_effect=fetch) as request,
        patch.object(manager, "_submit_verification", side_effect=AssertionError("unexpected worker")),
        patch("dnsid.manager.make_ssrf_safe_async_transport",
              side_effect=AssertionError("unexpected default transport")),
    ):
        leader = asyncio.create_task(manager.async_verify_domain(domain, peer_cert=cert))
        await asyncio.wait_for(started.wait(), 2)
        follower = asyncio.create_task(manager.async_verify_domain(domain, peer_cert=cert))
        await asyncio.sleep(0)
        leader.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await leader
            assert not manager._status_futures[domain].cancelled()
        finally:
            release.set()
        result = await follower
        request.assert_awaited_once_with(cached.record.su)
    assert result is not cached
    assert counters["dns"] == 1
    assert not manager._status_futures


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome,expected,evicted", [
    ({"state": "REVOKED", "revocationReason": "keyCompromise"},
     VerificationCode.STATUS_NOT_ACTIVE, True),
    ({"state": "unknown"}, VerificationCode.RECORD_INVALID, False),
    (VerificationError(VerificationCode.DNS_RESOLUTION, "network"),
     VerificationCode.STATUS_UNAVAILABLE, False),
    (VerificationError(VerificationCode.TLS_ERROR, "blocked", transient=False),
     VerificationCode.TLS_ERROR, False),
    (VerificationError(VerificationCode.DEADLINE_EXCEEDED, "deadline", transient=True),
     VerificationCode.DEADLINE_EXCEEDED, False),
])
async def test_injected_async_fetcher_keeps_error_mapping(warmed, outcome, expected, evicted):
    manager, _, domain, cert, _, _ = warmed
    fetcher = DualFetcher()
    manager._https_fetcher = fetcher
    kwargs = (
        {"side_effect": outcome} if isinstance(outcome, Exception)
        else {"return_value": ({**_ACTIVE, **outcome}, TLSCertificate())}
    )
    with patch.object(fetcher, "async_fetch_strict_json", **kwargs):
        with pytest.raises(VerificationError) as error:
            await manager.async_verify_domain(domain, peer_cert=cert)
    assert error.value.code == expected
    assert (manager._cache.get(domain) is None) is evicted
    assert not manager._status_futures
    if not evicted:
        assert (await manager.async_verify_domain(domain, peer_cert=cert)).domain == domain


@pytest.mark.asyncio
async def test_injected_async_fetcher_deadline_and_shutdown_ownership(warmed):
    manager, _, domain, cert, cached, _ = warmed
    fetcher = DualFetcher()
    manager._https_fetcher = fetcher
    close = AsyncMock()

    async def fetch(url):
        assert 0 < remaining_seconds() <= 0.05
        await asyncio.sleep(1)
        raise AssertionError("adapter was not cancelled")

    with (
        patch.object(fetcher, "aclose", close, create=True),
        patch.object(fetcher, "async_fetch_strict_json", side_effect=fetch),
    ):
        with pytest.raises(VerificationError) as error:
            with verification_budget(0.05):
                await manager._async_refresh_status(domain, cached)
        assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        assert manager._cache.get(domain) is cached
        await manager.aclose()
    close.assert_not_awaited()


def test_dual_fetcher_keeps_synchronous_status_path(warmed):
    manager, _, domain, cert, cached, _ = warmed
    fetcher = DualFetcher()
    manager._https_fetcher = fetcher
    with (
        patch.object(fetcher, "fetch_strict_json", return_value=(_ACTIVE, TLSCertificate())) as request,
        patch.object(fetcher, "async_fetch_strict_json",
                     side_effect=AssertionError("unexpected async fetch")),
    ):
        assert manager.verify_domain(domain, peer_cert=cert).domain == domain
    request.assert_called_once_with(cached.record.su)
