"""Explicit async refresh retains sync coordination, revalidation, and policy."""

import asyncio
import datetime
import threading
from concurrent.futures import Future
from contextlib import nullcontext
from unittest.mock import MagicMock, patch

import httpx
import pytest

from dnsid import (
    TLSCertificate,
    TrustedEntity,
    VerificationCode,
    VerificationError,
    verification_budget,
)
from dnsid._utils import b64url_encode
from dnsid._verification_budget import async_wait_for_verification, wait_for_verification
from dnsid.manager import _now
from tests.test_async_cold_verification import _wait
from tests.test_async_cold_verification import native as native
from tests.test_c2sp_migration import _DOMAIN


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["async", "sync", "default"])
async def test_refresh_revalidates_all_http_evidence_and_replaces_cache(native, monkeypatch, mode):
    n = native
    calls = []
    answer = n.https.answer

    def fetch(url, allowed_host=None, domain_boundary=False, *, revalidate=False):
        calls.append((url, revalidate))
        return answer(url, allowed_host, domain_boundary, revalidate=revalidate)

    monkeypatch.setattr(n.https, "answer", fetch)
    if mode == "sync":
        monkeypatch.setattr(type(n.https), "async_fetch_strict_json", None)
    elif mode == "default":
        n.manager._https_fetcher = None

        def handle(request):
            url = str(request.url)
            data, _ = fetch(
                url, "example" if url == n.record.ek else _DOMAIN if url == n.record.ku else None,
                domain_boundary=(url == n.record.ek),
                revalidate=(request.headers.get("cache-control") == "no-cache"),
            )
            return httpx.Response(200, json=data)

        monkeypatch.setattr("dnsid.manager.make_ssrf_safe_async_transport",
                            lambda config: httpx.MockTransport(handle))
        monkeypatch.setattr("dnsid._https_client._extract_tls_cert", lambda response: n.cert)
    worker = MagicMock(wraps=n.manager._submit_verification) if mode == "sync" else MagicMock(
        side_effect=AssertionError("unexpected core worker")
    )
    monkeypatch.setattr(n.manager, "_submit_verification", worker)
    old = await n.manager.async_verify_domain(_DOMAIN)
    resources = {n.record.ek, n.record.ku, n.record.su}
    assert set(calls) == {(url, False) for url in resources}
    assert len(calls) == 3
    calls.clear()

    fresh = await n.manager.async_refresh_domain(_DOMAIN.upper() + ".")
    assert fresh is not old
    assert n.manager._cache.get(_DOMAIN) is fresh
    assert set(calls) == {(url, True) for url in resources}
    assert len(calls) == 3
    assert n.calls["dns"] == 2
    calls.clear()
    assert await n.manager.async_verify_domain(_DOMAIN) is fresh
    assert not calls
    n.manager._config.verification.status_check_interval = datetime.timedelta(0)
    await n.manager.async_verify_domain(_DOMAIN)
    assert calls == [(n.record.su, False)]
    assert bool(worker.call_count) == (mode == "sync")


@pytest.mark.asyncio
@pytest.mark.parametrize("lookup_outcome", ["active", "unavailable", "revoked"])
async def test_refresh_waits_for_ordinary_lookup_but_acquires_its_own_evidence(
    native, monkeypatch, lookup_outcome,
):
    n = native
    n.resolver.gate.clear()
    original_dns, answer = n.resolver.async_fetch_txt, n.https.answer
    lookup_waited = asyncio.Event()
    revalidations = []

    async def dns(name):
        result = await original_dns(name)
        if n.calls["dns"] == 1 and lookup_outcome == "unavailable":
            raise VerificationError(VerificationCode.DNS_RESOLUTION, "offline", transient=True)
        return result

    def fetch(url, *args, revalidate=False, **kwargs):
        revalidations.append(revalidate)
        data, cert = answer(url, *args, revalidate=revalidate, **kwargs)
        if url == n.record.su and not revalidate and lookup_outcome == "revoked":
            data = {**data, "state": "REVOKED", "revocationReason": "keyCompromise"}
        return data, cert

    async def wait(future):
        if future is n.manager._verification_futures.get(_DOMAIN):
            lookup_waited.set()
        return await async_wait_for_verification(future)

    monkeypatch.setattr(n.resolver, "async_fetch_txt", dns)
    monkeypatch.setattr(n.https, "answer", fetch)
    monkeypatch.setattr("dnsid.manager.async_wait_for_verification", wait)
    lookup = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
    try:
        await _wait(n.resolver.started)
        lookup_waited.clear()
        refresh = asyncio.create_task(n.manager.async_refresh_domain(_DOMAIN))
        await _wait(lookup_waited)
        other_refresh = asyncio.create_task(n.manager.async_refresh_domain(_DOMAIN))
        other_lookup = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
        await asyncio.sleep(0)
        assert not any(task.done() for task in (refresh, other_refresh, other_lookup))
    finally:
        n.resolver.gate.set()
    if lookup_outcome == "active":
        old = await lookup
    else:
        with pytest.raises(VerificationError):
            await lookup
    fresh = await refresh
    assert await other_refresh is fresh
    assert await other_lookup is fresh
    assert n.manager._cache.get(_DOMAIN) is fresh
    assert n.calls["dns"] == 2
    assert revalidations[-3:] == [True] * 3
    if lookup_outcome == "active":
        assert old is not fresh
        assert revalidations[:3] == [False] * 3


@pytest.mark.asyncio
@pytest.mark.parametrize("sync_leader", [False, True])
async def test_sync_and_async_refreshes_and_lookups_join_one_refresh(native, sync_leader):
    n = native
    gate = n.resolver.sync_gate if sync_leader else n.resolver.gate
    started = n.resolver.sync_started if sync_leader else n.resolver.started
    gate.clear()
    sync_waiting = threading.Event()

    def wait(future):
        if future is n.manager._refresh_futures.get(_DOMAIN):
            sync_waiting.set()
        return wait_for_verification(future)

    with patch("dnsid.manager.wait_for_verification", side_effect=wait):
        leader = asyncio.create_task(
            asyncio.to_thread(n.manager.refresh_domain, _DOMAIN) if sync_leader
            else n.manager.async_refresh_domain(_DOMAIN)
        )
        try:
            await _wait(started)
            sync_waiting.clear()
            with nullcontext() if sync_leader else patch.object(
                n.manager, "_submit_verification", side_effect=AssertionError("unexpected worker"),
            ):
                follower = asyncio.create_task(n.manager.async_refresh_domain(_DOMAIN))
                sync = asyncio.create_task(asyncio.to_thread(n.manager.refresh_domain, _DOMAIN))
                lookup = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
                await _wait(sync_waiting)
                assert not any(task.done() for task in (leader, follower, sync, lookup))
        finally:
            gate.set()
        fresh = await leader
        assert all(result is fresh for result in await asyncio.gather(follower, sync, lookup))
    assert n.calls["dns"] == 1
    assert not n.manager._refresh_futures


@pytest.mark.asyncio
@pytest.mark.parametrize("sync_leader", [False, True])
async def test_zero_ttl_refresh_followers_acquire_their_own_revalidated_evidence(
    native, monkeypatch, sync_leader,
):
    n = native
    n.resolver.ttl = 0
    gate = n.resolver.sync_gate if sync_leader else n.resolver.gate
    started = n.resolver.sync_started if sync_leader else n.resolver.started
    gate.clear()
    answer = n.https.answer
    revalidations = []

    def fetch(*args, revalidate=False, **kwargs):
        revalidations.append(revalidate)
        return answer(*args, revalidate=revalidate, **kwargs)

    monkeypatch.setattr(n.https, "answer", fetch)
    calls = [asyncio.create_task(
        asyncio.to_thread(n.manager.refresh_domain, _DOMAIN) if sync_leader
        else n.manager.async_refresh_domain(_DOMAIN)
    )]
    try:
        await _wait(started)
        monkeypatch.setattr(n.manager, "_submit_verification", MagicMock(
            side_effect=AssertionError("unexpected core worker"),
        ))
        calls.extend(asyncio.create_task(n.manager.async_refresh_domain(_DOMAIN)) for _ in range(2))
        await asyncio.sleep(0)
    finally:
        gate.set()
    results = await asyncio.gather(*calls)
    assert len({id(result) for result in results}) == 3
    assert n.calls["dns"] == 3
    assert revalidations == [True] * 9
    assert n.manager._cache.get(_DOMAIN) is None
    assert not n.manager._refresh_futures


@pytest.mark.asyncio
@pytest.mark.parametrize("revoked", [False, True])
async def test_failed_refresh_never_returns_or_extends_cached_evidence(native, monkeypatch, revoked):
    n = native
    old = await n.manager.async_verify_domain(_DOMAIN)
    expiry = old.expiry()
    answer = n.https.answer

    def fetch(url, *args, **kwargs):
        if not revoked and url == n.record.ek:
            raise VerificationError(VerificationCode.TLS_ERROR, "unavailable", transient=True)
        data, cert = answer(url, *args, **kwargs)
        return ({**data, "state": "REVOKED", "revocationReason": "keyCompromise"}, cert) if (
            revoked and url == n.record.su
        ) else (data, cert)

    with monkeypatch.context() as context:
        context.setattr(n.https, "answer", fetch)
        with pytest.raises(VerificationError) as error:
            await n.manager.async_refresh_domain(_DOMAIN)
    assert error.value.code == (
        VerificationCode.STATUS_NOT_ACTIVE if revoked else VerificationCode.TLS_ERROR
    )
    assert n.manager._cache.get(_DOMAIN) is (None if revoked else old)
    assert old.expiry() == expiry
    assert not n.manager._refresh_futures
    assert await n.manager.async_refresh_domain(_DOMAIN) is not old


@pytest.mark.asyncio
async def test_refresh_enforces_peer_and_acceptance_for_each_caller(native):
    n = native
    n.record.fl = "mtls"
    n.record.sg = b64url_encode(n.logs.entity_private.sign(n.record.canonical().encode("ascii")))
    n.resolver.gate.clear()
    allowed = asyncio.create_task(n.manager.async_refresh_domain(_DOMAIN, n.cert))
    denied = asyncio.create_task(n.manager.async_refresh_domain(
        _DOMAIN, TLSCertificate(san_dns_names=["wrong.example"]),
    ))
    try:
        await _wait(n.resolver.started)
    finally:
        n.resolver.gate.set()
    results = await asyncio.gather(allowed, denied, return_exceptions=True)
    assert results[0].domain == _DOMAIN
    assert isinstance(results[1], VerificationError)
    assert results[1].code == VerificationCode.TLS_ERROR
    assert n.calls["dns"] == 1
    n.manager._config.verification.trusted_entities = [TrustedEntity("other.example")]
    with pytest.raises(VerificationError) as error:
        await n.manager.async_refresh_domain(_DOMAIN, n.cert)
    assert error.value.code == VerificationCode.COUNTERPARTY_NOT_ACCEPTED
    assert n.calls["dns"] == 2


@pytest.mark.asyncio
async def test_refresh_rechecks_final_freshness(native, monkeypatch):
    def expire(result):
        result.dns_expires_at = _now() - datetime.timedelta(seconds=1)

    monkeypatch.setattr(native.manager, "_enforce_counterparty_acceptance", expire)
    with pytest.raises(VerificationError, match="expired during verification"):
        await native.manager.async_refresh_domain(_DOMAIN)
    assert native.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["active", "revoked", "zero-ttl"])
async def test_old_status_lookup_cannot_restore_evidence_after_async_refresh(native, monkeypatch,
                                                                          outcome):
    n = native
    old = await n.manager.async_verify_domain(_DOMAIN)
    n.manager._config.verification.status_check_interval = datetime.timedelta(0)
    started, release = asyncio.Event(), asyncio.Event()
    original = n.https.async_fetch_strict_json

    async def fetch(url, **kwargs):
        if url == n.record.su and not kwargs.get("revalidate"):
            started.set()
            await release.wait()
        return await original(url, **kwargs)

    monkeypatch.setattr(n.https, "async_fetch_strict_json", fetch)
    lookup = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
    try:
        await _wait(started)
        if outcome == "revoked":
            data, cert = n.responses[n.record.su]
            n.responses[n.record.su] = (
                {**data, "state": "REVOKED", "revocationReason": "keyCompromise"}, cert,
            )
            with pytest.raises(VerificationError):
                await n.manager.async_refresh_domain(_DOMAIN)
            n.responses[n.record.su] = data, cert
        else:
            if outcome == "zero-ttl":
                n.resolver.ttl = 0
            fresh = await n.manager.async_refresh_domain(_DOMAIN)
            assert fresh is not old
    finally:
        release.set()
    if outcome == "active":
        assert await lookup is fresh
        assert n.manager._cache.get(_DOMAIN) is fresh
    else:
        with pytest.raises(VerificationError, match="invalidated during status refresh"):
            await lookup
        assert n.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
async def test_refresh_budget_includes_wait_for_older_lookup(native):
    previous = Future()
    with patch.dict(native.manager._verification_futures, {_DOMAIN: previous}):
        with pytest.raises(VerificationError) as error:
            with verification_budget(0.02):
                await asyncio.wait_for(native.manager._async_refresh_identity(_DOMAIN), 1)
        assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        assert not previous.done()
    assert not native.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", [False, True])
async def test_caller_cancellation_or_deadline_does_not_cancel_refresh(native, deadline):
    n = native
    n.resolver.gate.clear()

    async def refresh():
        with verification_budget(0.05 if deadline else 2):
            return await n.manager.async_refresh_domain(_DOMAIN)

    caller = asyncio.create_task(refresh())
    try:
        await _wait(n.resolver.started)
        follower = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
        await asyncio.sleep(0)
        if deadline:
            with pytest.raises(VerificationError) as error:
                await caller
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        else:
            caller.cancel()
            with pytest.raises(asyncio.CancelledError):
                await caller
        assert not n.manager._refresh_futures[_DOMAIN].cancelled()
    finally:
        n.resolver.gate.set()
    fresh = await follower
    assert n.manager._cache.get(_DOMAIN) is fresh
    assert n.calls["dns"] == 1
    assert n.resolver.budgets[0] > 2
    assert not n.manager._refresh_futures


@pytest.mark.asyncio
async def test_shutdown_drains_cancelled_refresh_and_rejects_new_refreshes(native):
    n = native
    n.resolver.gate.clear()
    caller = asyncio.create_task(n.manager.async_refresh_domain(_DOMAIN))
    try:
        await _wait(n.resolver.started)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        shutdown = asyncio.create_task(n.manager.aclose())
        await asyncio.sleep(0)
        assert n.manager._closing and not n.manager._closed
        assert not shutdown.done()
        with pytest.raises(RuntimeError, match="closing or closed"):
            await n.manager.async_refresh_domain(_DOMAIN)
    finally:
        n.resolver.gate.set()
    await shutdown
    assert n.manager._closed
    assert not n.manager._refresh_futures
    assert not n.manager._async_verification_tasks
