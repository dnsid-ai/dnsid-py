"""Native cold orchestration, including authenticated C2SP migrations and sync waiters."""

import asyncio
import datetime
import threading
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import httpx
import pytest
import pytest_asyncio

from dnsid import (
    AsyncLogReader,
    DnsidConfig,
    DnsIdTxtRecord,
    DNSResolver,
    DNSSECMode,
    DNSSECState,
    HTTPSFetcher,
    IdentityManager,
    IdentityManagerDependencies,
    TrustedEntity,
    VerificationCode,
    VerificationConfig,
    VerificationError,
    remaining_seconds,
    verification_budget,
)
from dnsid._utils import b64url_encode
from dnsid._verification_budget import (
    BudgetExhausted,
    async_run_concurrently,
    wait_for_verification,
)
from dnsid.c2sp_tlog import C2spTlogReader
from dnsid.models import TLSCertificate, TXTRecord
from tests.test_c2sp_migration import _DOMAIN, _Logs


@pytest_asyncio.fixture
async def native(request, monkeypatch):
    logs = _Logs.create()
    old = logs.issuance("initial")
    lr = logs.migration("current", old, 0)
    bundles = getattr(request, "param", False)
    registry, fetcher = logs.registry(bundles=bundles)
    record = DnsIdTxtRecord(
        v="dnsid-draft-01", identity_fqdn=_DOMAIN, gi="example",
        ek="https://example/ek", ku=f"https://{_DOMAIN}/ku", lr=lr,
        su="https://registry.example/status", ka="24h",
    )
    record.sg = b64url_encode(logs.entity_private.sign(record.canonical().encode("ascii")))
    calls = Counter()
    loop_thread = threading.get_ident()
    cert = TLSCertificate(
        not_after=datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1),
        san_dns_names=[_DOMAIN, "example"],
    )
    responses = {
        record.ek: ({"keys": [logs.entity_key.to_dict()]}, cert),
        record.ku: ({"keys": [logs.operational_key.to_dict()]}, cert),
        record.su: ({"state": "ACTIVE", "lastTransitionAt": "2026-10-14T00:00:00Z"}, cert),
    }
    started = {url: asyncio.Event() for url in responses}
    gates = {url: asyncio.Event() for url in responses}
    closed = {url: asyncio.Event() for url in responses}
    for gate in gates.values():
        gate.set()
    log_started, log_gate = asyncio.Event(), asyncio.Event()
    log_gate.set()

    class Resolver(DNSResolver):
        def __init__(self):
            self.started, self.gate = asyncio.Event(), asyncio.Event()
            self.gate.set()
            self.sync_started, self.sync_gate = threading.Event(), threading.Event()
            self.sync_gate.set()
            self.ttl, self.state = 300, DNSSECState.UNKNOWN
            self.budgets = []
            self.records = None

        def answer(self):
            calls["dns"] += 1
            self.budgets.append(remaining_seconds())
            return (
                self.records if self.records is not None else
                [TXTRecord([record.serialize().encode("ascii")], ttl=self.ttl)],
                self.state,
            )

        def fetch_txt(self, name):
            assert threading.get_ident() != loop_thread
            assert name == f"_dnsid.{_DOMAIN}"
            self.sync_started.set()
            assert self.sync_gate.wait(2)
            return self.answer()

        async def async_fetch_txt(self, name):
            assert threading.get_ident() == loop_thread
            assert name == f"_dnsid.{_DOMAIN}"
            self.started.set()
            await self.gate.wait()
            return self.answer()

    class Fetcher(HTTPSFetcher):
        def answer(self, url, allowed_host=None, domain_boundary=False, *, revalidate=False):
            calls[url] += 1
            if url == record.ek:
                assert allowed_host == "example" and domain_boundary is True
            elif url == record.ku:
                assert allowed_host == _DOMAIN and domain_boundary is False
            else:
                assert url == record.su and allowed_host is None
            return responses[url]

        def fetch_strict_json(self, *args, **kwargs):
            assert threading.get_ident() != loop_thread
            return self.answer(*args, **kwargs)

        async def async_fetch_strict_json(self, url, **kwargs):
            assert threading.get_ident() == loop_thread
            started[url].set()
            try:
                await gates[url].wait()
                return self.answer(url, **kwargs)
            finally:
                closed[url].set()

    async def log_fetch(url, max_bytes):
        assert threading.get_ident() == loop_thread
        log_started.set()
        await log_gate.wait()
        fetcher.calls.append(url)
        result = fetcher.resources[url]
        assert len(result) <= max_bytes
        return result

    monkeypatch.setattr(fetcher, "async_fetch_bounded", log_fetch, raising=False)
    resolver, https = Resolver(), Fetcher()
    manager = IdentityManager(
        DnsidConfig(verification=VerificationConfig(
            status_check_interval=datetime.timedelta(minutes=5),
        )),
        deps=IdentityManagerDependencies(
            dns_resolver=resolver, https_fetcher=https, log_registry=registry,
        ),
    )
    async with manager:
        yield SimpleNamespace(
            manager=manager, resolver=resolver, https=https, logs=logs, record=record, bundles=bundles,
            responses=responses, calls=calls, fetcher=fetcher, cert=cert,
            started=started, gates=gates, closed=closed, log_started=log_started,
            log_gate=log_gate, loop_thread=loop_thread,
        )


async def _wait(event):
    async with asyncio.timeout(2):
        while not event.is_set():
            await asyncio.sleep(0)


@pytest.mark.asyncio
@pytest.mark.parametrize("native", [False, True], indirect=True)
async def test_native_cold_fanout_shares_work_and_keeps_sync_log_reader(native, monkeypatch):
    n = native
    n.gates[n.record.ku].clear()
    n.gates[n.record.su].clear()
    n.log_gate.clear()
    for name in ("preload_history", "verify_bilateral_binding",
                 "verify_operational_continuity", "key_timestamp"):
        monkeypatch.setattr(C2spTlogReader, name, MagicMock(side_effect=AssertionError("sync log")))
    with patch.object(n.manager, "_submit_verification", side_effect=AssertionError("core worker")):
        calls = [asyncio.create_task(n.manager.async_verify_domain(_DOMAIN)) for _ in range(16)]
        try:
            await _wait(n.started[n.record.ku])
            await _wait(n.started[n.record.su])
            await _wait(n.log_started)
            assert n.manager._cache.get(_DOMAIN) is None
            assert n.calls[n.record.ek] == 1
        finally:
            for gate in n.gates.values():
                gate.set()
            n.log_gate.set()
        results = await asyncio.gather(*calls)
        result = results[0]
        assert all(value is result for value in results)
        assert await n.manager.async_verify_domain(_DOMAIN) is result
    assert isinstance(result.log_reader, AsyncLogReader)
    assert [event.event_type for event in result.log_reader.rebuild_history(_DOMAIN)] == [
        "ISSUANCE", "MIGRATION",
    ]
    assert result.key_bound_at < result.verified_at
    assert result.record_signing_tls_cert is result.tls_cert is n.cert
    assert n.calls == Counter({"dns": 1, n.record.ek: 1, n.record.ku: 1, n.record.su: 1})
    assert len(n.fetcher.calls) == (2 if n.bundles else 4)


@pytest.mark.asyncio
async def test_default_https_helpers_reuse_native_transport_until_shutdown(native, monkeypatch):
    n = native
    n.manager._https_fetcher = None
    transports = []

    async def handle(request):
        assert threading.get_ident() == n.loop_thread
        return httpx.Response(200, json=n.responses[str(request.url)][0])

    def transport(config):
        assert config is n.manager._transport_config
        result = httpx.MockTransport(handle)
        result.aclose = AsyncMock(wraps=result.aclose)
        transports.append(result)
        return result

    monkeypatch.setattr("dnsid.manager.make_ssrf_safe_async_transport", transport)
    with patch.object(n.manager, "_submit_verification", side_effect=AssertionError("core worker")):
        result = await n.manager.async_verify_domain(_DOMAIN)
    assert result.jwks.keys[0].thumbprint() == n.logs.operational_key.thumbprint()
    assert result.signing_key.thumbprint() == n.logs.entity_key.thumbprint()
    assert len(transports) == 1
    transports[0].aclose.assert_not_awaited()
    await n.manager.aclose()
    transports[0].aclose.assert_awaited_once()
    assert not n.manager._verification_futures


@pytest.mark.asyncio
@pytest.mark.parametrize("dependency", ["dns", "https", "log"])
async def test_sync_only_adapters_keep_worker_fallback(native, monkeypatch, dependency):
    n = native
    if dependency == "dns":
        monkeypatch.setattr(type(n.resolver), "async_fetch_txt", None)
    elif dependency == "https":
        monkeypatch.setattr(type(n.https), "async_fetch_strict_json", None)
    else:
        class SyncReader:
            def __init__(self, reader):
                self.reader = reader

            def __getattr__(self, name):
                if name.startswith("async_"):
                    raise AttributeError(name)
                return getattr(self.reader, name)

        registry = n.manager._log_registry
        factory = registry._factories["c2sp-tlog"]
        registry.register("c2sp-tlog", lambda lr: SyncReader(factory(lr)))
        original = n.fetcher.fetch_bounded

        def fetch(*args):
            assert threading.get_ident() != n.loop_thread
            return original(*args)

        monkeypatch.setattr(n.fetcher, "fetch_bounded", fetch)
    result = await n.manager.async_verify_domain(_DOMAIN)
    assert result.domain == _DOMAIN
    assert n.calls == Counter({"dns": 1, n.record.ek: 1, n.record.ku: 1, n.record.su: 1})


@pytest.mark.asyncio
@pytest.mark.parametrize("sync_leader", [False, True])
@pytest.mark.parametrize("deadline", [False, True])
async def test_cold_sync_async_waiters_survive_leader_cancellation_or_deadline(
    native, sync_leader, deadline,
):
    n = native
    n.resolver.gate.clear()
    n.resolver.sync_gate.clear()
    sync_waiting = threading.Event()

    def sync_call():
        with verification_budget(0.04 if deadline else 2):
            return n.manager.verify_domain(_DOMAIN)

    async def async_call():
        with verification_budget(0.04 if deadline else 2):
            return await n.manager.async_verify_domain(_DOMAIN)

    def wait(future):
        sync_waiting.set()
        return wait_for_verification(future)

    leader = asyncio.create_task(asyncio.to_thread(sync_call) if sync_leader else async_call())
    await _wait(n.resolver.sync_started if sync_leader else n.resolver.started)
    with patch("dnsid.manager.wait_for_verification", side_effect=wait):
        sync_follower = asyncio.create_task(asyncio.to_thread(n.manager.verify_domain, _DOMAIN))
        follower = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
        try:
            await _wait(sync_waiting)
            if deadline:
                with pytest.raises(VerificationError) as error:
                    await leader
                assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
            else:
                leader.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await leader
            assert not follower.done()
            assert not sync_follower.done()
        finally:
            n.resolver.gate.set()
            n.resolver.sync_gate.set()
        a, b = await asyncio.gather(follower, sync_follower)
    assert a is b
    assert n.calls["dns"] == 1
    assert n.resolver.budgets[0] > 0.04


@pytest.mark.asyncio
async def test_bad_signature_never_follows_authenticated_locations(native):
    n = native
    n.record.sg = "AA"
    with pytest.raises(VerificationError) as error:
        await n.manager.async_verify_domain(_DOMAIN)
    assert error.value.code == VerificationCode.SIGNATURE_INVALID
    assert n.calls == Counter({"dns": 1, n.record.ek: 1})
    assert n.fetcher.calls == []
    assert n.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,state,expected", [
    (DNSSECMode.AUTO, DNSSECState.UNKNOWN, None),
    (DNSSECMode.VALIDATED, DNSSECState.UNKNOWN, VerificationCode.DNSSEC_FAILED),
    (DNSSECMode.REQUIRED, DNSSECState.UNKNOWN, VerificationCode.DNSSEC_FAILED),
    (DNSSECMode.REQUIRED, DNSSECState.VALID, None),
    (DNSSECMode.AUTO, DNSSECState.FAILED, VerificationCode.DNSSEC_FAILED),
    (DNSSECMode.AUTO, "VALID", VerificationCode.DNSSEC_FAILED),
])
async def test_cold_dnssec_matches_sync_validation(native, mode, state, expected):
    n = native
    n.manager._config.verification.dnssec_mode = mode
    n.resolver.state = state
    if expected is None:
        assert (await n.manager.async_verify_domain(_DOMAIN)).dnssec_state == state
    else:
        with pytest.raises(VerificationError) as error:
            await n.manager.async_verify_domain(_DOMAIN)
        assert error.value.code == expected
        assert n.calls == Counter(dns=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl", [-1, False, "300", 2**100])
async def test_invalid_dns_ttl_fails_before_https(native, ttl):
    native.resolver.ttl = ttl
    with pytest.raises(VerificationError) as error:
        await native.manager.async_verify_domain(_DOMAIN)
    assert error.value.code == VerificationCode.DNS_RESOLUTION
    assert native.calls == Counter(dns=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["collision", "missing-log", "inactive", "bad-status"])
async def test_failed_cold_evidence_is_not_cached(native, failure):
    n = native
    expected = VerificationCode.RECORD_INVALID
    if failure == "collision":
        n.responses[n.record.ku] = n.responses[n.record.ek]
    elif failure == "missing-log":
        n.manager._log_registry = None
        expected = VerificationCode.LOG_ERROR
    else:
        document, cert = n.responses[n.record.su]
        state = "REVOKED" if failure == "inactive" else "bad"
        n.responses[n.record.su] = ({**document, "state": state}, cert)
        if failure == "inactive":
            n.responses[n.record.su][0]["revocationReason"] = "keyCompromise"
            expected = VerificationCode.STATUS_NOT_ACTIVE
    with pytest.raises(VerificationError) as error:
        await n.manager.async_verify_domain(_DOMAIN)
    assert error.value.code == expected
    assert n.manager._cache.get(_DOMAIN) is None
    assert not n.manager._verification_futures


@pytest.mark.asyncio
async def test_zero_ttl_followers_get_independent_native_dns_lookups(native):
    n = native
    n.resolver.ttl = 0
    n.resolver.gate.clear()
    leader = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
    await _wait(n.resolver.started)
    followers = [asyncio.create_task(n.manager.async_verify_domain(_DOMAIN)) for _ in range(3)]
    await asyncio.sleep(0)
    n.resolver.gate.set()
    results = await asyncio.gather(leader, *followers)
    assert all(result.dns_ttl == 0 for result in results)
    assert n.calls["dns"] == 4
    assert n.manager._cache.get(_DOMAIN) is None
    assert not n.manager._verification_workers


@pytest.mark.asyncio
async def test_native_cold_keeps_peer_binding_acceptance_and_ownership_per_caller(native):
    n = native
    n.record.fl = "mtls"
    n.record.sg = b64url_encode(n.logs.entity_private.sign(n.record.canonical().encode("ascii")))
    close = AsyncMock()
    with patch.object(n.https, "aclose", close, create=True):
        results = await asyncio.gather(
            n.manager.async_verify_domain(_DOMAIN, n.cert),
            n.manager.async_verify_domain(_DOMAIN), return_exceptions=True,
        )
        assert results[0].domain == _DOMAIN
        assert isinstance(results[1], VerificationError)
        n.manager._config.verification.trusted_entities = [TrustedEntity(governance_id="other.example")]
        with pytest.raises(VerificationError) as error:
            await n.manager.async_verify_domain(_DOMAIN, n.cert)
        assert error.value.code == VerificationCode.COUNTERPARTY_NOT_ACCEPTED
        await n.manager.aclose()
    close.assert_not_awaited()
    assert n.calls["dns"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("primary_budget", [False, True])
async def test_nested_fanout_keeps_identity_error_before_status_or_cancellation(primary_budget):
    ready = [asyncio.Event(), asyncio.Event()]
    release = asyncio.Event()
    primary_error = BudgetExhausted() if primary_budget else VerificationError(
        VerificationCode.TLS_ERROR, "ku failed",
    )
    status_error = VerificationError(VerificationCode.STATUS_UNAVAILABLE, "su failed", transient=True)

    async def fail(index, error):
        ready[index].set()
        await release.wait()
        raise error

    async def identity():
        return await async_run_concurrently(lambda: fail(0, primary_error), lambda: asyncio.sleep(0))

    call = asyncio.create_task(async_run_concurrently(identity, lambda: fail(1, status_error)))
    await asyncio.gather(*(event.wait() for event in ready))
    release.set()
    with pytest.raises(VerificationError) as error:
        await call
    assert error.value is (status_error if primary_budget else primary_error)


@pytest.mark.asyncio
async def test_native_shared_deadline_cancels_fanout_and_cleans_up(native):
    n = native
    n.gates[n.record.ku].clear()
    n.gates[n.record.su].clear()
    from dnsid._verification_budget import verification_work_context

    def short_context(track, **kwargs):
        with verification_budget(0.03):
            return verification_work_context(track)

    with patch("dnsid.manager.verification_work_context", side_effect=short_context):
        with pytest.raises(VerificationError) as error:
            await n.manager.async_verify_domain(_DOMAIN)
    assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
    assert error.value.transient
    assert n.closed[n.record.ku].is_set()
    assert n.closed[n.record.su].is_set()
    assert not n.manager._verification_futures
    assert not n.manager._async_verification_tasks
    assert n.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_at", [1, 3, 5])
async def test_native_task_submission_failure_cleans_up_and_allows_retry(native, fail_at):
    n = native
    create = asyncio.create_task
    calls = 0

    def rejected(coroutine, **kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise RuntimeError("task rejected")
        return create(coroutine, **kwargs)

    with patch("dnsid.manager.asyncio.create_task", side_effect=rejected):
        with pytest.raises(RuntimeError, match="task rejected"):
            await n.manager.async_verify_domain(_DOMAIN)
    assert not n.manager._verification_futures
    assert not n.manager._async_verification_tasks
    assert n.manager._cache.get(_DOMAIN) is None
    assert (await n.manager.async_verify_domain(_DOMAIN)).domain == _DOMAIN


@pytest.mark.asyncio
@pytest.mark.parametrize("status_first", [False, True])
async def test_cold_nested_fanout_prefers_ku_failure_to_status_failure(native, status_first):
    n = native
    original = n.https.async_fetch_strict_json
    ku_error = VerificationError(VerificationCode.TLS_ERROR, "ku failed")

    async def fetch(url, **kwargs):
        result = await original(url, **kwargs)
        if url == n.record.ku:
            raise ku_error
        if url == n.record.su:
            raise VerificationError(VerificationCode.DNS_RESOLUTION, "su failed", transient=True)
        return result

    n.gates[n.record.ku].clear()
    n.gates[n.record.su].clear()
    with patch.object(n.https, "async_fetch_strict_json", side_effect=fetch):
        call = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
        await _wait(n.started[n.record.ku])
        await _wait(n.started[n.record.su])
        order = [n.record.su, n.record.ku] if status_first else [n.record.ku, n.record.su]
        for url in order:
            n.gates[url].set()
        with pytest.raises(VerificationError) as error:
            await call
    assert error.value is ku_error
    assert n.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("identity_fails", [False, True])
async def test_definitive_failure_closes_native_sibling_reads(native, identity_fails):
    n = native
    n.gates[n.record.ku].clear()
    n.gates[n.record.su].clear()
    if identity_fails:
        n.responses[n.record.ku] = n.responses[n.record.ek]
    else:
        document, cert = n.responses[n.record.su]
        n.responses[n.record.su] = (
            {**document, "state": "REVOKED", "revocationReason": "keyCompromise"}, cert,
        )
    call = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
    await _wait(n.started[n.record.ku])
    await _wait(n.started[n.record.su])
    n.gates[n.record.ku if identity_fails else n.record.su].set()
    with pytest.raises(VerificationError) as error:
        await asyncio.wait_for(call, 2)
    assert error.value.code == (
        VerificationCode.RECORD_INVALID if identity_fails else VerificationCode.STATUS_NOT_ACTIVE
    )
    assert n.closed[n.record.su if identity_fails else n.record.ku].is_set()
    assert n.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
async def test_expired_dns_is_not_cached_after_native_reads(native):
    n = native
    n.resolver.ttl = 1
    n.gates[n.record.su].clear()
    now = datetime.datetime.now(datetime.UTC)
    with patch("dnsid.manager._now", return_value=now) as clock:
        call = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
        await _wait(n.started[n.record.su])
        clock.return_value += datetime.timedelta(seconds=2)
        n.gates[n.record.su].set()
        with pytest.raises(VerificationError) as error:
            await call
    assert error.value.code == VerificationCode.DNS_RESOLUTION
    assert n.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
async def test_async_key_timestamp_enforces_key_age(native, monkeypatch):
    key_time = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=2)
    monkeypatch.setattr(C2spTlogReader, "async_key_timestamp", AsyncMock(return_value=key_time))
    with pytest.raises(VerificationError) as error:
        await native.manager.async_verify_domain(_DOMAIN)
    assert error.value.code == VerificationCode.KEY_AGE_EXCEEDED
    assert native.manager._cache.get(_DOMAIN) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("sync_only", [False, True])
@pytest.mark.parametrize("failure,code,transient", [
    (dns.resolver.NXDOMAIN(), VerificationCode.RECORD_NOT_FOUND, False),
    (dns.resolver.NoAnswer(), VerificationCode.RECORD_NOT_FOUND, False),
    (dns.exception.ValidationFailure(), VerificationCode.DNSSEC_FAILED, False),
    (OSError("offline"), VerificationCode.DNS_RESOLUTION, True),
])
async def test_dns_failures_match_sync_classification(native, monkeypatch, sync_only,
                                                     failure, code, transient):
    if sync_only:
        monkeypatch.setattr(type(native.resolver), "async_fetch_txt", None)
        monkeypatch.setattr(native.resolver, "fetch_txt", MagicMock(side_effect=failure))
    else:
        monkeypatch.setattr(native.resolver, "async_fetch_txt", AsyncMock(side_effect=failure))
    with pytest.raises(VerificationError) as error:
        await native.manager.async_verify_domain(_DOMAIN)
    assert error.value.code == code
    assert error.value.transient == transient
    assert not native.calls


@pytest.mark.asyncio
async def test_async_lookup_joins_explicit_refresh(native):
    manager = native.manager
    old = await manager.async_verify_domain(_DOMAIN)
    native.resolver.sync_gate.clear()
    refresh = asyncio.create_task(asyncio.to_thread(manager.refresh_domain, _DOMAIN))
    try:
        async with asyncio.timeout(2):
            while not native.resolver.sync_started.is_set():
                await asyncio.sleep(0)
        lookup = asyncio.create_task(manager.async_verify_domain(_DOMAIN))
        await asyncio.sleep(0)
        assert not lookup.done()
    finally:
        native.resolver.sync_gate.set()
    fresh = await refresh
    assert await lookup is fresh
    assert fresh is not old
    assert native.calls["dns"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 2])
async def test_dns_record_count_is_checked_before_https(native, count):
    native.resolver.records = [
        TXTRecord([native.record.serialize().encode("ascii")], ttl=300) for _ in range(count)
    ]
    with pytest.raises(VerificationError) as error:
        await native.manager.async_verify_domain(_DOMAIN)
    expected = VerificationCode.RECORD_NOT_FOUND if count == 0 else VerificationCode.RECORD_INVALID
    assert error.value.code == expected
    assert native.calls == Counter(dns=1)


@pytest.mark.asyncio
async def test_cold_default_resolver_reads_real_udp_without_network_workers(native, monkeypatch):
    import json

    import dns.flags
    import dns.message
    import dns.rrset

    from dnsid._default_resolver import DefaultDNSResolver

    raw = native.record.serialize()
    chunks = " ".join(json.dumps(raw[index:index + 200]) for index in range(0, len(raw), 200))
    questions = []

    class Server(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, peer):
            query = dns.message.from_wire(data)
            questions.append(query.question[0])
            response = dns.message.make_response(query)
            response.flags |= dns.flags.AD
            response.answer.append(dns.rrset.from_text(
                query.question[0].name, 300, "IN", "TXT", chunks,
            ))
            self.transport.sendto(response.to_wire(), peer)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        Server, local_addr=("127.0.0.1", 0),
    )
    resolver = DefaultDNSResolver("127.0.0.1:" + str(transport.get_extra_info("sockname")[1]))
    native.manager._dns_resolver = resolver
    monkeypatch.setattr(resolver, "fetch_txt", MagicMock(side_effect=AssertionError("sync TXT")))
    try:
        with patch.object(native.manager, "_submit_verification",
                          side_effect=AssertionError("core worker")):
            result = await native.manager.async_verify_domain(_DOMAIN)
        assert result.dnssec_state == DNSSECState.UNKNOWN
        assert str(questions[0].name) == f"_dnsid.{_DOMAIN}."
        assert len(questions) == 1
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_cancelled_shutdown_wait_does_not_cancel_native_cold_work(native):
    n = native
    n.gates[n.record.su].clear()
    call = asyncio.create_task(n.manager.async_verify_domain(_DOMAIN))
    await _wait(n.started[n.record.su])
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    shutdown = asyncio.create_task(n.manager.aclose())
    await asyncio.sleep(0)
    shutdown.cancel()
    with pytest.raises(asyncio.CancelledError):
        await shutdown
    assert n.manager._closing and not n.manager._closed
    assert not n.closed[n.record.su].is_set()
    assert not n.manager._verification_futures[_DOMAIN].cancelled()
    n.gates[n.record.su].set()
    await n.manager.aclose()
    assert n.manager._closed
    assert n.closed[n.record.su].is_set()
    assert not n.manager._verification_futures
    assert not n.manager._verification_workers
