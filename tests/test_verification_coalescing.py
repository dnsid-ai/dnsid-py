"""Threaded checks for verification coalescing and manager HTTP ownership."""

from __future__ import annotations

import datetime
import threading
from collections import Counter
from concurrent.futures import Future
from unittest.mock import MagicMock, patch

from dnsid import (
    JWKS,
    DnsidConfig,
    IdentityManager,
    IdentityManagerDependencies,
    VerificationConfig,
)
from dnsid.enums import DNSSECState, VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.interfaces import DNSResolver, HTTPSFetcher, LogReader
from dnsid.models import AgentStatus, TLSCertificate, TXTRecord, VerifiedDomain
from dnsid.registry import LogRegistry
from tests.conftest import make_ec_p256_pair
from tests.test_verify_domain import _make_signed_txt_record


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class _Resolver(DNSResolver):
    def __init__(self, records: dict[str, TXTRecord], counters: Counter[str]) -> None:
        self.records = records
        self.counters = counters
        self.lock = threading.Lock()
        self.started: threading.Event | None = None
        self.release: threading.Event | None = None
        self.failure: VerificationError | None = None

    def fetch_txt(self, name: str):
        with self.lock:
            self.counters["dns"] += 1
            call = self.counters["dns"]
        if call == 1 and self.started is not None and self.release is not None:
            self.started.set()
            assert self.release.wait(5)
        if call == 1 and self.failure is not None:
            raise self.failure
        return [self.records[name]], DNSSECState.UNKNOWN


def _manager_fixture(ec_pair, *, mtls: bool = False, interval: datetime.timedelta | None = None):
    private, ek_key = ec_pair
    domain = "service.example.com"
    txt = _make_signed_txt_record(private, ek_key, domain, fl="mtls" if mtls else "")
    counters: Counter[str] = Counter()
    resolver = _Resolver(
        {f"_dnsid.{domain}": TXTRecord(strings=[txt.encode("ascii")], ttl=300)}, counters
    )
    _, ku_key = make_ec_p256_pair("ku-threaded")
    endpoint_cert = TLSCertificate(
        not_after=_now() + datetime.timedelta(days=1), san_dns_names=[domain]
    )
    active = AgentStatus(state="ACTIVE", last_transition_at=_now())

    class Binding(LogReader):
        def __init__(self, lr: str) -> None:
            self.lr = lr

        def canonical(self, event):
            return b""

        def key_timestamp(self, domain, key_thumbprint):
            return _now()

        def verify_non_revocation(self, domain, at):
            return None

        def read_event(self, ref):
            raise NotImplementedError

        def rebuild_history(self, domain):
            return []

        def verify_bilateral_binding(self, record, entity_key, operational_key):
            with resolver.lock:
                counters["bilateral"] += 1
            result = MagicMock()
            result.initial_operational_thumbprint = operational_key.thumbprint()
            return result

        def verify_operational_continuity(self, *args):
            with resolver.lock:
                counters["continuity"] += 1

    registry = LogRegistry()
    registry.register("microledger", Binding)
    config = DnsidConfig(
        verification=VerificationConfig(
            status_check_interval=interval
            if interval is not None
            else datetime.timedelta(minutes=5)
        )
    )
    manager = IdentityManager(
        config,
        deps=IdentityManagerDependencies(dns_resolver=resolver, log_registry=registry),
    )

    def fetch_jwks(uri, allowed_host, **kwargs):
        with resolver.lock:
            counters["ku" if uri.startswith(f"https://{domain}/") else "ek"] += 1
        keys = [ku_key] if uri.startswith(f"https://{domain}/") else [ek_key]
        return JWKS(keys=keys), endpoint_cert

    def fetch_status(su, **kwargs):
        with resolver.lock:
            counters["status"] += 1
        return active

    return manager, resolver, counters, domain, fetch_jwks, fetch_status, active


def _simultaneous_calls(manager: IdentityManager, calls: list[tuple[str, TLSCertificate | None]]):
    barrier = threading.Barrier(len(calls) + 1)
    results: list[VerifiedDomain] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def call(domain: str, cert: TLSCertificate | None) -> None:
        barrier.wait()
        try:
            result = manager.verify_domain(domain, peer_cert=cert)
            with lock:
                results.append(result)
        except BaseException as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=call, args=args) for args in calls]
    for thread in threads:
        thread.start()
    barrier.wait()
    return threads, results, errors


def _join(threads: list[threading.Thread]) -> None:
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()


def _counting_future(expected_waiters: int):
    count = 0
    lock = threading.Lock()
    ready = threading.Event()

    class CountingFuture(Future[VerifiedDomain]):
        def result(self, timeout=None):
            nonlocal count
            with lock:
                count += 1
                if count == expected_waiters:
                    ready.set()
            return super().result(timeout)

    return CountingFuture, ready


def test_32_cold_calls_share_all_reusable_verification(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(
        ec_pair
    )
    resolver.started = threading.Event()
    resolver.release = threading.Event()
    future_type, all_waiters = _counting_future(31)

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
        patch("dnsid.manager.Future", future_type),
    ):
        threads, results, errors = _simultaneous_calls(manager, [(domain, None)] * 32)
        assert resolver.started.wait(5)
        assert all_waiters.wait(5)
        resolver.release.set()
        _join(threads)

    manager.close()
    assert not errors
    assert len(results) == 32
    assert counters == Counter(
        dns=1, ek=1, ku=1, status=1, bilateral=1, continuity=1
    )


def test_32_stale_calls_share_refresh_and_later_zero_interval_call_refreshes(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, _, active = _manager_fixture(
        ec_pair, interval=datetime.timedelta(0)
    )
    refresh_started = threading.Event()
    refresh_release = threading.Event()

    def status(su, **kwargs):
        with resolver.lock:
            counters["status"] += 1
            call = counters["status"]
        if call == 2:
            refresh_started.set()
            assert refresh_release.wait(5)
        return active

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        manager.verify_domain(domain)
        future_type, all_waiters = _counting_future(31)
        with patch("dnsid.manager.Future", future_type):
            threads, results, errors = _simultaneous_calls(
                manager, [(domain, None)] * 32
            )
            assert refresh_started.wait(5)
            assert all_waiters.wait(5)
            refresh_release.set()
            _join(threads)
        assert not errors
        assert len(results) == 32
        assert counters["status"] == 2

        manager.verify_domain(domain)
        assert counters["status"] == 3

    manager.close()


def test_shared_failure_reaches_waiters_and_later_call_retries(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(
        ec_pair
    )
    resolver.started = threading.Event()
    resolver.release = threading.Event()
    resolver.failure = VerificationError(
        VerificationCode.DNS_RESOLUTION, "shared failure", transient=True
    )
    future_type, all_waiters = _counting_future(31)

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
        patch("dnsid.manager.Future", future_type),
    ):
        threads, results, errors = _simultaneous_calls(manager, [(domain, None)] * 32)
        assert resolver.started.wait(5)
        assert all_waiters.wait(5)
        resolver.release.set()
        _join(threads)
        assert not results
        assert len(errors) == 32
        assert len({id(error) for error in errors}) == 1

        assert manager.verify_domain(domain).domain == domain

    manager.close()
    assert counters["dns"] == 2


def test_shared_refresh_failure_never_returns_stale_and_later_call_retries(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, _, active = _manager_fixture(
        ec_pair, interval=datetime.timedelta(0)
    )
    refresh_started = threading.Event()
    refresh_release = threading.Event()
    failure = VerificationError(
        VerificationCode.DNS_RESOLUTION, "status offline", transient=True
    )

    def status(su, **kwargs):
        with resolver.lock:
            counters["status"] += 1
            call = counters["status"]
        if call == 2:
            refresh_started.set()
            assert refresh_release.wait(5)
            raise failure
        return active

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        manager.verify_domain(domain)
        future_type, all_waiters = _counting_future(31)
        with patch("dnsid.manager.Future", future_type):
            threads, results, errors = _simultaneous_calls(
                manager, [(domain, None)] * 32
            )
            assert refresh_started.wait(5)
            assert all_waiters.wait(5)
            refresh_release.set()
            _join(threads)

        assert not results
        assert len(errors) == 32
        assert len({id(error) for error in errors}) == 1
        assert all(
            isinstance(error, VerificationError)
            and error.code is VerificationCode.STATUS_UNAVAILABLE
            for error in errors
        )
        assert manager.verify_domain(domain).registry_status.state == "ACTIVE"
        assert counters["status"] == 3
    manager.close()


def test_mtls_outcomes_are_per_caller_while_reusable_work_is_shared(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(
        ec_pair, mtls=True
    )
    resolver.started = threading.Event()
    resolver.release = threading.Event()
    valid = TLSCertificate(san_dns_names=[domain])
    mismatch = TLSCertificate(san_dns_names=["other.example.com"])
    calls = [(domain, valid)] * 12 + [(domain, None)] * 10 + [(domain, mismatch)] * 10
    future_type, all_waiters = _counting_future(31)

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
        patch("dnsid.manager.Future", future_type),
    ):
        threads, results, errors = _simultaneous_calls(manager, calls)
        assert resolver.started.wait(5)
        assert all_waiters.wait(5)
        resolver.release.set()
        _join(threads)

    manager.close()
    assert len(results) == 12
    assert len(errors) == 20
    assert all(
        isinstance(error, VerificationError) and error.code is VerificationCode.TLS_ERROR
        for error in errors
    )
    assert counters["dns"] == counters["status"] == 1


def test_different_domains_do_not_wait_for_each_other():
    manager = IdentityManager.for_verification(
        IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver))
    )
    first_started = threading.Event()
    release_first = threading.Event()
    second_done = threading.Event()
    evidence = MagicMock()
    evidence.record.policy_flags.return_value = []
    evidence.record.ka = ""
    evidence.dns_ttl = 300
    evidence.dns_expires_at = _now() + datetime.timedelta(seconds=300)
    evidence.tls_cert = TLSCertificate(not_after=_now() + datetime.timedelta(days=1))
    evidence.record_signing_tls_cert = None

    def verify(domain: str):
        if domain == "first.example.com":
            first_started.set()
            assert release_first.wait(5)
        else:
            second_done.set()
        return evidence

    with patch.object(manager, "_verify_domain_uncached", side_effect=verify):
        first = threading.Thread(target=manager.verify_domain, args=("first.example.com",))
        second = threading.Thread(target=manager.verify_domain, args=("second.example.com",))
        first.start()
        assert first_started.wait(5)
        second.start()
        assert second_done.wait(5)
        release_first.set()
        _join([first, second])
    manager.close()


class _InjectedFetcher(HTTPSFetcher):
    def __init__(self) -> None:
        self.close = MagicMock()

    def fetch_strict_json(self, url, allowed_host=None, domain_boundary=False):
        raise NotImplementedError


def test_manager_http_clients_are_owned_separately_and_close_is_idempotent():
    resolver = MagicMock(spec=DNSResolver)
    first = IdentityManager.for_verification(
        IdentityManagerDependencies(dns_resolver=resolver)
    )
    second = IdentityManager.for_verification(
        IdentityManagerDependencies(dns_resolver=resolver)
    )
    assert first._http_client is not second._http_client

    first_client = first._http_client
    assert first_client is not None
    with patch.object(first_client, "close", wraps=first_client.close) as close:
        first.close()
        first.close()
        close.assert_called_once_with()
    assert second._http_client is not None and not second._http_client.is_closed
    caller_client = second.create_dnsid_http_client()
    assert caller_client is not second._http_client
    second.close()
    assert not caller_client.is_closed
    caller_client.close()

    third = IdentityManager.for_verification(
        IdentityManagerDependencies(dns_resolver=resolver)
    )
    with third as entered:
        assert entered is third
    assert third._http_client is not None and third._http_client.is_closed


def test_injected_fetcher_remains_caller_owned():
    fetcher = _InjectedFetcher()
    manager = IdentityManager.for_verification(
        IdentityManagerDependencies(
            dns_resolver=MagicMock(spec=DNSResolver), https_fetcher=fetcher
        )
    )
    assert manager._http_client is None
    manager.close()
    manager.close()
    fetcher.close.assert_not_called()


def test_one_manager_passes_one_client_to_ek_ku_status_and_refresh(ec_pair):
    manager, _, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(
        ec_pair, interval=datetime.timedelta(0)
    )
    clients: list[object] = []

    def jwks(uri, allowed_host, **kwargs):
        clients.append(kwargs["client"])
        return fetch_jwks(uri, allowed_host, **kwargs)

    def status(su, **kwargs):
        clients.append(kwargs["client"])
        return fetch_status(su, **kwargs)

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        manager.verify_domain(domain)
        manager.verify_domain(domain)

    assert len(clients) == 4
    assert all(client is manager._http_client for client in clients)
    assert counters["status"] == 2
    manager.close()
