"""HTTP cache revalidation is required for explicit identity refreshes only."""

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import MagicMock, patch

import httpx
import pytest

from dnsid._https_client import (
    async_fetch_agent_status,
    async_fetch_jwks,
    fetch_agent_status,
    fetch_jwks,
)
from dnsid._verification_budget import wait_for_verification
from dnsid.c2sp_tlog import SafeC2spResourceFetcher
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.interfaces import HTTPSFetcher
from tests.test_verification_coalescing import _manager_fixture


@pytest.mark.parametrize("resource", ["jwks", "status"])
@pytest.mark.parametrize("revalidate", [False, True])
def test_redirects_preserve_revalidation_headers(resource, revalidate):
    requests = []

    def handle(request):
        requests.append(request)
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, json={"keys": [], "state": "ACTIVE"})

    transport = httpx.MockTransport(handle)
    if resource == "jwks":
        fetch_jwks("https://agent.example/start", "agent.example",
                   transport=transport, revalidate=revalidate)
    else:
        fetch_agent_status("https://agent.example/start", transport=transport,
                           revalidate=revalidate)
    assert len(requests) == 2
    assert all(request.headers.get("cache-control") == (
        "no-cache" if revalidate else None
    ) for request in requests)
    if resource == "status":
        assert all(request.headers["accept"] == "application/json" for request in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("resource", ["jwks", "status", "log"])
@pytest.mark.parametrize("revalidate", [False, True])
async def test_async_resource_revalidation_matches_sync_and_survives_redirects(resource, revalidate):
    requests = []

    def handle(request):
        requests.append(request)
        if resource != "log" and request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, json={"keys": [], "state": "ACTIVE"})

    transport = httpx.MockTransport(handle)
    if resource == "jwks":
        await async_fetch_jwks("https://agent.example/start", "agent.example",
                               transport=transport, revalidate=revalidate)
    elif resource == "status":
        await async_fetch_agent_status("https://agent.example/start", transport=transport,
                                       revalidate=revalidate)
    else:
        async with SafeC2spResourceFetcher() as fetcher:
            with patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport",
                       return_value=transport):
                await fetcher.async_fetch_bounded("https://agent.example/checkpoint", 4096)
    assert len(requests) == (1 if resource == "log" else 2)
    assert all(request.headers.get("cache-control") == (
        "no-cache" if revalidate or resource == "log" else None
    ) for request in requests)
    if resource == "status":
        assert all(request.headers["accept"] == "application/json" for request in requests)


@pytest.mark.parametrize("injected", [False, True])
def test_manager_only_revalidates_explicit_refresh(ec_pair, injected):
    manager, _, _, domain, keys, _, active = _manager_fixture(
        ec_pair, interval=datetime.timedelta(0)
    )
    calls = []
    _, cert = keys(f"https://{domain}/keys", domain)

    def fetch_json(url, allowed_host=None, domain_boundary=False, *, revalidate=False):
        calls.append((url, revalidate))
        if url.endswith("/status"):
            return {"state": "ACTIVE", "lastTransitionAt": active.last_transition_at.isoformat()}, cert
        jwks, _ = keys(url, allowed_host)
        return {"keys": [key._raw for key in jwks.keys]}, cert

    def handle(request):
        data, _ = fetch_json(str(request.url), revalidate=(
            request.headers.get("cache-control") == "no-cache"
        ))
        return httpx.Response(200, json=data)

    manager._http_client.close()
    if injected:
        manager._http_client = None
        manager._https_fetcher = MagicMock(spec=HTTPSFetcher)
        manager._https_fetcher.fetch_strict_json.side_effect = fetch_json
    else:
        manager._http_client = httpx.Client(transport=httpx.MockTransport(handle))
    try:
        with patch("dnsid._https_client._extract_tls_cert", return_value=cert):
            manager.verify_domain(domain)
            assert len(calls) == 3
            assert all(not revalidate for _, revalidate in calls)
            resources = {url for url, _ in calls}
            calls.clear()

            manager.refresh_domain(domain)
            assert {url for url, _ in calls} == resources
            assert len(calls) == 3
            assert all(revalidate for _, revalidate in calls)
            calls.clear()

            manager.verify_domain(domain)
            assert calls == [(manager._cache.get(domain).record.su, False)]
    finally:
        manager.close()


@pytest.mark.parametrize("lookup_outcome", ["active", "unavailable", "revoked"])
def test_refresh_does_not_reuse_an_ordinary_lookup(ec_pair, lookup_outcome):
    manager, resolver, counters, domain, keys, status, active = _manager_fixture(ec_pair)
    resolver.started, resolver.release = threading.Event(), threading.Event()
    if lookup_outcome == "unavailable":
        resolver.failure = VerificationError(VerificationCode.DNS_RESOLUTION, "offline", transient=True)
    lookup_waited, refresh_joined = threading.Event(), threading.Event()
    revalidations = []

    def fetch_keys(url, allowed_host, **kwargs):
        revalidations.append(kwargs["revalidate"])
        return keys(url, allowed_host, **kwargs)

    def fetch_status(url, **kwargs):
        revalidations.append(kwargs["revalidate"])
        if lookup_outcome == "revoked" and not kwargs["revalidate"]:
            return replace(active, state="REVOKED", revocation_reason="keyCompromise")
        return status(url, **kwargs)

    def wait(future):
        with manager._coordination_lock:
            if future is manager._verification_futures.get(domain):
                lookup_waited.set()
            if future is manager._refresh_futures.get(domain):
                refresh_joined.set()
        return wait_for_verification(future)

    try:
        with (
            patch("dnsid.manager._fetch_jwks", side_effect=fetch_keys),
            patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
            patch("dnsid.manager.wait_for_verification", side_effect=wait),
            ThreadPoolExecutor(max_workers=4) as pool,
        ):
            lookup = pool.submit(manager.verify_domain, domain)
            try:
                assert resolver.started.wait(5)
                refresh = pool.submit(manager.refresh_domain, domain)
                assert lookup_waited.wait(5)
                other_refresh = pool.submit(manager.refresh_domain, domain)
                assert refresh_joined.wait(5)
                refresh_joined.clear()
                another_lookup = pool.submit(manager.verify_domain, domain)
                assert refresh_joined.wait(5)
            finally:
                resolver.release.set()
            if lookup_outcome == "active":
                old = lookup.result(5)
            else:
                with pytest.raises(VerificationError):
                    lookup.result(5)
            fresh = refresh.result(5)
            assert other_refresh.result(5) is fresh
            assert another_lookup.result(5) is fresh
            assert manager._cache.get(domain) is fresh
            assert counters["dns"] == 2
            assert revalidations[-3:] == [True, True, True]
            if lookup_outcome == "active":
                assert old is not fresh
                assert revalidations[:3] == [False, False, False]
    finally:
        manager.close()
