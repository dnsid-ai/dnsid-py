"""WBA directory timing, ku separation, and bounded current-key refresh."""

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest

from dnsid import JWKS, HttpRequest, WBAHttpSigner, WBAHttpVerifier, WebBotAuthConfig
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.local_key_provider import LocalKeyProvider
from dnsid.models import SignatureParams
from dnsid.wba_signer import _wba_identifier, serve_http_message_signatures_directory
from tests.test_verification_coalescing import _manager_fixture
from tests.test_wba_verifier import DOMAIN
from tests.test_wba_verifier import setup as setup


@pytest.mark.parametrize("ttl,backdate", [(300, 5), (60, 5), (5, 4), (1, 0)])
def test_directory_backdating(setup, monkeypatch, ttl, backdate):
    provider, _, _, req, _, _, _ = setup
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    monkeypatch.setattr("dnsid.wba_signer._now", lambda: now)
    response = serve_http_message_signatures_directory(
        req, provider, WebBotAuthConfig(directory_signature_ttl=ttl)
    )
    params = SignatureParams.parse(response.headers["signature-input"])
    assert params.created == int(now.timestamp()) - backdate
    assert params.expires == params.created + ttl
    assert response.headers["cache-control"] == f"max-age={ttl - backdate}, must-revalidate"
    assert "content-encoding" not in response.headers


def test_directory_does_not_serve_a_signature_that_expired_during_signing(setup, monkeypatch):
    provider, _, _, req, _, _, _ = setup
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    clock = iter([now, now + datetime.timedelta(seconds=1)])
    monkeypatch.setattr("dnsid.wba_signer._now", lambda: next(clock))
    with pytest.raises(ArgumentError, match="expired during signing"):
        serve_http_message_signatures_directory(
            req, provider, WebBotAuthConfig(directory_signature_ttl=1)
        )


def test_directory_tolerates_verifier_five_seconds_behind(setup, monkeypatch):
    _, _, verifier, req, opts, _, _ = setup
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    monkeypatch.setattr("dnsid.wba_verifier._now", lambda: now - datetime.timedelta(seconds=5))
    verifier.verify_web_bot_auth_signed_request(req, opts)


def test_wba_identifier_preserves_reserved_path_escapes():
    assert _wba_identifier(f"https://{DOMAIN}/a%2fb?key=1#key") == f"https://{DOMAIN}/a%2Fb"
    assert _wba_identifier(f"https://{DOMAIN}/a%2Fb") != _wba_identifier(f"https://{DOMAIN}/a/b")


@pytest.mark.parametrize("endpoint,ku", [
    (f"https://{DOMAIN}", f"https://{DOMAIN}/?key=1#key"),
    (f"https://{DOMAIN}/", f"https://{DOMAIN}"),
])
def test_empty_https_path_is_equivalent_to_slash_for_ku_guard(setup, endpoint, ku):
    provider, resolver, verifier, req, opts, _, _ = setup
    config = WebBotAuthConfig(signature_agent_uri=endpoint, signature_agent_type="jwks_uri")
    with pytest.raises(ArgumentError, match="local ku"):
        WBAHttpSigner(provider, DOMAIN, config=config, ku_url=ku)
    WBAHttpSigner(provider, DOMAIN, config=config).sign(req)
    resolver.verify_domain.return_value.record.ku = ku
    with pytest.raises(VerificationError, match="authenticated ku"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.refresh_domain.assert_not_called()


@pytest.mark.parametrize("ku", [
    f"https://{DOMAIN}/jwks", f"https://{DOMAIN}/jwks?version=2#key",
    f"https://{DOMAIN.upper()}:443/unused/../%6Awks",
])
def test_ku_discovery_rejected_when_locally_known_and_after_authentication(setup, ku):
    provider, resolver, verifier, req, opts, _, _ = setup
    config = WebBotAuthConfig(
        signature_agent_uri=f"https://{DOMAIN}/jwks?discovery=1",
        signature_agent_type="jwks_uri",
    )
    with pytest.raises(ArgumentError, match="local ku"):
        WBAHttpSigner(provider, DOMAIN, config=config, ku_url=ku)
    WBAHttpSigner(provider, DOMAIN, config=config).sign(req)
    resolver.verify_domain.return_value.record.ku = ku
    with pytest.raises(VerificationError, match="authenticated ku"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.refresh_domain.assert_not_called()


def test_verifier_requires_refresh_capability():
    with pytest.raises(ArgumentError, match="RefreshingIdentityResolver"):
        WBAHttpVerifier(SimpleNamespace(verify_domain=MagicMock()))


@pytest.mark.parametrize("outcome", [
    "success", "unchanged", "revoked", "denied", "unavailable", "expired", "ku", "tls",
])
def test_key_mismatch_refresh_rechecks_binding_policy_and_time(setup, monkeypatch, outcome):
    _, resolver, verifier, req, opts, _, _ = setup
    fresh = resolver.verify_domain.return_value
    old = replace(fresh, jwks=JWKS(keys=[LocalKeyProvider.generate().signing_key()]))
    resolver.verify_domain.return_value = old
    resolver.refresh_domain.return_value = old if outcome == "unchanged" else fresh
    if outcome in {"revoked", "denied", "unavailable"}:
        code = {
            "revoked": VerificationCode.STATUS_NOT_ACTIVE,
            "denied": VerificationCode.COUNTERPARTY_NOT_ACCEPTED,
            "unavailable": VerificationCode.STATUS_UNAVAILABLE,
        }[outcome]
        resolver.refresh_domain.side_effect = VerificationError(
            code, outcome, transient=outcome == "unavailable"
        )
    elif outcome in {"expired", "ku", "tls"}:
        def refresh(*args, **kwargs):
            if outcome == "expired":
                later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=400)
                monkeypatch.setattr("dnsid.wba_verifier._now", lambda: later)
            elif outcome == "tls":
                fresh.tls_cert.not_after = datetime.datetime.now(datetime.UTC)
            else:
                fresh.record.ku = f"https://{DOMAIN}/.well-known/http-message-signatures-directory"
            return fresh
        resolver.refresh_domain.side_effect = refresh
    if outcome == "success":
        assert verifier.verify_web_bot_auth_signed_request(req, opts) is fresh
    else:
        with pytest.raises(VerificationError) as error:
            verifier.verify_web_bot_auth_signed_request(req, opts)
        if outcome in {"revoked", "denied", "unavailable"}:
            assert error.value.code == code
            assert error.value.transient == (outcome == "unavailable")
    resolver.refresh_domain.assert_called_once_with(DOMAIN, peer_cert=opts.peer_cert)


def test_refresh_cooldown_covers_url_and_key_changes_and_failed_attempts(setup, monkeypatch):
    provider, resolver, verifier, req, opts, hook, _ = setup
    clock = [100.0]
    monkeypatch.setattr("dnsid.wba_verifier.time.monotonic", lambda: clock[0])
    resolver.verify_domain.return_value.jwks = JWKS(keys=[LocalKeyProvider.generate().signing_key()])
    resolver.refresh_domain.side_effect = VerificationError(VerificationCode.STATUS_UNAVAILABLE, "down")
    with pytest.raises(VerificationError, match="down"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    provider = LocalKeyProvider.generate()
    hook.side_effect = lambda response: serve_http_message_signatures_directory(
        HttpRequest(method="GET", url=f"https://{DOMAIN}/other?key=2"), provider
    )
    WBAHttpSigner(provider, DOMAIN, config=WebBotAuthConfig(
        signature_agent_uri=f"https://{DOMAIN}/other?key=2", signature_agent_type="jwks_uri",
    )).sign(req)
    clock[0] += 4.9
    with pytest.raises(VerificationError, match="suppressed"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert resolver.refresh_domain.call_count == 1
    clock[0] += 0.1
    with pytest.raises(VerificationError, match="down"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert resolver.refresh_domain.call_count == 2
    verifier._refresh_deadlines = {str(i): float("inf") for i in range(1024)}
    with pytest.raises(VerificationError, match="suppressed"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert len(verifier._refresh_deadlines) == 1024


def test_concurrent_mismatches_share_admission_not_peer_policy(setup):
    _, resolver, verifier, req, opts, _, _ = setup
    fresh = resolver.verify_domain.return_value
    resolver.verify_domain.return_value = replace(
        fresh, jwks=JWKS(keys=[LocalKeyProvider.generate().signing_key()])
    )
    started, release = threading.Event(), threading.Event()

    def refresh(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return fresh

    resolver.refresh_domain.side_effect = refresh
    with ThreadPoolExecutor(max_workers=2) as pool:
        leader = pool.submit(verifier.verify_web_bot_auth_signed_request, req, opts)
        try:
            assert started.wait(5)
            for _ in range(8):
                with pytest.raises(VerificationError, match="suppressed"):
                    verifier.verify_web_bot_auth_signed_request(req, opts)
        finally:
            release.set()
        assert leader.result(5) is fresh
    assert resolver.refresh_domain.call_count == 1


def test_uncached_directory_always_revalidates_and_never_retries_fresh_key_miss(setup):
    _, resolver, _, req, opts, _, _ = setup
    requests = []
    other = LocalKeyProvider.generate()

    def missing(request):
        requests.append(request)
        directory = serve_http_message_signatures_directory(
            HttpRequest(method="GET", url=str(request.url)), other
        )
        return httpx.Response(200, headers=directory.headers, content=directory.body)

    verifier = WBAHttpVerifier(resolver, transport=httpx.MockTransport(missing))
    for _ in range(2):
        with pytest.raises(VerificationError, match="matching directory key"):
            verifier.verify_web_bot_auth_signed_request(req, opts)
    assert len(requests) == 2
    assert all(request.headers["cache-control"] == "no-cache" for request in requests)
    assert all("if-none-match" not in request.headers for request in requests)
    resolver.refresh_domain.assert_not_called()


def test_manager_refresh_replaces_cache_and_failure_never_falls_back(ec_pair):
    manager, _, counters, domain, fetch_jwks, fetch_status, active = _manager_fixture(ec_pair)
    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks) as fetch,
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
    ):
        old = manager.verify_domain(domain)
        key = LocalKeyProvider.generate().signing_key()

        def rotated(uri, allowed_host, **kwargs):
            jwks, cert = fetch_jwks(uri, allowed_host, **kwargs)
            return (JWKS(keys=[key]) if uri.startswith(f"https://{domain}/") else jwks), cert

        fetch.side_effect = rotated
        fresh = manager.refresh_domain(domain.upper() + ".")
        assert fresh.jwks.keys == [key]
        assert manager.verify_domain(domain) is fresh
        assert counters["dns"] == counters["status"] == 2
        assert old is not fresh
        fetch.side_effect = VerificationError(VerificationCode.TLS_ERROR, "unavailable")
        with pytest.raises(VerificationError, match="unavailable"):
            manager.refresh_domain(domain)
        assert manager._cache.get(domain) is fresh
        fetch.side_effect = rotated
        with patch.object(manager, "_enforce_counterparty_acceptance") as acceptance:
            acceptance.side_effect = VerificationError(
                VerificationCode.COUNTERPARTY_NOT_ACCEPTED, "denied"
            )
            with pytest.raises(VerificationError, match="denied"):
                manager.refresh_domain(domain)
            acceptance.assert_called_once()
        with patch("dnsid.manager._fetch_strict_json_status", return_value=replace(
            active, state="REVOKED", revocation_reason="keyCompromise",
        )):
            with pytest.raises(VerificationError) as error:
                manager.refresh_domain(domain)
            assert error.value.code == VerificationCode.STATUS_NOT_ACTIVE
            assert manager._cache.get(domain) is None
    manager.close()


@pytest.mark.parametrize("outcome", ["active", "revoked", "zero-ttl"])
def test_slow_status_lookup_cannot_restore_old_key_after_full_refresh(ec_pair, outcome):
    manager, resolver, _, domain, fetch_jwks, fetch_status, active = _manager_fixture(
        ec_pair, interval=datetime.timedelta(0)
    )
    started, release = threading.Event(), threading.Event()

    def slow_status(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return active

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status) as status,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        old = manager.verify_domain(domain)
        status.side_effect = slow_status
        lookup = pool.submit(manager.verify_domain, domain)
        try:
            assert started.wait(5)
            status.side_effect = fetch_status
            if outcome == "revoked":
                status.side_effect = lambda *args, **kwargs: replace(
                    active, state="REVOKED", revocation_reason="keyCompromise",
                )
                with pytest.raises(VerificationError):
                    manager.refresh_domain(domain)
            else:
                if outcome == "zero-ttl":
                    resolver.records[f"_dnsid.{domain}"].ttl = 0
                fresh = manager.refresh_domain(domain)
                assert fresh is not old
        finally:
            release.set()
        if outcome == "active":
            assert lookup.result(5) is fresh
            assert manager._cache.get(domain) is fresh
        else:
            with pytest.raises(VerificationError, match="invalidated during status refresh"):
                lookup.result(5)
            assert manager._cache.get(domain) is None
    manager.close()


@pytest.mark.parametrize("peer", [None, "wrong.example"])
def test_manager_refresh_enforces_current_peer(ec_pair, peer):
    from dnsid import TLSCertificate

    manager, _, _, domain, fetch_jwks, fetch_status, _ = _manager_fixture(ec_pair, mtls=True)
    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
    ):
        manager.verify_domain(domain, TLSCertificate(san_dns_names=[domain]))
        with pytest.raises(VerificationError) as error:
            manager.refresh_domain(domain, TLSCertificate(san_dns_names=[peer]) if peer else None)
        assert error.value.code == VerificationCode.TLS_ERROR
    manager.close()


@pytest.mark.parametrize("resource", ["jwks", "status", "log"])
@pytest.mark.parametrize("revalidate", [False, True])
def test_identity_resource_transports_revalidate(resource, revalidate):
    from dnsid._https_client import fetch_agent_status, fetch_jwks
    from tests.test_c2sp_resource_fetcher import _mock_fetcher

    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={
            "keys": [], "state": "ACTIVE", "lastTransitionAt": "2026-01-01T00:00:00Z",
        })

    transport = httpx.MockTransport(handle)
    url = f"https://{DOMAIN}/resource"
    if resource == "log":
        fetcher = _mock_fetcher(transport)
        fetcher.fetch_bounded(url, 1024)
        fetcher.close()
    elif resource == "jwks":
        fetch_jwks(url, DOMAIN, transport=transport, revalidate=revalidate)
    else:
        fetch_agent_status(url, transport=transport, revalidate=revalidate)
    assert requests[0].headers.get("cache-control") == (
        "no-cache" if revalidate or resource == "log" else None
    )
