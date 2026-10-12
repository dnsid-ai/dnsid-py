"""Async hot-path verification, shared evidence and synchronous API parity."""

import asyncio
import datetime
import threading
from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dnsid import AsyncIdentityResolver, TrustedEntity, verification_budget
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.http_signatures import HttpSignatureProfile
from dnsid.models import TLSCertificate
from tests.test_http_signing import TestVerifySignedHttpRequest as _SignatureFixture
from tests.test_verification_coalescing import _manager_fixture


async def _started(event):
    async with asyncio.timeout(2):
        while not event.is_set():
            await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_cold_calls_share_one_worker_and_hot_calls_need_none(ec_pair):
    manager, resolver, counters, domain, keys, status, _ = _manager_fixture(ec_pair)
    resolver.started = threading.Event()
    resolver.release = threading.Event()
    loop = asyncio.get_running_loop()
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
        patch.object(loop, "run_in_executor", wraps=loop.run_in_executor) as workers,
    ):
        calls = [asyncio.create_task(manager.async_verify_domain(domain)) for _ in range(32)]
        try:
            await _started(resolver.started)
            assert workers.call_count == 1
        finally:
            resolver.release.set()
        results = await asyncio.gather(*calls)
        assert all(result is results[0] for result in results)
        assert await manager.async_verify_domain(domain) is results[0]
        assert workers.call_count == 1
    assert counters == Counter(dns=1, ek=1, ku=1, status=1, bilateral=1, continuity=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_leader", [False, True])
async def test_cancellation_does_not_cancel_shared_evidence(ec_pair, cancel_leader):
    manager, resolver, _, domain, keys, status, _ = _manager_fixture(ec_pair)
    resolver.started = threading.Event()
    resolver.release = threading.Event()
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        leader = asyncio.create_task(manager.async_verify_domain(domain))
        await _started(resolver.started)
        follower = asyncio.create_task(manager.async_verify_domain(domain))
        await asyncio.sleep(0)
        cancelled, survivor = (leader, follower) if cancel_leader else (follower, leader)
        try:
            cancelled.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            assert not manager._verification_futures[domain].cancelled()
        finally:
            resolver.release.set()
        result = await survivor
        assert await manager.async_verify_domain(domain) is result
        assert not manager._verification_futures


@pytest.mark.asyncio
async def test_waiter_deadline_does_not_cancel_sync_leader(ec_pair):
    manager, resolver, _, domain, keys, status, _ = _manager_fixture(ec_pair)
    resolver.started = threading.Event()
    resolver.release = threading.Event()
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        leader = asyncio.create_task(asyncio.to_thread(manager.verify_domain, domain))
        await _started(resolver.started)
        try:
            with pytest.raises(VerificationError, match="deadline"):
                with verification_budget(0.01):
                    await manager.async_verify_domain(domain)
        finally:
            resolver.release.set()
        result = await leader
        assert await manager.async_verify_domain(domain) is result


@pytest.mark.asyncio
async def test_failed_verification_can_retry(ec_pair):
    manager, resolver, _, domain, keys, status, _ = _manager_fixture(ec_pair)
    resolver.failure = VerificationError(VerificationCode.DNS_RESOLUTION, "failed", transient=True)
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        with pytest.raises(VerificationError, match="failed"):
            await manager.async_verify_domain(domain)
        assert not manager._verification_futures
        assert (await manager.async_verify_domain(domain)).domain == domain


@pytest.mark.asyncio
async def test_stale_status_refreshes(ec_pair):
    manager, _, counters, domain, keys, status, _ = _manager_fixture(
        ec_pair, interval=datetime.timedelta(0)
    )
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        await manager.async_verify_domain(domain)
        await manager.async_verify_domain(domain)
        assert counters["dns"] == 1
        assert counters["status"] == 2


@pytest.mark.asyncio
async def test_hot_cache_enforces_mtls_and_acceptance(ec_pair):
    manager, _, counters, domain, keys, status, _ = _manager_fixture(ec_pair, mtls=True)
    cert = TLSCertificate(san_dns_names=[domain])
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        await manager.async_verify_domain(domain, peer_cert=cert)
        with pytest.raises(VerificationError):
            await manager.async_verify_domain(domain)
        manager._config.verification.trusted_entities = [TrustedEntity(governance_id="other.example")]
        with pytest.raises(VerificationError) as error:
            await manager.async_verify_domain(domain, peer_cert=cert)
        assert error.value.code == VerificationCode.COUNTERPARTY_NOT_ACCEPTED
        assert counters["dns"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [None, b"", b"hello"])
@pytest.mark.parametrize("legacy", [False, True])
async def test_http_signature_resolution_and_peer_binding(ec_pair, ec_provider, body, legacy):
    signed, _, verified = _SignatureFixture()._sign_and_get_verifier(
        ec_pair, ec_provider, body=body
    )
    cert = TLSCertificate(san_dns_names=["signer.example.com"])
    if legacy:
        resolver = MagicMock(spec=["verify_domain"])
        resolver.verify_domain.return_value = verified
        method = resolver.verify_domain
    else:
        resolver = MagicMock(spec=AsyncIdentityResolver)
        resolver.async_verify_domain = AsyncMock(return_value=verified)
        method = resolver.async_verify_domain
    profile = HttpSignatureProfile(resolver, None, "")
    assert await profile.async_verify_signed_http_request(signed, peer_cert=cert) is verified
    method.assert_called_once_with("signer.example.com", peer_cert=cert)


@pytest.mark.asyncio
async def test_bad_digest_rejected_before_async_resolution(ec_pair, ec_provider):
    signed, _, verified = _SignatureFixture()._sign_and_get_verifier(
        ec_pair, ec_provider, body=b"original"
    )
    resolver = MagicMock(spec=AsyncIdentityResolver)
    resolver.async_verify_domain = AsyncMock(return_value=verified)
    profile = HttpSignatureProfile(resolver, None, "")
    signed.body = b"tampered"
    with pytest.raises(VerificationError, match="Content-Digest"):
        await profile.async_verify_signed_http_request(signed)
    resolver.async_verify_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_bad_signature_rejected_after_async_resolution(ec_pair, ec_provider):
    signed, _, verified = _SignatureFixture()._sign_and_get_verifier(ec_pair, ec_provider)
    resolver = MagicMock(spec=AsyncIdentityResolver)
    resolver.async_verify_domain = AsyncMock(return_value=verified)
    profile = HttpSignatureProfile(resolver, None, "")
    signed.url = "https://verifier.example.com/tampered"
    with pytest.raises(VerificationError, match="signature invalid"):
        await profile.async_verify_signed_http_request(signed)
    resolver.async_verify_domain.assert_awaited_once()


@pytest.mark.asyncio
async def test_zero_ttl_requires_each_call_to_fetch_dns(ec_pair):
    manager, resolver, counters, domain, keys, status, _ = _manager_fixture(ec_pair)
    resolver.records[f"_dnsid.{domain}"].ttl = 0
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        await manager.async_verify_domain(domain)
        await manager.async_verify_domain(domain)
        assert counters["dns"] == 2


@pytest.mark.asyncio
async def test_async_signing_does_not_block_loop(ec_provider):
    from tests.test_signed_async_http_client import _build_profile, _mock_inner

    profile = _build_profile(ec_provider)
    original = profile.create_signed_http_request
    started, release = threading.Event(), threading.Event()

    def blocking_sign(*args):
        started.set()
        assert release.wait(2)
        return original(*args)

    with (
        patch.object(profile, "create_signed_http_request", side_effect=blocking_sign),
        patch("dnsid.manager._make_async_sdk_transport", return_value=_mock_inner()[0]),
    ):
        async with profile.create_signed_async_http_client() as client:
            request = asyncio.create_task(client.get("https://service.example.com/api"))
            try:
                await _started(started)
            finally:
                release.set()
            assert (await request).status_code == 200


@pytest.mark.asyncio
async def test_async_operation_preserves_parent_budget():
    from dnsid._verification_budget import async_verification_operation, remaining_seconds

    @async_verification_operation
    async def operation():
        return remaining_seconds(120)

    with verification_budget(60):
        assert 30 < await operation() <= 60
