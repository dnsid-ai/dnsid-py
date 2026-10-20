"""Tests for HttpSignatureProfile.create_signed_async_http_client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from dnsid import JWKS, DnsidConfig, IdentityConfig, IdentityManager, IdentityManagerDependencies
from dnsid.exceptions import ArgumentError
from dnsid.http_signatures import HttpSignatureProfile
from dnsid.models import (
    HttpRequest,
    HttpSigningOptions,
    HttpVerificationOptions,
    TransportConfig,
    VerifiedDomain,
)
from tests.conftest import MockDNSResolver


def _build_profile(provider, domain="agent.example.com", transport_config=None):
    with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
        mgr = IdentityManager(
            DnsidConfig(
                identity=IdentityConfig(
                    domain=domain,
                    governance_id="example.com",
                    log_ref="microledger:abc",
                    status_url=f"https://{domain}/status",
                ),
                transport=transport_config or TransportConfig(),
            ),
            provider,
            deps=IdentityManagerDependencies(dns_resolver=MockDNSResolver()),
        )
    return HttpSignatureProfile.from_identity_manager(mgr)


def _transport():
    captured = []

    async def handle(request):
        captured.append(request)
        return httpx.Response(200)

    return httpx.MockTransport(handle), captured


@pytest.mark.asyncio
class TestCreateSignedAsyncHttpClient:
    async def test_returns_async_client(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, _ = _transport()
        async with profile.create_signed_async_http_client(transport=transport) as client:
            assert isinstance(client, httpx.AsyncClient)

    async def test_from_manager_inherits_transport_config(self, ec_provider):
        config = TransportConfig(dns_server="127.0.0.1:5353")
        profile = _build_profile(ec_provider, transport_config=config)
        inner, _ = _transport()
        with patch("dnsid.manager._make_async_sdk_transport", return_value=inner) as make_transport:
            async with profile.create_signed_async_http_client():
                pass
        make_transport.assert_called_once_with(config)

    async def test_injected_transport_is_owned_and_default_routing_is_not_used(self, ec_provider):
        profile = _build_profile(ec_provider, transport_config=TransportConfig(dns_server="127.0.0.1:5353"))
        transport, captured = _transport()
        with (
            patch("dnsid.manager._make_async_sdk_transport", side_effect=AssertionError("unexpected default")),
            patch.object(transport, "aclose", wraps=transport.aclose) as close,
        ):
            async with profile.create_signed_async_http_client(transport=transport) as client:
                await client.post("https://peer.example.com/api", content=b"hello")
            close.assert_awaited_once()
        assert captured[0].headers.get("signature")

    async def test_injected_transport_rejects_explicit_transport_config(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, _ = _transport()
        with patch.object(transport, "aclose", wraps=transport.aclose) as close:
            with pytest.raises(ArgumentError, match="mutually exclusive"):
                profile.create_signed_async_http_client(transport=transport, transport_config=TransportConfig())
            close.assert_not_awaited()
        await transport.aclose()

    async def test_outbound_request_has_signature_headers(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        async with profile.create_signed_async_http_client(transport=transport) as client:
            await client.post("https://peer.example.com/api", content=b"hello")
        assert len(captured) == 1
        assert captured[0].headers.get("signature-input")
        assert captured[0].headers.get("signature")

    async def test_body_adds_content_digest(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        async with profile.create_signed_async_http_client(transport=transport) as client:
            await client.post("https://peer.example.com/api", content=b"hello")
        req = captured[0]
        assert req.headers.get("content-digest")
        assert '"content-digest"' in req.headers.get("signature-input", "")

    async def test_explicit_empty_body_adds_content_digest(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        async with profile.create_signed_async_http_client(transport=transport) as client:
            await client.post("https://peer.example.com/api", content=b"")
        req = captured[0]
        assert req.headers.get("content-digest") == (
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        )
        assert '"content-digest"' in req.headers.get("signature-input", "")

    async def test_absent_body_does_not_add_content_digest(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        async with profile.create_signed_async_http_client(transport=transport) as client:
            await client.post("https://peer.example.com/api")
        req = captured[0]
        assert req.headers.get("content-digest") is None
        assert '"content-digest"' not in req.headers.get("signature-input", "")

    async def test_base_headers_forwarded_to_peer(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        async with profile.create_signed_async_http_client(
            base_headers={"x-custom": "value"}, transport=transport,
        ) as client:
            await client.get("https://peer.example.com/api")
        assert captured[0].headers.get("x-custom") == "value"

    async def test_additional_components_covered_by_signature(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        opts = HttpSigningOptions(additional_components=["x-custom"])
        async with profile.create_signed_async_http_client(
            base_headers={"x-custom": "value"}, opts=opts, transport=transport,
        ) as client:
            await client.post("https://peer.example.com/api", content=b"hello")
        assert '"x-custom"' in captured[0].headers.get("signature-input", "")

    async def test_a2a_request_is_cryptographically_valid(self, ec_pair, ec_provider):
        profile = _build_profile(ec_provider, domain="alice.example.com")
        transport, captured = _transport()
        opts = HttpSigningOptions(
            additional_components=["content-type", "a2a-version", "a2a-extensions"],
            tag="a2a-dnsid-http-sig-v1",
        )
        async with profile.create_signed_async_http_client(
            base_headers={
                "content-type": "application/json",
                "a2a-version": "1.0",
                "a2a-extensions": "https://example.com/dnsid",
            },
            opts=opts, transport=transport,
        ) as client:
            await client.post("https://bob.example.com/", json={"jsonrpc": "2.0"})
        request = captured[0]
        signed = HttpRequest(
            method=request.method, url=str(request.url),
            headers=dict(request.headers), body=request.content,
        )
        _, public_key = ec_pair
        verified_domain = MagicMock(spec=VerifiedDomain)
        verified_domain.jwks = JWKS(keys=[public_key])
        verifier = _build_profile(ec_provider, domain="bob.example.com")
        with patch.object(verifier._resolver, "verify_domain", return_value=verified_domain):
            assert verifier.verify_signed_http_request(
                signed,
                HttpVerificationOptions(
                    required_components=[
                        "@method", "@target-uri", "content-type", "content-digest",
                        "a2a-version", "a2a-extensions",
                    ],
                    required_tag="a2a-dnsid-http-sig-v1",
                ),
            ) is verified_domain

    async def test_keyid_encodes_domain_and_kid(self, ec_provider):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        async with profile.create_signed_async_http_client(transport=transport) as client:
            await client.post("https://peer.example.com/api", content=b"hello")
        assert 'keyid="agent.example.com#k1"' in captured[0].headers.get("signature-input", "")

    @pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
    async def test_all_http_methods_are_signed(self, ec_provider, method):
        profile = _build_profile(ec_provider)
        transport, captured = _transport()
        async with profile.create_signed_async_http_client(transport=transport) as client:
            await client.request(method, "https://peer.example.com/api")
        assert captured[0].headers.get("signature-input")
        assert captured[0].headers.get("signature")
