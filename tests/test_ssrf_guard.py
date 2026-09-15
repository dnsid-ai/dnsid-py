"""Tests for the status-endpoint (su) SSRF guard.

The su host comes from the attacker-controllable TXT record, so status
fetches reject a host that resolves to a non-public address unless that exact
hostname is configured in TransportConfig.private_address_hosts.
"""

from __future__ import annotations

from unittest.mock import patch

import httpcore
import pytest

from dnsid._https_client import SSRF_BLOCK_MARKER, fetch_agent_status, fetch_jwks
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.models import TransportConfig
from dnsid.safe_transport import (
    _is_allowed_loopback_resolution,
    is_disallowed_ip,
    make_ssrf_safe_transport,
    resolve_checked_address,
)


class TestIsDisallowedIp:
    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "18.67.65.117",
            "1.1.1.1",
            "2606:4700:4700::1111",
        ],
    )
    def test_public_allowed(self, ip):
        assert is_disallowed_ip(ip) is False

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",  # loopback
            "10.0.0.5",  # private
            "192.168.1.1",  # private
            "172.16.0.1",  # private
            "169.254.169.254",  # link-local (cloud metadata)
            "100.64.0.1",  # CGNAT
            "0.0.0.0",  # unspecified
            "::1",  # ipv6 loopback
            "fe80::1",  # ipv6 link-local
            "fc00::1",  # ipv6 ULA
            "::ffff:127.0.0.1",  # ipv4-mapped loopback
            "not-an-ip",  # unparseable → fail closed
        ],
    )
    def test_non_public_blocked(self, ip):
        assert is_disallowed_ip(ip) is True


class TestResolveChecked:
    def test_blocks_private_resolution(self):
        with patch("dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]):
            with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
                resolve_checked_address("evil.example")

    def test_allows_private_for_exact_configured_host(self):
        with patch("dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]):
            assert (
                resolve_checked_address(
                    "registry.dev.dnsid.test",
                    private_address_hosts={"registry.dev.dnsid.test"},
                )
                == "127.0.0.1"
            )

    def test_leading_dot_entry_allows_domain_and_subdomains_only(self):
        with patch("dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]):
            for host in ("dnsid.test", "agent.dnsid.test", "Deep.Peer.DNSID.test."):
                assert (
                    resolve_checked_address(host, private_address_hosts={".dnsid.test"})
                    == "127.0.0.1"
                )
            for host in ("evildnsid.test", "dnsid.test.attacker.example"):
                with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
                    resolve_checked_address(host, private_address_hosts={".dnsid.test"})

    def test_private_host_allowlist_does_not_apply_to_other_hosts(self):
        with patch("dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]):
            with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
                resolve_checked_address(
                    "attacker.example",
                    private_address_hosts={"registry.dev.dnsid.test"},
                )

    def test_returns_public_ip(self):
        with patch(
            "dnsid.safe_transport._resolve_addresses", return_value=["18.67.65.117"]
        ):
            assert resolve_checked_address("app.dnsid.dev") == "18.67.65.117"

    def test_rejects_entire_dns_answer_when_any_address_is_unsafe(self):
        with patch(
            "dnsid.safe_transport._resolve_addresses",
            return_value=["18.67.65.117", "169.254.169.254"],
        ):
            with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
                resolve_checked_address("rebinding.example")

    def test_ip_literal_host_is_checked_directly(self):
        # A private IP literal is rejected without any resolver call.
        with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
            resolve_checked_address("10.0.0.1")

    def test_explicit_loopback_host_allows_only_loopback_resolution(self):
        with patch("dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]):
            assert resolve_checked_address(
                "localhost", allow_loopback_host="localhost"
            ) == "127.0.0.1"

    def test_explicit_loopback_host_rejects_non_loopback_resolution(self):
        with patch("dnsid.safe_transport._resolve_addresses", return_value=["10.0.0.1"]):
            with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
                resolve_checked_address(
                    "localhost", allow_loopback_host="localhost"
                )

    def test_loopback_exception_does_not_apply_to_other_hosts(self):
        with patch("dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]):
            with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
                resolve_checked_address(
                    "internal.example",
                    allow_loopback_host="localhost",
                )

    def test_loopback_resolution_helper_requires_exact_host_and_loopback_ip(self):
        assert _is_allowed_loopback_resolution("localhost", "127.0.0.1", "localhost")
        assert not _is_allowed_loopback_resolution("other", "127.0.0.1", "localhost")
        assert not _is_allowed_loopback_resolution("localhost", "10.0.0.1", "localhost")


class TestStatusFetchSsrf:
    def test_private_su_host_raises_clean_error(self):
        # Route a public-looking su host to a private IP; the guarded transport
        # must fail closed with a non-transient TLS_ERROR, never connecting.
        transport = make_ssrf_safe_transport(TransportConfig())
        with patch(
            "dnsid.safe_transport._resolve_addresses",
            return_value=["169.254.169.254"],
        ):
            with pytest.raises(VerificationError) as exc:
                fetch_agent_status(
                    "https://metadata.attacker.example/status", transport=transport
                )
        assert exc.value.code == VerificationCode.TLS_ERROR
        assert exc.value.transient is False
        assert "SSRF" in str(exc.value)

    def test_allowlisted_transport_does_not_block_exact_host(self):
        # The configured hostname may resolve privately; the connection then
        # fails on its own, but never via the SSRF guard.
        transport = make_ssrf_safe_transport(
            TransportConfig(
                private_address_hosts=frozenset({"registry.dev.dnsid.test"})
            )
        )
        with patch(
            "dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]
        ):
            with pytest.raises(VerificationError) as exc:
                fetch_agent_status(
                    "https://registry.dev.dnsid.test/status", transport=transport
                )
        # Not the SSRF path: either a transient connection error or similar.
        assert "SSRF" not in str(exc.value)

    def test_private_jwks_host_uses_same_guard(self):
        transport = make_ssrf_safe_transport()
        with patch(
            "dnsid.safe_transport._resolve_addresses",
            return_value=["169.254.169.254"],
        ):
            with pytest.raises(VerificationError) as exc:
                fetch_jwks(
                    "https://metadata.attacker.example/jwks",
                    "metadata.attacker.example",
                    transport=transport,
                )
        assert exc.value.code == VerificationCode.TLS_ERROR
        assert SSRF_BLOCK_MARKER in str(exc.value)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
