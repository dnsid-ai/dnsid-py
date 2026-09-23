"""Consolidated DnsidConfig and counterparty acceptance (design 01: validation matrix)."""

from __future__ import annotations

import datetime
import threading
from collections import Counter
from unittest.mock import MagicMock, patch

import pytest

from dnsid import (
    JWKS,
    DnsidConfig,
    IdentityConfig,
    IdentityManager,
    IdentityManagerDependencies,
    TransportConfig,
    TrustedEntity,
    VerificationConfig,
)
from dnsid.enums import DNSSECMode, DNSSECState, VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.interfaces import DNSResolver, HTTPSFetcher
from dnsid.models import AgentStatus, TLSCertificate, TXTRecord
from tests.conftest import make_ec_p256_pair
from tests.test_verify_domain import _make_signed_txt_record, _stub_log_registry

DOMAIN = "service.example.com"
GI = "example.com"
PIN_OK = "A" * 43  # valid unpadded base64url, 32 bytes


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class _Resolver(DNSResolver):
    def __init__(self, txt: str, counters: Counter[str]) -> None:
        self.txt = txt
        self.counters = counters
        self.lock = threading.Lock()

    def fetch_txt(self, name: str):
        with self.lock:
            self.counters["dns"] += 1
        assert name == f"_dnsid.{DOMAIN}"
        return [TXTRecord(strings=[self.txt.encode("ascii")], ttl=300)], DNSSECState.UNKNOWN


def _identity(**overrides) -> IdentityConfig:
    defaults = dict(
        domain="agent.example.com",
        governance_id="example.com",
        log_ref="microledger:abc123",
        status_url="https://agent.example.com/status",
    )
    defaults.update(overrides)
    return IdentityConfig(**defaults)


def _verifier(
    ec_pair, verification: VerificationConfig, *, identity=None, key_provider=None, cache=None
):
    """Return (manager, counters, ek_key) with patched JWKS/status fetches."""
    private, ek_key = ec_pair
    txt = _make_signed_txt_record(private, ek_key, DOMAIN)
    counters: Counter[str] = Counter()
    resolver = _Resolver(txt, counters)
    _, ku_key = make_ec_p256_pair("ku-acceptance")
    cert = TLSCertificate(not_after=_now() + datetime.timedelta(days=1), san_dns_names=[DOMAIN])
    active = AgentStatus(state="ACTIVE", last_transition_at=_now())

    manager = IdentityManager(
        DnsidConfig(identity=identity, verification=verification),
        key_provider,
        IdentityManagerDependencies(
            dns_resolver=resolver, log_registry=_stub_log_registry(), cache=cache
        ),
    )

    def fetch_jwks(uri, allowed_host, **kwargs):
        counters["ku" if uri.startswith(f"https://{DOMAIN}/") else "ek"] += 1
        return JWKS(keys=[ku_key if uri.startswith(f"https://{DOMAIN}/") else ek_key]), cert

    def fetch_status(su, **kwargs):
        counters["status"] += 1
        return active

    patches = (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
    )
    return manager, counters, ek_key, patches


def _denied(manager, gi=GI):
    with pytest.raises(VerificationError) as exc_info:
        manager.verify_domain(DOMAIN)
    err = exc_info.value
    assert err.code is VerificationCode.COUNTERPARTY_NOT_ACCEPTED
    assert err.transient is False
    assert err.verified_governance_id == gi
    return err


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_same_verification_settings_with_and_without_identity(self, ec_provider):
        verification = VerificationConfig(
            dnssec_mode=DNSSECMode.VALIDATED,
            status_check_interval=datetime.timedelta(seconds=7),
            trusted_entities=[TrustedEntity("Example.COM.")],
        )
        deps = IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver))
        local = IdentityManager(DnsidConfig(_identity(), verification), ec_provider, deps)
        only = IdentityManager(DnsidConfig(verification=verification), deps=deps)
        assert local.config.verification == only.config.verification
        assert only.config.verification.trusted_entities == (TrustedEntity("example.com"),)
        assert IdentityManager(deps=deps).config.verification == VerificationConfig()

    def test_caller_mutation_after_construction_does_not_affect_manager(self):
        entities = [TrustedEntity(GI)]
        transport = TransportConfig(dns_server="")
        config = DnsidConfig(
            verification=VerificationConfig(trusted_entities=entities), transport=transport
        )
        manager = IdentityManager(
            config, deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver))
        )
        entities.append(TrustedEntity("evil.example"))
        entities.clear()
        config.verification.dnssec_mode = DNSSECMode.REQUIRED
        transport.dns_server = "1.2.3.4:53"
        snapshot = manager.config
        assert snapshot.verification.trusted_entities == (TrustedEntity(GI),)
        assert snapshot.verification.dnssec_mode is DNSSECMode.AUTO
        assert snapshot.transport.dns_server == ""
        # The accessor returns a copy, too.
        snapshot.verification.trusted_entities = None
        assert manager.config.verification.trusted_entities == (TrustedEntity(GI),)

    @pytest.mark.parametrize(
        "verification",
        [
            VerificationConfig(status_check_interval=datetime.timedelta(seconds=-1)),
            VerificationConfig(status_check_interval=5),  # type: ignore[arg-type]
            VerificationConfig(dnssec_mode="required"),  # type: ignore[arg-type]
            VerificationConfig(trusted_entities="example.com"),  # type: ignore[arg-type]
            VerificationConfig(trusted_entities=[GI]),  # type: ignore[list-item]
            VerificationConfig(trusted_entities=[TrustedEntity("")]),
            VerificationConfig(trusted_entities=[TrustedEntity("bad..example")]),
            VerificationConfig(trusted_entities=[TrustedEntity(GI), TrustedEntity("EXAMPLE.com.")]),
            VerificationConfig(trusted_entities=[TrustedEntity(GI, ())]),
            VerificationConfig(trusted_entities=[TrustedEntity(GI, ("not base64url!",))]),
            VerificationConfig(trusted_entities=[TrustedEntity(GI, ("AAAA",))]),  # wrong length
            VerificationConfig(trusted_entities=[TrustedEntity(GI, (PIN_OK + "=",))]),  # padded
            VerificationConfig(trusted_entities=[TrustedEntity(GI, (PIN_OK, PIN_OK))]),
        ],
    )
    def test_invalid_verification_config_fails_before_network(self, verification):
        resolver = MagicMock(spec=DNSResolver)
        with pytest.raises(ArgumentError):
            IdentityManager(
                DnsidConfig(verification=verification),
                deps=IdentityManagerDependencies(dns_resolver=resolver),
            )
        resolver.fetch_txt.assert_not_called()

    def test_unknown_setting_rejected_with_argument_error(self):
        with pytest.raises(ArgumentError, match="trusted"):
            VerificationConfig(trusted=True)  # type: ignore[call-arg]
        with pytest.raises(ArgumentError, match="registry_url"):
            DnsidConfig(registry_url="https://x")  # type: ignore[call-arg]
        with pytest.raises(ArgumentError, match="allow_private"):
            TransportConfig(allow_private=True)  # type: ignore[call-arg]
        with pytest.raises(ArgumentError, match="governance_id"):
            TrustedEntity()  # type: ignore[call-arg]
        with pytest.raises(ArgumentError, match="domain"):
            IdentityConfig()  # type: ignore[call-arg]

    def test_dns_server_with_only_resolver_injected_configures_fetcher(self):
        with patch("dnsid.manager._make_sdk_transport") as make_transport:
            manager = IdentityManager(
                DnsidConfig(transport=TransportConfig(dns_server="10.0.0.1:53")),
                deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver)),
            )
        make_transport.assert_called_once()
        assert make_transport.call_args.args[0].dns_server == "10.0.0.1:53"
        manager.close()

    def test_dns_server_with_only_fetcher_injected_configures_resolver(self):
        with patch("dnsid.manager._default_dns_resolver") as default_resolver:
            IdentityManager(
                DnsidConfig(transport=TransportConfig(dns_server="10.0.0.1:53")),
                deps=IdentityManagerDependencies(https_fetcher=MagicMock(spec=HTTPSFetcher)),
            )
        assert default_resolver.call_args.args[0].dns_server == "10.0.0.1:53"

    def test_transport_settings_without_consumer_are_rejected(self):
        both = IdentityManagerDependencies(
            dns_resolver=MagicMock(spec=DNSResolver), https_fetcher=MagicMock(spec=HTTPSFetcher)
        )
        with pytest.raises(ArgumentError, match="dns_server"):
            IdentityManager(
                DnsidConfig(transport=TransportConfig(dns_server="10.0.0.1:53")), deps=both
            )
        with pytest.raises(ArgumentError, match="ca_bundle_path"):
            IdentityManager(
                DnsidConfig(transport=TransportConfig(ca_bundle_path="/ca.pem")),
                deps=IdentityManagerDependencies(https_fetcher=MagicMock(spec=HTTPSFetcher)),
            )
        # A resolver-only injection leaves the default fetcher as the CA consumer.
        with patch("dnsid.manager._make_sdk_transport") as make_transport:
            IdentityManager(
                DnsidConfig(transport=TransportConfig(ca_bundle_path="/ca.pem")),
                deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver)),
            ).close()
        assert make_transport.call_args.args[0].ca_bundle_path == "/ca.pem"

    @pytest.mark.parametrize(
        "transport",
        [
            TransportConfig(dns_server=None),  # type: ignore[arg-type]
            TransportConfig(dns_server=5353),  # type: ignore[arg-type]
            TransportConfig(ca_bundle_path=b"/ca.pem"),  # type: ignore[arg-type]
            TransportConfig(private_address_hosts=".test"),  # type: ignore[arg-type]
            TransportConfig(private_address_hosts=frozenset({1})),  # type: ignore[arg-type]
        ],
    )
    def test_mistyped_transport_fields_fail_before_network(self, transport):
        resolver = MagicMock(spec=DNSResolver)
        with pytest.raises(ArgumentError, match="transport\\."):
            IdentityManager(
                DnsidConfig(transport=transport),
                deps=IdentityManagerDependencies(dns_resolver=resolver),
            )
        resolver.fetch_txt.assert_not_called()

    @pytest.mark.parametrize(
        ("overrides", "match"),
        [
            ({"status_url": None}, "identity.status_url must be a string"),
            ({"ek_url": 42}, "identity.ek_url must be a string"),
            ({"ku_url": ["https://agent.example.com/jwks"]}, "identity.ku_url must be a string"),
            ({"publish_profile": 1}, "identity.publish_profile must be a string"),
            ({"max_key_age": 7}, "identity.max_key_age must be a string"),
            ({"policy_flags": b"mtls"}, "identity.policy_flags must be a string"),
            ({"publish_profile": "dnsid-draft-99"}, "unsupported DNSid publish profile"),
            ({"max_key_age": "1y"}, "identity.max_key_age must be one of"),
            ({"status_url": "http://agent.example.com/status"}, "identity.status_url"),
            ({"ek_url": "ftp://example.com/jwks"}, "identity.ek_url"),
            ({"ku_url": "not a url"}, "identity.ku_url"),
            ({"capabilities_url": "https:///nohost"}, "identity.capabilities_url"),
        ],
    )
    def test_invalid_identity_config_fails_before_network(self, ec_provider, overrides, match):
        resolver = MagicMock(spec=DNSResolver)
        with pytest.raises(ArgumentError, match=match):
            IdentityManager(
                DnsidConfig(identity=_identity(**overrides)),
                ec_provider,
                deps=IdentityManagerDependencies(dns_resolver=resolver),
            )
        resolver.fetch_txt.assert_not_called()

    def test_valid_identity_config_accepted(self, ec_provider):
        IdentityManager(
            DnsidConfig(
                identity=_identity(
                    ek_url="https://example.com/jwks",
                    ku_url="https://agent.example.com/jwks",
                    max_key_age="30d",
                    publish_profile="dnsid-draft-01",
                )
            ),
            ec_provider,
            deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver)),
        ).close()

    def test_private_address_hosts_with_fetcher_injected_is_rejected(self):
        with pytest.raises(ArgumentError, match="private_address_hosts"):
            IdentityManager(
                DnsidConfig(transport=TransportConfig(private_address_hosts=frozenset({".test"}))),
                deps=IdentityManagerDependencies(https_fetcher=MagicMock(spec=HTTPSFetcher)),
            )

    @pytest.mark.parametrize(
        "entry",
        ["", ".", "127.0.0.1", "::1", "[::1]", ".10.0.0.0", "agent.test:443", "https://agent.test",
         "agent.test/path", "user@agent.test", "user:pw@agent.test", "a b.test", "-bad.test",
         "..test", "agent..test"],
    )
    def test_invalid_private_address_host_entry_rejected(self, entry):
        with pytest.raises(ArgumentError, match="private_address_hosts"):
            IdentityManager(
                DnsidConfig(transport=TransportConfig(private_address_hosts=frozenset({entry}))),
                deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver)),
            )

    def test_valid_private_address_host_entries_accepted(self):
        with patch("dnsid.manager._make_sdk_transport"):
            IdentityManager(
                DnsidConfig(transport=TransportConfig(
                    private_address_hosts=frozenset({".test", "agent.example.test", "TEST.", "münchen.test"})
                )),
                deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver)),
            ).close()


# ---------------------------------------------------------------------------
# Acceptance decisions
# ---------------------------------------------------------------------------


class TestAcceptance:
    def test_omitted_policy_makes_no_decision(self, ec_pair):
        manager, _, _, patches = _verifier(ec_pair, VerificationConfig())
        with patches[0], patches[1]:
            assert manager.verify_domain(DOMAIN).record.gi == GI

    def test_explicit_empty_allowlist_denies_all(self, ec_pair):
        manager, _, ek_key, patches = _verifier(ec_pair, VerificationConfig(trusted_entities=[]))
        with patches[0], patches[1]:
            err = _denied(manager)
        assert err.verified_entity_key_thumbprint == ek_key.thumbprint()

    def test_exact_gi_accepts_unrelated_agent_domain(self, ec_pair):
        # DOMAIN is beneath GI here, but matching is on gi only; the bilateral
        # binding (stubbed log) establishes accountability, not agent naming.
        manager, _, _, patches = _verifier(
            ec_pair,
            VerificationConfig(
                trusted_entities=[TrustedEntity("other.example"), TrustedEntity(GI)]
            ),
        )
        with patches[0], patches[1]:
            assert manager.verify_domain(DOMAIN).domain == DOMAIN

    @pytest.mark.parametrize(
        "configured", ["service.example.com", "com", "xample.test", "example.co"]
    )
    def test_child_suffix_lookalike_gi_rejected(self, ec_pair, configured):
        manager, _, _, patches = _verifier(
            ec_pair, VerificationConfig(trusted_entities=[TrustedEntity(configured)])
        )
        with patches[0], patches[1]:
            _denied(manager)

    def test_pin_match_accepts_only_current_entity_key(self, ec_pair):
        _, ek_key = ec_pair
        manager, _, _, patches = _verifier(
            ec_pair,
            VerificationConfig(trusted_entities=[TrustedEntity(GI, (PIN_OK, ek_key.thumbprint()))]),
        )
        with patches[0], patches[1]:
            result = manager.verify_domain(DOMAIN)
        expected = ek_key.thumbprint()
        assert result.signing_key_thumbprint == expected
        # Retained as evidence: repeated acceptance checks do not recompute it.
        with patch.object(type(result.signing_key), "thumbprint") as recompute:
            assert result.signing_key_thumbprint == expected
        recompute.assert_not_called()

    def test_pin_matching_only_ku_or_other_key_rejects(self, ec_pair):
        _, ku_key = make_ec_p256_pair("ku-acceptance")  # same key as served at ku
        manager, _, ek_key, patches = _verifier(
            ec_pair,
            VerificationConfig(trusted_entities=[TrustedEntity(GI, (ku_key.thumbprint(), PIN_OK))]),
        )
        with patches[0], patches[1]:
            err = _denied(manager)
        assert err.verified_entity_key_thumbprint == ek_key.thumbprint()
        assert "pin" in err.message

    def test_denial_does_not_disclose_configured_policy(self, ec_pair):
        configured_gi = "allowed-entity.example"
        manager, _, ek_key, patches = _verifier(
            ec_pair,
            VerificationConfig(trusted_entities=[TrustedEntity(configured_gi, (PIN_OK,))]),
        )
        with patches[0], patches[1]:
            err = _denied(manager)
        observed = (GI, ek_key.thumbprint())
        assert err.verified_governance_id == GI
        assert err.verified_entity_key_thumbprint == ek_key.thumbprint()
        for secret in (configured_gi, PIN_OK):
            assert not any(secret in value for value in observed)
            assert secret not in str(err)
            assert secret not in err.message

    def test_verified_domain_carries_no_trust_flag(self, ec_pair):
        manager, _, _, patches = _verifier(
            ec_pair, VerificationConfig(trusted_entities=[TrustedEntity(GI)])
        )
        with patches[0], patches[1]:
            result = manager.verify_domain(DOMAIN)
        assert not any("trust" in name or "accept" in name for name in vars(result))


# ---------------------------------------------------------------------------
# Cache and coalescing interaction
# ---------------------------------------------------------------------------


class TestAcceptanceAndCache:
    def test_fresh_denial_caches_evidence_and_reevaluates(self, ec_pair):
        manager, counters, _, patches = _verifier(
            ec_pair,
            VerificationConfig(
                trusted_entities=[], status_check_interval=datetime.timedelta(minutes=5)
            ),
        )
        with patches[0], patches[1]:
            _denied(manager)
            assert manager._cache.get(DOMAIN) is not None  # evidence cached before acceptance
            _denied(manager)  # cache hit, no refresh due: still rejects
        assert counters["dns"] == 1 and counters["status"] == 1

    def test_status_refresh_then_denial_keeps_refreshed_status(self, ec_pair):
        manager, counters, _, patches = _verifier(
            ec_pair,
            VerificationConfig(trusted_entities=[], status_check_interval=datetime.timedelta(0)),
        )
        with patches[0], patches[1]:
            _denied(manager)
            first = manager._cache.get(DOMAIN)
            _denied(manager)  # zero interval: refresh, cache, then deny again
            second = manager._cache.get(DOMAIN)
        assert counters["dns"] == 1 and counters["status"] == 2
        assert second.last_status_check_at >= first.last_status_check_at
        assert second.dns_expires_at == first.dns_expires_at  # refresh never extends expiry

    def test_concurrent_denied_invocations_all_reject(self, ec_pair):
        manager, counters, _, patches = _verifier(
            ec_pair, VerificationConfig(trusted_entities=[TrustedEntity("nobody.example")])
        )
        errors: list[BaseException] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def call():
            barrier.wait()
            try:
                manager.verify_domain(DOMAIN)
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        with patches[0], patches[1]:
            threads = [threading.Thread(target=call) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(5)
        assert len(errors) == 8
        assert all(e.code is VerificationCode.COUNTERPARTY_NOT_ACCEPTED for e in errors)
        assert counters["dns"] == 1  # protocol work shared, acceptance per invocation

    def test_different_policies_do_not_share_cache(self, ec_pair):
        from dnsid.manager import _InMemoryCache

        backend = _InMemoryCache()
        allow, _, _, patches = _verifier(
            ec_pair, VerificationConfig(trusted_entities=[TrustedEntity(GI)]), cache=backend
        )
        deny, counters, _, _ = _verifier(
            ec_pair, VerificationConfig(trusted_entities=[]), cache=backend
        )
        with patches[0], patches[1]:
            allow.verify_domain(DOMAIN)
            _denied(deny)
        assert counters["dns"] == 1  # deny manager did its own lookup; no shared decision


# ---------------------------------------------------------------------------
# Local identity and registry publication
# ---------------------------------------------------------------------------


class TestLocalIdentity:
    def test_public_verify_domain_on_local_domain_still_enforces_acceptance(
        self, ec_pair, ec_provider
    ):
        _, ku_key = make_ec_p256_pair("ku-acceptance")
        identity = _identity(domain=DOMAIN, governance_id=GI)
        manager, _, _, patches = _verifier(
            ec_pair,
            VerificationConfig(trusted_entities=[TrustedEntity("someone-else.example")]),
            identity=identity,
            key_provider=ec_provider,
        )
        with patches[0], patches[1]:
            _denied(manager)  # no self-acceptance exception in the public API
            # The internal protocol-only path used for publication confirmation succeeds.
            assert manager._verify_publication_evidence(DOMAIN).domain == DOMAIN
