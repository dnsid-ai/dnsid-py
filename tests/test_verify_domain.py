"""Tests for IdentityManager.verify_domain — mocked DNS and HTTP layers."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest

from dnsid import JWKS, DnsidConfig, DnsIdTxtRecord, IdentityManager, IdentityManagerDependencies
from dnsid._crypto import ec_sign
from dnsid._utils import b64url_encode
from dnsid.enums import DNSSECMode, DNSSECState, VerificationCode
from dnsid.exceptions import ArgumentError, ValidationError, VerificationError
from dnsid.interfaces import LogReader
from dnsid.models import (
    AgentStatus,
    LoggedStateEvidence,
    TLSCertificate,
    TXTRecord,
    VerifiedDomain,
)
from dnsid.registry import LogRegistry
from tests._config import make_config
from tests.conftest import MockDNSResolver, make_ec_p256_pair


def _now():
    return datetime.datetime.now(datetime.UTC)


def _make_signed_txt_record(
    private_key, pub_jwk, domain: str, *, bare_sg: bool | None = None, **overrides
) -> str:
    """Build a fully-signed _dnsid TXT record string for *domain*.

    Defaults to the numbered publish selector. Pass ``v="DNSid1"`` to
    exercise the pre-RFC moving verification selector with identical behavior.
    """
    gi = ".".join(domain.split(".")[-2:])
    defaults = dict(
        v="dnsid-draft-01",
        gi=gi,
        ek=f"https://{gi}/.well-known/jwks.json",
        ku=f"https://{domain}/.well-known/jwks.json",
        lr="microledger:abc123",
        su=f"https://{domain}/status",
        identity_fqdn=domain,
    )
    defaults.update(overrides)
    record = DnsIdTxtRecord(**defaults)
    canonical = record.canonical().encode("ascii")
    sig = ec_sign(private_key, pub_jwk.alg, canonical)
    if bare_sg is None:
        bare_sg = record.v in {"dnsid-draft-01", "DNSid1"}
    record.sg = b64url_encode(sig) if bare_sg else pub_jwk.alg + ":" + b64url_encode(sig)
    return record.serialize()




def _make_txt_record(raw: str, ttl: int = 300) -> TXTRecord:
    return TXTRecord(strings=[raw.encode("ascii")], ttl=ttl)


def _split_jwks_fetch(ek_jwks, target, tls_cert):
    """_fetch_jwks side_effect serving *ek_jwks* at the ek URI and a distinct
    operational key at the ku URI — the two-key model requires ek != ku material."""
    _, ku_only = make_ec_p256_pair("ku-only")
    ku_jwks = JWKS(keys=[ku_only])
    return _routed_jwks_fetch(ek_jwks, ku_jwks, target, tls_cert)


def _routed_jwks_fetch(ek_jwks, ku_jwks, target, tls_cert):
    """_fetch_jwks side_effect routing the ku URI (https://{target}/...) to
    *ku_jwks* and every other URI (the ek endpoint) to *ek_jwks* — the two-key
    model fetches the record-signing (ek) and operational (ku) sets from
    separate endpoints."""
    ku_uri = f"https://{target}/.well-known/jwks.json"

    def fetch(uri, allowed_host, transport=None, **kwargs):
        return (ku_jwks, tls_cert) if uri == ku_uri else (ek_jwks, tls_cert)

    return fetch


def _make_config(**overrides) -> DnsidConfig:
    defaults = dict(
        domain="verifier.example.com",
        governance_id="example.com",
        log_ref="microledger:abc",
        status_url="https://verifier.example.com/status",
    )
    defaults.update(overrides)
    return make_config(**defaults)


def _build_verifier(provider, config=None, dns_resolver=None, log_registry=None):
    cfg = config or _make_config()
    resolver = dns_resolver or MockDNSResolver()
    if log_registry is None:
        # DNSid1 verification requires binding-level lifecycle checks; the
        # permissive stub satisfies them for tests about other behaviour.
        log_registry = _stub_log_registry()
    with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
        return IdentityManager(
            cfg,
            provider,
            deps=IdentityManagerDependencies(dns_resolver=resolver, log_registry=log_registry),
        )


class _StubLogBinding(LogReader):
    """Permissive log binding for tests that are not about log policy.

    DNSid1 verification requires binding-level lifecycle checks (design doc
    01 §VerifyDomain step 5); this stub satisfies them so tests can exercise
    other verification behaviour without constructing a real log.
    """

    def __init__(self, lr: str) -> None:
        self.lr = lr

    def canonical(self, event):
        return b""

    def key_timestamp(self, domain, key_thumbprint):
        return datetime.datetime.now(datetime.UTC)

    def verify_non_revocation(self, domain, at):
        return None

    def read_event(self, ref):
        raise NotImplementedError

    def rebuild_history(self, domain):
        return []

    def verify_bilateral_binding(self, record, entity_key, operational_key):
        from types import SimpleNamespace

        return SimpleNamespace(
            initial_operational_thumbprint=operational_key.thumbprint(),
            initial_entity_thumbprint=entity_key.thumbprint(),
            timestamp=datetime.datetime.now(datetime.UTC),
        )

    def verify_operational_continuity(
        self, domain, initial_operational_thumbprint, current_operational_thumbprint
    ):
        return None


def _stub_log_registry() -> LogRegistry:
    registry = LogRegistry()
    registry.register("microledger", _StubLogBinding)
    return registry


class TestVerifyDomain:
    def test_verify_domain_success(self, ec_pair, ec_provider):
        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [_make_txt_record(txt_raw)],
            }
        )
        dns_resolver.fetch_txt = lambda name: (
            [_make_txt_record(txt_raw)],
            DNSSECState.UNKNOWN,
        )

        active_status = AgentStatus(
            state="ACTIVE",
            last_transition_at=_now(),
        )
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            result = mgr.verify_domain(target)

        assert result.domain == target
        assert result.signing_key.kid == "k1"
        assert result.registry_status.state == "ACTIVE"
        assert result.dnssec_state == DNSSECState.UNKNOWN
        # DNSid1 retains the record-signing evidence: the ek JWKS and the TLS
        # certificate presented by the ek endpoint fetch.
        assert result.record_signing_jwks is not None
        assert result.record_signing_jwks.key_by_id("k1") is not None
        assert result.record_signing_tls_cert is not None

    @pytest.mark.parametrize("version", ["DNSid1"])
    def test_verify_domain_submitted_spec_profiles_use_alphabetical_canonicalization(
        self, version, ec_pair, ec_provider
    ):
        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(
            private, pub_jwk, target, v=version, bare_sg=(version == "DNSid1")
        )

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )

        # DNSid1 requires binding-level log checks (doc 01 step 5); the stub
        # satisfies them so this test stays about canonicalization.
        mgr = _build_verifier(
            ec_provider, dns_resolver=dns_resolver, log_registry=_stub_log_registry()
        )

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            result = mgr.verify_domain(target)

        assert result.domain == target
        assert result.record.v == version
        assert result.record.canonical().split(";")[-1] == f"v={version}"
        assert result.signing_key.kid == "k1"



    def test_record_signing_tls_cert_is_ek_cert_and_bounds_expiry(self, ec_pair, ec_provider):
        """The retained record-signing certificate is the ek endpoint's cert
        (not the ku one), and expiry() is bounded by it when it is the
        earliest validity bound."""
        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        ek_jwks = JWKS(keys=[pub_jwk])
        _, ku_jwk = make_ec_p256_pair("ku-distinct")
        ku_jwks = JWKS(keys=[ku_jwk])

        # Distinct certs per endpoint: the ek cert expires well before both
        # the ku cert and the DNS TTL bound (verified_at + 300s).
        ek_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(seconds=60),
            san_dns_names=["example.com"],
        )
        ku_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )
        ku_uri = f"https://{target}/.well-known/jwks.json"

        def routed_fetch(uri, allowed_host, transport=None, **kwargs):
            return (ku_jwks, ku_cert) if uri == ku_uri else (ek_jwks, ek_cert)

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch("dnsid.manager._fetch_jwks", side_effect=routed_fetch),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            result = mgr.verify_domain(target)

        # The ek endpoint's certificate is retained — not the ku one.
        assert result.record_signing_tls_cert is not None
        assert result.record_signing_tls_cert.not_after == ek_cert.not_after
        assert result.tls_cert.not_after == ku_cert.not_after
        # It is the earliest validity bound, so expiry() returns it.
        assert result.expiry() == ek_cert.not_after

    def test_dnsid1_rejects_detached_jws_sg(self, ec_pair, ec_provider):
        """DNSid1 sg is bare base64url only; a detached-JWS sg must be rejected."""
        private, pub_jwk = ec_pair
        target = "service.example.com"
        gi = "example.com"
        record = DnsIdTxtRecord(
            v="DNSid1",
            gi=gi,
            ek=f"https://{gi}/.well-known/jwks.json",
            ku=f"https://{target}/.well-known/jwks.json",
            lr="microledger:abc123",
            su=f"https://{target}/status",
            identity_fqdn=target,
        )
        record.sg = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0..AAAA"
        txt_raw = record.serialize()

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert "bare" in str(exc_info.value)

    def test_dnsid1_rejects_alg_prefixed_sg(self, ec_pair, ec_provider):
        """DNSid1 sg is bare base64url only; the alg-prefixed form must be rejected."""
        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target, bare_sg=False)

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert "bare" in str(exc_info.value)

    def test_dnsid1_rejects_ek_key_without_alg(self, ec_pair, ec_provider):
        """The single current ek JWK must declare alg for DNSid1."""
        from dnsid._crypto import ec_public_jwk_dict, jwk_from_dict

        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        raw_no_alg = ec_public_jwk_dict(private, "k1", "ES256")
        raw_no_alg.pop("alg", None)
        ek_key_no_alg = jwk_from_dict(raw_no_alg)
        assert not ek_key_no_alg.alg

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[ek_key_no_alg])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "alg" in str(exc_info.value)

    def test_dnsid1_rejects_ku_key_without_alg(self, ec_pair, ec_provider):
        """The current ku operational JWK must declare alg for DNSid1 too."""
        from dnsid._crypto import ec_public_jwk_dict, jwk_from_dict

        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        # ek serves the (alg-declaring) record-signing key that signed sg;
        # ku serves a distinct operational key with no alg member.
        ku_private, _ = make_ec_p256_pair("ku-1")
        raw_no_alg = ec_public_jwk_dict(ku_private, "ku-1", "ES256")
        raw_no_alg.pop("alg", None)
        ku_key_no_alg = jwk_from_dict(raw_no_alg)
        assert not ku_key_no_alg.alg

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        ek_jwks = JWKS(keys=[pub_jwk])
        ku_jwks = JWKS(keys=[ku_key_no_alg])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_routed_jwks_fetch(ek_jwks, ku_jwks, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "operational key must declare alg" in str(exc_info.value)

    def test_dnssec_failed_raises(self, ec_pair, ec_provider):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [_make_txt_record(txt_raw)],
            }
        )
        dns_resolver.fetch_txt = lambda name: ([_make_txt_record(txt_raw)], DNSSECState.FAILED)

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with pytest.raises(VerificationError) as exc_info:
            mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.DNSSEC_FAILED

    def test_default_resolver_is_usable_in_auto_mode(self, ec_provider):
        with (
            patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s),
            patch(
                "dnsid._default_resolver.DefaultDNSResolver.fetch_txt",
                return_value=([], DNSSECState.UNKNOWN),
            ) as fetch_txt,
        ):
            manager = IdentityManager(
                _make_config(),
                ec_provider,
                deps=IdentityManagerDependencies(log_registry=_stub_log_registry()),
            )
            with pytest.raises(VerificationError) as exc_info:
                manager.verify_domain("service.example.com")
        fetch_txt.assert_called_once_with("_dnsid.service.example.com")
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    @pytest.mark.parametrize(
        ("mode", "state", "allowed"),
        [
            (DNSSECMode.AUTO, DNSSECState.VALID, True),
            (DNSSECMode.AUTO, DNSSECState.UNSIGNED, True),
            (DNSSECMode.AUTO, DNSSECState.UNKNOWN, True),
            (DNSSECMode.AUTO, DNSSECState.FAILED, False),
            (DNSSECMode.VALIDATED, DNSSECState.VALID, True),
            (DNSSECMode.VALIDATED, DNSSECState.UNSIGNED, True),
            (DNSSECMode.VALIDATED, DNSSECState.UNKNOWN, False),
            (DNSSECMode.VALIDATED, DNSSECState.FAILED, False),
            (DNSSECMode.REQUIRED, DNSSECState.VALID, True),
            (DNSSECMode.REQUIRED, DNSSECState.UNSIGNED, False),
            (DNSSECMode.REQUIRED, DNSSECState.UNKNOWN, False),
            (DNSSECMode.REQUIRED, DNSSECState.FAILED, False),
        ],
    )
    def test_dnssec_policy_matrix(self, ec_provider, mode, state, allowed):
        resolver = MockDNSResolver()
        resolver.fetch_txt = lambda name: ([], state)
        manager = _build_verifier(
            ec_provider,
            config=_make_config(dnssec_mode=mode),
            dns_resolver=resolver,
        )

        with pytest.raises(VerificationError) as exc_info:
            manager.verify_domain("service.example.com")

        expected = VerificationCode.RECORD_INVALID if allowed else VerificationCode.DNSSEC_FAILED
        assert exc_info.value.code == expected

    def test_invalid_dnssec_mode_fails_at_construction(self, ec_provider):
        resolver = MockDNSResolver()
        resolver.fetch_txt = MagicMock(return_value=([], DNSSECState.UNKNOWN))

        with pytest.raises(ArgumentError, match="invalid DNSSEC mode"):
            _build_verifier(
                ec_provider,
                config=_make_config(dnssec_mode="disabled"),
                dns_resolver=resolver,
            )

        resolver.fetch_txt.assert_not_called()

    def test_multiple_txt_records_raises(self, ec_pair, ec_provider):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [_make_txt_record(txt_raw), _make_txt_record(txt_raw)],
            }
        )

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with pytest.raises(VerificationError) as exc_info:
            mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_no_txt_records_raises(self, ec_provider):
        target = "service.example.com"
        mgr = _build_verifier(ec_provider)

        with pytest.raises(VerificationError) as exc_info:
            mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_wrong_signature_raises(self, ec_pair, ec_provider):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        other_private, _ = make_ec_p256_pair("k2")
        txt_raw = _make_signed_txt_record(other_private, pub_jwk, target)

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [_make_txt_record(txt_raw)],
            }
        )

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        ek_jwks = JWKS(keys=[pub_jwk])
        _, ku_jwk = make_ec_p256_pair("ku-only")
        ku_jwks = JWKS(keys=[ku_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_routed_jwks_fetch(ek_jwks, ku_jwks, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID

    def test_sg_verified_against_ek_not_ku(self, ec_provider):
        """draft-01: sg MUST verify against the ek key, never the ku key.

        ek and ku carry different key material; sg is signed by the ek key, so
        verification succeeds only because the ek JWKS is used.
        """
        target = "service.example.com"
        ek_private, ek_jwk = make_ec_p256_pair("ek-key")
        _, ku_jwk = make_ec_p256_pair("ku-key")  # unrelated operational key

        txt_raw = _make_signed_txt_record(ek_private, ek_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        ku_jwks = JWKS(keys=[ku_jwk])
        ek_jwks = JWKS(keys=[ek_jwk])

        ku_uri = f"https://{target}/.well-known/jwks.json"
        ek_uri = "https://example.com/.well-known/jwks.json"
        seen_pins: dict[str, str] = {}
        fetch_order: list[str] = []

        def fake_fetch_jwks(uri, allowed_host, transport=None, **kwargs):
            # Route by URI (robust); record the pin each fetch was anchored to.
            seen_pins[uri] = allowed_host
            fetch_order.append(uri)
            return (ku_jwks, tls_cert) if uri == ku_uri else (ek_jwks, tls_cert)

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch("dnsid.manager._fetch_jwks", side_effect=fake_fetch_jwks),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            result = mgr.verify_domain(target)

        assert result.signing_key.kid == "ek-key"
        assert fetch_order == [ek_uri, ku_uri]
        # The operational (ku) key set is what callers/profiles see.
        assert result.jwks.key_by_id("ku-key") is not None
        # ku is pinned to the agent host; ek is pinned to the gi domain (not the
        # raw ek URI host — here they coincide, but the pin is gi-derived).
        assert seen_pins[ku_uri] == target
        assert seen_pins[ek_uri] == "example.com"

    def test_sg_signed_by_ku_key_rejected(self, ec_provider):
        """A record signed by the ku key (not ek) must fail — ku MUST NOT verify sg."""
        target = "service.example.com"
        _, ek_jwk = make_ec_p256_pair("ek-key")
        ku_private, ku_jwk = make_ec_p256_pair("ku-key")

        # sg signed by the ku key, which must NOT be accepted for sg.
        txt_raw = _make_signed_txt_record(ku_private, ku_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        ku_jwks = JWKS(keys=[ku_jwk])
        ek_jwks = JWKS(keys=[ek_jwk])

        ku_uri = f"https://{target}/.well-known/jwks.json"
        fetched: list[str] = []

        def fake_fetch_jwks(uri, allowed_host, transport=None, **kwargs):
            fetched.append(uri)
            return (ku_jwks, tls_cert) if uri == ku_uri else (ek_jwks, tls_cert)

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch("dnsid.manager._fetch_jwks", side_effect=fake_fetch_jwks),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert ku_uri not in fetched

    def test_ek_with_multiple_signing_keys_rejected(self, ec_provider):
        """draft-01: ek MUST publish exactly one current record-signing key.

        A multi-key ek JWKS is ambiguous about the accountable-entity key, so
        verification is rejected even though the sg is a valid signature.
        """
        target = "service.example.com"
        ek_private, ek_jwk = make_ec_p256_pair("ek-key")
        _, ek_extra_jwk = make_ec_p256_pair("ek-key-2")  # second usable signing key
        _, ku_jwk = make_ec_p256_pair("ku-key")

        txt_raw = _make_signed_txt_record(ek_private, ek_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        ku_jwks = JWKS(keys=[ku_jwk])
        ek_jwks = JWKS(keys=[ek_jwk, ek_extra_jwk])

        ku_uri = f"https://{target}/.well-known/jwks.json"

        def fake_fetch_jwks(uri, allowed_host, transport=None, **kwargs):
            return (ku_jwks, tls_cert) if uri == ku_uri else (ek_jwks, tls_cert)

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch("dnsid.manager._fetch_jwks", side_effect=fake_fetch_jwks),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_ek_and_ku_same_key_material_rejected(self, ec_provider):
        """The two-key model collapses if ek and ku serve identical key material.

        Both endpoints return the same JWK; the RFC 7638 thumbprint match must be
        rejected so ek and ku remain distinct keys.
        """
        target = "service.example.com"
        shared_private, shared_jwk = make_ec_p256_pair("shared-key")

        txt_raw = _make_signed_txt_record(shared_private, shared_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        shared_jwks = JWKS(keys=[shared_jwk])

        def fake_fetch_jwks(uri, allowed_host, transport=None, **kwargs):
            return (shared_jwks, tls_cert)

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch("dnsid.manager._fetch_jwks", side_effect=fake_fetch_jwks),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "thumbprint collision" in str(exc_info.value)

    def test_ek_ku_pairwise_thumbprint_collision_non_signing_key(self, ec_provider):
        """Full pairwise check: a non-signing key in ek that also appears in ku
        must still trigger rejection (RFC 7638 thumbprint collision)."""
        target = "service.example.com"
        ek_private, ek_jwk = make_ec_p256_pair("ek-signing")
        _, shared_jwk = make_ec_p256_pair("shared-non-signing")
        shared_jwk.use = "enc"

        txt_raw = _make_signed_txt_record(ek_private, ek_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        # ek set has the signing key + a second key
        ek_jwks = JWKS(keys=[ek_jwk, shared_jwk])
        # ku set contains that second key (collision)
        _, ku_only = make_ec_p256_pair("ku-unique")
        ku_jwks = JWKS(keys=[ku_only, shared_jwk])

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_routed_jwks_fetch(ek_jwks, ku_jwks, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "thumbprint collision" in str(exc_info.value)

    def test_ek_ku_distinct_keys_accepted(self, ec_pair, ec_provider):
        """When ek and ku key sets have no thumbprint overlap, verification proceeds."""
        # This is implicitly covered by test_verify_domain_success, but we
        # make the pairwise distinctness explicit here.
        target = "service.example.com"
        ek_private, ek_jwk = ec_pair

        txt_raw = _make_signed_txt_record(ek_private, ek_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        ek_jwks = JWKS(keys=[ek_jwk])
        _, ku_jwk = make_ec_p256_pair("ku-distinct")
        ku_jwks = JWKS(keys=[ku_jwk])

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_routed_jwks_fetch(ek_jwks, ku_jwks, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            result = mgr.verify_domain(target)
        assert result is not None

    def test_status_not_active_raises(self, ec_pair, ec_provider):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [_make_txt_record(txt_raw)],
            }
        )
        revoked_status = AgentStatus(
            state="REVOKED",
            last_transition_at=_now(),
            revocation_reason="keyCompromise",
        )
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )

        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=revoked_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.STATUS_NOT_ACTIVE

    def test_malformed_status_is_non_transient_record_invalid_on_live_paths(
        self, ec_pair, ec_provider
    ):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)
        dns_resolver = MockDNSResolver(
            {f"_dnsid.{target}": [_make_txt_record(txt_raw)]}
        )
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        malformed = AgentStatus(  # type: ignore[arg-type]
            state={"malformed": True}, last_transition_at=_now()
        )
        active = AgentStatus(state="ACTIVE", last_transition_at=_now())
        cfg = _make_config(status_check_interval=datetime.timedelta(minutes=5))
        mgr = _build_verifier(ec_provider, config=cfg, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch(
                "dnsid.manager._fetch_strict_json_status", return_value=malformed
            ) as fetch_status,
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as uncached_error:
                mgr.verify_domain(target)

            fetch_status.return_value = active
            mgr.verify_domain(target)
            cached = mgr._cache.get(target)
            assert cached is not None
            cached.last_status_check_at = _now() - datetime.timedelta(hours=1)
            mgr._cache.put(target, cached)

            fetch_status.return_value = malformed
            with pytest.raises(VerificationError) as refresh_error:
                mgr.verify_domain(target)

        for error in (uncached_error.value, refresh_error.value):
            assert error.code == VerificationCode.RECORD_INVALID
            assert error.transient is False
            assert isinstance(error.__cause__, ValidationError)

    def test_status_transport_failure_raises_status_unavailable(self, ec_pair, ec_provider):
        """A transport-level status fetch failure is transient StatusUnavailable."""
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        transport_failure = VerificationError(
            VerificationCode.DNS_RESOLUTION,
            "connect timeout",
            transient=True,
        )
        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", side_effect=transport_failure),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.STATUS_UNAVAILABLE
        assert exc_info.value.transient is True

    def test_status_non_transient_failure_keeps_original_code(self, ec_pair, ec_provider):
        """Non-transient status failures (e.g. disallowed redirect) are not remapped."""
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        policy_failure = VerificationError(
            VerificationCode.TLS_ERROR,
            "redirect to non-HTTPS URL",
            transient=False,
        )
        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", side_effect=policy_failure),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.TLS_ERROR
        assert exc_info.value.transient is False

    def test_status_refresh_transport_failure_raises_status_unavailable(self, ec_pair, ec_provider):
        """The cache-hit status-only refresh path uses the same taxonomy."""
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        cfg = _make_config(status_check_interval=datetime.timedelta(minutes=5))
        mgr = _build_verifier(ec_provider, config=cfg, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            first = mgr.verify_domain(target)
        assert first.registry_status.state == "ACTIVE"

        # Force the cached entry stale so the next call re-fetches status only.
        cached = mgr._cache.get(target)
        cached.last_status_check_at = _now() - datetime.timedelta(hours=1)
        mgr._cache.put(target, cached)

        transport_failure = VerificationError(
            VerificationCode.DNS_RESOLUTION,
            "connect timeout",
            transient=True,
        )
        with patch("dnsid.manager._fetch_strict_json_status", side_effect=transport_failure):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.STATUS_UNAVAILABLE
        assert exc_info.value.transient is True

    def test_injected_fetcher_network_error_maps_to_status_unavailable(self, ec_pair, ec_provider):
        """An injected HTTPSFetcher raising DNS_RESOLUTION without the
        transient flag still surfaces as transient StatusUnavailable — the
        remap keys on the code, not only on a flag the fetcher may omit."""
        from dnsid.interfaces import HTTPSFetcher

        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        _, ku_jwk = make_ec_p256_pair("ku-only")
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        ku_uri = f"https://{target}/.well-known/jwks.json"

        class FlaglessFetcher(HTTPSFetcher):
            def fetch_strict_json(self, url, allowed_host=None, domain_boundary=False):
                if url == ku_uri:
                    return {"keys": [ku_jwk._raw]}, tls_cert
                if url.endswith("/status"):
                    # Network failure raised WITHOUT transient=True.
                    raise VerificationError(VerificationCode.DNS_RESOLUTION, "connect timeout")
                return {"keys": [pub_jwk._raw]}, tls_cert  # ek endpoint

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        cfg = _make_config()
        with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
            mgr = IdentityManager(
                cfg,
                ec_provider,
                deps=IdentityManagerDependencies(
                    dns_resolver=dns_resolver,
                    https_fetcher=FlaglessFetcher(),
                    log_registry=_stub_log_registry(),
                ),
            )

        with patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)
        assert exc_info.value.code == VerificationCode.STATUS_UNAVAILABLE
        assert exc_info.value.transient is True

    def test_logchk_flag_does_not_trigger_log_checks_in_verify(self, ec_pair, ec_provider):
        """Operation-level logchk is caller policy: verify_domain records the
        flag but performs no automatic verify_non_revocation."""
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target, fl="logchk")

        calls: list[tuple[str, datetime.datetime]] = []
        evidence = LoggedStateEvidence(
            log_reference="microledger:abc123",
            logged_state="ACTIVE",
            history_start="microledger:first",
            history_end="microledger:last",
            complete_through=10,
            completeness_mode="test",
            checkpoint=b"checkpoint",
            freshness_time=_now(),
        )

        class _RecordingStub(_StubLogBinding):
            def verify_non_revocation(self, domain, at):
                calls.append((domain, at))
                return evidence

        registry = LogRegistry()
        registry.register("microledger", _RecordingStub)

        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver, log_registry=registry)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            result = mgr.verify_domain(target)

        assert calls == [], "verify_domain must not run operation-level log checks"
        assert result.requires_log_check()

        at = _now()
        assert mgr.verify_log_evidence(result, at) is evidence
        assert calls == [(target, at)]

    def test_cache_hit_skips_reverification(self, ec_pair, ec_provider):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [_make_txt_record(txt_raw)],
            }
        )

        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )

        cfg = _make_config(status_check_interval=datetime.timedelta(minutes=5))
        mgr = _build_verifier(ec_provider, config=cfg, dns_resolver=dns_resolver)

        fetch_count = [0]

        def counting_fetch_status(su, **_):
            fetch_count[0] += 1
            return active_status

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", side_effect=counting_fetch_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            mgr.verify_domain(target)
            mgr.verify_domain(target)  # should be a cache hit

        assert fetch_count[0] == 1

    def test_mtls_is_enforced_on_initial_verification_and_cache_hits(
        self, ec_pair, ec_provider
    ):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target, fl="mtls")
        dns_resolver = MockDNSResolver(
            {f"_dnsid.{target}": [_make_txt_record(txt_raw)]}
        )
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        endpoint_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )
        peer_cert = TLSCertificate(san_dns_names=[target])
        cfg = _make_config(status_check_interval=datetime.timedelta(minutes=5))
        mgr = _build_verifier(ec_provider, config=cfg, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(JWKS(keys=[pub_jwk]), target, endpoint_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            first = mgr.verify_domain(target, peer_cert=peer_cert)
            assert mgr.verify_domain(target, peer_cert=peer_cert) is first

            with pytest.raises(VerificationError) as missing:
                mgr.verify_domain(target)
            assert missing.value.code == VerificationCode.TLS_ERROR

            with pytest.raises(VerificationError) as mismatch:
                mgr.verify_domain(
                    target,
                    peer_cert=TLSCertificate(san_dns_names=["other.example.com"]),
                )
            assert mismatch.value.code == VerificationCode.TLS_ERROR
            assert mismatch.value.__cause__ is not None

    def test_evict_domain_clears_cache(self, ec_pair, ec_provider):
        target = "service.example.com"
        private, pub_jwk = ec_pair
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [_make_txt_record(txt_raw)],
            }
        )
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        jwks_obj = JWKS(keys=[pub_jwk])
        tls_cert = TLSCertificate(
            not_after=_now() + datetime.timedelta(days=365),
            san_dns_names=[target],
        )

        cfg = _make_config(status_check_interval=datetime.timedelta(minutes=5))
        mgr = _build_verifier(ec_provider, config=cfg, dns_resolver=dns_resolver)

        fetch_count = [0]

        def counting_fetch(su, **_):
            fetch_count[0] += 1
            return active_status

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(jwks_obj, target, tls_cert),
            ),
            patch("dnsid.manager._fetch_strict_json_status", side_effect=counting_fetch),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            mgr.verify_domain(target)
            mgr.evict_domain(target)
            mgr.verify_domain(target)

        assert fetch_count[0] == 2

    def test_logchk_not_rerun_on_status_refresh(self, ec_pair, ec_provider):
        """logchk checks must NOT run during a status-only cache refresh.

        Per the design spec, the status-only cache-hit path re-fetches only the su
        endpoint.  logchk verification runs only during
        full verification (cache miss or expired entry), not on every status refresh.
        """
        from dnsid.enums import DNSSECState as DS

        target = "service.example.com"
        _, pub_jwk = ec_pair
        now = _now()

        record = DnsIdTxtRecord(
            v="DNSid1",
            gi="example.com",
            ek="https://example.com/.well-known/jwks.json",
            ku=f"https://{target}/.well-known/jwks.json",
            lr="microledger:abc",
            su=f"https://{target}/status",
            sg="sig",
            fl="logchk",
            identity_fqdn=target,
        )
        mock_log_reader = MagicMock()

        cached = VerifiedDomain(
            domain=target,
            record=record,
            jwks=JWKS(keys=[pub_jwk]),
            signing_key=pub_jwk,
            tls_cert=TLSCertificate(
                not_after=now + datetime.timedelta(days=365),
                san_dns_names=[target],
            ),
            registry_status=AgentStatus(state="ACTIVE", last_transition_at=now),
            verified_at=now,
            dns_ttl=300,
            key_bound_at=datetime.datetime.min.replace(tzinfo=datetime.UTC),
            last_status_check_at=now - datetime.timedelta(hours=1),
            dnssec_state=DS.UNKNOWN,
            log_reader=mock_log_reader,
        )

        cfg = _make_config(status_check_interval=datetime.timedelta(minutes=5))
        mgr = _build_verifier(ec_provider, config=cfg)

        mgr._cache.put(target, cached)

        active_status = AgentStatus(state="ACTIVE", last_transition_at=now)
        with patch("dnsid.manager._fetch_strict_json_status", return_value=active_status):
            result = mgr.verify_domain(target)

        # Log checks must NOT run on a status-only refresh.
        mock_log_reader.verify_non_revocation.assert_not_called()
        assert result.registry_status.state == "ACTIVE"



class TestEkPinningHost:
    """Unit tests for the ek TLS-pin derivation (anchored to gi, not raw ek)."""

    def test_pin_derived_from_gi_domain(self):
        from dnsid.manager import _ek_pinning_host

        assert (
            _ek_pinning_host("example.com", "https://example.com/.well-known/jwks.json")
            == "example.com"
        )

    def test_pin_allows_ek_subdomain_of_gi(self):
        from dnsid.manager import _ek_pinning_host

        assert _ek_pinning_host(
            "example.com", "https://keys.example.com/jwks.json"
        ) == "example.com"

    def test_pin_rejects_ek_host_outside_gi(self):
        from dnsid.manager import _ek_pinning_host

        with pytest.raises(VerificationError) as exc_info:
            _ek_pinning_host("example.com", "https://attacker.com/jwks.json")
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_non_domain_gi_rejected(self):
        # DNSid1 gi must be a lowercase ASCII DNS domain; there is no
        # fall-back pinning for non-domain governance identifiers.
        from dnsid.manager import _ek_pinning_host

        with pytest.raises(VerificationError) as exc_info:
            _ek_pinning_host("algorand:ADDR123", "https://keys.example/jwks.json")
        assert exc_info.value.code == VerificationCode.RECORD_INVALID


class TestUnknownCertificateExpiry:
    def test_verify_domain_accepts_evidence_without_a_peer_certificate(self, ec_pair, ec_provider):
        """A transport that cannot expose the peer certificate (custom httpx
        transports, ASGI/WSGI adapters) yields ``TLSCertificate()``.  Its
        sentinel ``not_after`` means "unknown", not "already expired" — the
        same reading ``VerifiedDomain.expires_at`` gives it."""
        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        dns_resolver.fetch_txt = lambda name: ([_make_txt_record(txt_raw)], DNSSECState.UNKNOWN)
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(JWKS(keys=[pub_jwk]), target, TLSCertificate()),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            result = mgr.verify_domain(target)

        assert result.domain == target
        assert result.tls_cert == TLSCertificate()

    def test_expired_peer_certificate_is_still_rejected(self, ec_pair, ec_provider):
        private, pub_jwk = ec_pair
        target = "service.example.com"
        txt_raw = _make_signed_txt_record(private, pub_jwk, target)
        dns_resolver = MockDNSResolver({f"_dnsid.{target}": [_make_txt_record(txt_raw)]})
        dns_resolver.fetch_txt = lambda name: ([_make_txt_record(txt_raw)], DNSSECState.UNKNOWN)
        active_status = AgentStatus(state="ACTIVE", last_transition_at=_now())
        expired = TLSCertificate(
            not_after=_now() - datetime.timedelta(seconds=1), san_dns_names=[target]
        )
        mgr = _build_verifier(ec_provider, dns_resolver=dns_resolver)

        with (
            patch(
                "dnsid.manager._fetch_jwks",
                side_effect=_split_jwks_fetch(JWKS(keys=[pub_jwk]), target, expired),
            ),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
            pytest.raises(VerificationError) as excinfo,
        ):
            mgr.verify_domain(target)

        assert excinfo.value.code == VerificationCode.TLS_ERROR
