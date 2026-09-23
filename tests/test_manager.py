"""Unit tests for IdentityManager.get_key_set, get_entity_key_set,
create_txt_record, and publish_to_registry."""

from __future__ import annotations

import datetime
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from dnsid import (
    JWK,
    JWKS,
    DnsidConfig,
    DNSSECMode,
    IdentityManager,
    IdentityManagerDependencies,
    VerificationConfig,
)
from dnsid.exceptions import ArgumentError, ValidationError
from dnsid.interfaces import DNSResolver, KeyProvider
from dnsid.models import (
    AgentRegistration,
    CanonicalRecordContentResponse,
    PublishedRecord,
    RegistryAgentStatus,
)
from dnsid.registry_client import RegistryClient
from tests._config import make_config

_LEGACY_PROFILE = "dnsid-draft-01-20260527"

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


def _make_jwk(kid: str, alg: str = "ES256") -> JWK:
    # x/y are fake but present so RFC 7638 thumbprints are computable and
    # differ per kid (create_txt_record enforces entity/agent distinctness).
    if alg == "EdDSA":
        kty, crv = "OKP", "Ed25519"
        raw = {"kty": kty, "crv": crv, "alg": alg, "kid": kid, "x": f"x-{kid}"}
    else:
        kty, crv = "EC", "P-256"
        raw = {"kty": kty, "crv": crv, "alg": alg, "kid": kid, "x": f"x-{kid}", "y": f"y-{kid}"}
    return JWK(kty=kty, alg=alg, kid=kid, _raw=raw)


class FakeKeyProvider(KeyProvider):
    """Minimal KeyProvider backed by a fixed dict of JWKs."""

    def __init__(self, keys: dict[str, JWK], active_kid: str) -> None:
        self._keys = keys
        self._active_kid = active_kid

    def signing_key(self) -> JWK:
        return self._keys[self._active_kid]

    def jwk(self, kid: str) -> JWK:
        return self._keys[kid]

    def list_key_ids(self) -> list[str]:
        # Active key first, then the rest.
        rest = [k for k in self._keys if k != self._active_kid]
        return [self._active_kid] + rest

    def sign(self, payload: bytes) -> bytes:
        return b"fake_sig_bytes"

    def generate_key(self) -> str:
        raise NotImplementedError

    def activate(self, kid: str) -> None:
        raise NotImplementedError

    def supersede(self, kid: str) -> None:
        raise NotImplementedError


def _make_config(**overrides) -> DnsidConfig:
    defaults = dict(
        domain="agent.example.com",
        governance_id="example.com",
        log_ref="microledger:abc123",
        status_url="https://agent.example.com/status",
        ek_url="https://example.com/.well-known/jwks.json",
        ku_url="https://agent.example.com/.well-known/jwks.json",
    )
    defaults.update(overrides)
    return make_config(**defaults)


# Patch targets: normalize_fqdn is imported into manager.py, so patch it there.
# _default_dns_resolver is also in manager.py and raises NotImplementedError;
# we pass a mock DNSResolver to the constructor so it is never called.
_PATCH_NORMALIZE = "dnsid.manager.normalize_fqdn"


def _default_entity_provider() -> FakeKeyProvider:
    return FakeKeyProvider({"ent1": _make_jwk("ent1", alg="EdDSA")}, active_kid="ent1")


def _build_manager(
    key_provider: KeyProvider,
    config: DnsidConfig | None = None,
    entity_key_provider: KeyProvider | None = None,
) -> IdentityManager:
    """Build an IdentityManager with normalize_fqdn stubbed to a pass-through."""
    cfg = config or _make_config()
    mock_resolver = MagicMock(spec=DNSResolver)
    with patch(_PATCH_NORMALIZE, side_effect=lambda s, **_: s):
        return IdentityManager(
            cfg,
            key_provider,
            deps=IdentityManagerDependencies(
                dns_resolver=mock_resolver,
                entity_key_provider=entity_key_provider,
            ),
        )


# ---------------------------------------------------------------------------
# get_key_set
# ---------------------------------------------------------------------------


class TestVerificationOnlyConstruction:
    def test_requires_neither_local_config_nor_keys(self):
        manager = IdentityManager.for_verification(
            IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver)),
            verification=VerificationConfig(
                dnssec_mode=DNSSECMode.REQUIRED,
                status_check_interval=datetime.timedelta(seconds=30),
            ),
        )

        assert manager.config.identity is None
        assert manager.local_domain == ""
        assert manager.config.verification.dnssec_mode is DNSSECMode.REQUIRED
        assert manager.config.verification.status_check_interval == datetime.timedelta(seconds=30)

    def test_verification_only_rejects_key_providers(self, ec_provider):
        deps = IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver))
        with pytest.raises(ArgumentError, match="verification-only"):
            IdentityManager(DnsidConfig(), ec_provider, deps)
        with pytest.raises(ArgumentError, match="verification-only"):
            IdentityManager(None, deps=replace(deps, entity_key_provider=ec_provider))

    def test_rejects_non_dnsid_config_root(self, ec_provider):
        with pytest.raises(ArgumentError, match="must be a DnsidConfig"):
            IdentityManager(_make_config().identity, ec_provider)

    def test_local_identity_requires_key_provider(self):
        with pytest.raises(ArgumentError, match="requires a key_provider"):
            IdentityManager(
                _make_config(),
                deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver)),
            )

    def test_no_config_is_verification_only(self):
        manager = IdentityManager(
            deps=IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver))
        )
        with pytest.raises(ArgumentError, match="verification-only"):
            manager.create_txt_record()

    def test_local_key_operation_fails_with_argument_error(self):
        manager = IdentityManager.for_verification(
            IdentityManagerDependencies(dns_resolver=MagicMock(spec=DNSResolver))
        )

        with pytest.raises(ArgumentError, match="verification-only"):
            manager.get_key_set()



class TestGetKeySet:
    def test_returns_jwks_type(self):
        provider = FakeKeyProvider({"k1": _make_jwk("k1")}, active_kid="k1")
        manager = _build_manager(provider)
        result = manager.get_key_set()
        assert isinstance(result, JWKS)

    def test_single_key(self):
        provider = FakeKeyProvider({"k1": _make_jwk("k1")}, active_kid="k1")
        manager = _build_manager(provider)
        result = manager.get_key_set()
        assert len(result.keys) == 1
        assert result.keys[0].kid == "k1"

    def test_only_current_key_exposed(self):
        """DNSid1 live ku endpoints expose exactly one current operational key;
        retained keys never appear."""
        keys = {"k1": _make_jwk("k1"), "k2": _make_jwk("k2"), "k3": _make_jwk("k3")}
        provider = FakeKeyProvider(keys, active_kid="k2")
        manager = _build_manager(provider)
        result = manager.get_key_set()
        assert [jwk.kid for jwk in result.keys] == ["k2"]

    def test_key_attributes_preserved(self):
        jwk = _make_jwk("k1", alg="EdDSA")
        jwk.use = "sig"
        provider = FakeKeyProvider({"k1": jwk}, active_kid="k1")
        manager = _build_manager(provider)
        result = manager.get_key_set()
        returned = result.keys[0]
        assert returned.kid == "k1"
        assert returned.alg == "EdDSA"
        assert returned.use == "sig"


# ---------------------------------------------------------------------------
# get_entity_key_set
# ---------------------------------------------------------------------------


class TestGetEntityKeySet:
    def test_single_current_entity_key(self):
        provider = FakeKeyProvider({"k1": _make_jwk("k1")}, active_kid="k1")
        manager = _build_manager(provider, entity_key_provider=_default_entity_provider())
        result = manager.get_entity_key_set()
        assert [jwk.kid for jwk in result.keys] == ["ent1"]

    def test_missing_entity_provider_raises(self):
        provider = FakeKeyProvider({"k1": _make_jwk("k1")}, active_kid="k1")
        manager = _build_manager(provider)
        with pytest.raises(ArgumentError, match="entity_key_provider"):
            manager.get_entity_key_set()


# ---------------------------------------------------------------------------
# create_txt_record — DNSid1 (default publish profile)
# ---------------------------------------------------------------------------


class TestCreateTxtRecordDnsid1:
    def _manager(self, config: DnsidConfig | None = None) -> IdentityManager:
        provider = FakeKeyProvider({"k1": _make_jwk("k1")}, active_kid="k1")
        return _build_manager(provider, config, entity_key_provider=_default_entity_provider())

    def test_returns_string(self):
        result = self._manager().create_txt_record()
        assert isinstance(result, str)

    def test_emits_exact_dnsid1_version(self):
        result = self._manager().create_txt_record()
        assert result.startswith("v=dnsid-draft-01;")

    def test_contains_required_tags(self):
        result = self._manager().create_txt_record()
        for tag in ("gi=", "ek=", "ku=", "lr=", "su=", "sg="):
            assert tag in result, f"missing tag {tag!r} in: {result}"

    def test_sg_is_bare_base64url(self):
        """DNSid1 sg is bare unpadded base64url — no alg prefix, no colon."""
        result = self._manager().create_txt_record()
        sg_value = next(
            part.split("=", 1)[1] for part in result.split(";") if part.startswith("sg=")
        )
        assert sg_value
        assert ":" not in sg_value
        assert "=" not in sg_value

    def test_signed_by_entity_key_not_agent_key(self):
        entity_provider = _default_entity_provider()
        entity_provider.sign = MagicMock(return_value=b"entity_sig")  # type: ignore[method-assign]
        agent_provider = FakeKeyProvider({"k1": _make_jwk("k1")}, active_kid="k1")
        agent_provider.sign = MagicMock(return_value=b"agent_sig")  # type: ignore[method-assign]
        manager = _build_manager(agent_provider, entity_key_provider=entity_provider)

        manager.create_txt_record()

        entity_provider.sign.assert_called_once()
        agent_provider.sign.assert_not_called()
        signed_payload: bytes = entity_provider.sign.call_args[0][0]
        assert isinstance(signed_payload, bytes)
        assert b"sg=" not in signed_payload

    def test_missing_entity_provider_raises(self):
        provider = FakeKeyProvider({"k1": _make_jwk("k1")}, active_kid="k1")
        manager = _build_manager(provider)
        with pytest.raises(ArgumentError, match="entity_key_provider"):
            manager.create_txt_record()

    def test_shared_entity_and_agent_key_raises(self):
        shared = _make_jwk("k1", alg="EdDSA")
        provider = FakeKeyProvider({"k1": shared}, active_kid="k1")
        entity = FakeKeyProvider({"k1": shared}, active_kid="k1")
        manager = _build_manager(provider, entity_key_provider=entity)
        with pytest.raises(ArgumentError, match="distinct"):
            manager.create_txt_record()

    def test_missing_ek_url_raises(self):
        cfg = _make_config(ek_url="")
        with pytest.raises(ArgumentError, match="ek_url and ku_url"):
            self._manager(cfg).create_txt_record()

    def test_missing_ku_url_raises(self):
        cfg = _make_config(ku_url="")
        with pytest.raises(ArgumentError, match="ek_url and ku_url"):
            self._manager(cfg).create_txt_record()

    def test_unsupported_publish_profile_raises(self):
        cfg = _make_config(publish_profile=_LEGACY_PROFILE)
        with pytest.raises(ArgumentError, match="unsupported DNSid publish profile"):
            self._manager(cfg).create_txt_record()

    def test_optional_tags_included_when_set(self):
        cfg = _make_config(
            policy_flags="mtls,logchk",
            max_key_age="30d",
            capabilities_url="https://agent.example.com/agents.md",
        )
        result = self._manager(cfg).create_txt_record()
        assert "fl=mtls,logchk" in result
        assert "ka=30d" in result
        assert "cu=https://agent.example.com/agents.md" in result

    def test_optional_tags_absent_when_not_set(self):
        result = self._manager().create_txt_record()
        for tag in ("fl=", "ka=", "cu="):
            assert tag not in result, f"unexpected tag {tag!r}"

    def test_is_parseable_round_trip(self):
        from dnsid import DnsIdTxtRecord

        result = self._manager().create_txt_record()
        parsed = DnsIdTxtRecord.parse(result)
        assert parsed.v == "dnsid-draft-01"
        assert parsed.gi == "example.com"
        assert parsed.lr == "microledger:abc123"


# ---------------------------------------------------------------------------
# publish_to_registry
# ---------------------------------------------------------------------------

_PUBLISHED_RECORD = PublishedRecord(
    domain="agent.example.com",
    owner_name="_dnsid.agent.example.com",
    txt_record="v=dnsid-draft-01;...",
    ttl=300,
    publication_status="ready_for_publication",
)

_BASE_CANONICAL = (
    "ek=https://example.com/.well-known/jwks.json;"
    "gi=example.com;"
    "ku=https://agent.example.com/.well-known/jwks.json;"
    "lr=microledger:abc123;"
    "su=https://agent.example.com/status;"
    "v=dnsid-draft-01"
)


def _make_registry(canonical: str, signing_kid: str = "ent1") -> RegistryClient:
    registry = MagicMock(spec=RegistryClient)
    registry.get_registration.return_value = AgentRegistration(
        domain="agent.example.com",
        publication_authority="client",
        registry_status="READY",
        registry_url="https://registry.example.com",
    )
    registry.canonical_record_content.return_value = CanonicalRecordContentResponse(
        canonical=canonical, signing_kid=signing_kid
    )
    registry.publish_signature.return_value = _PUBLISHED_RECORD
    return registry


class TestPublishToRegistry:
    def _manager(self, config: DnsidConfig | None = None) -> IdentityManager:
        provider = FakeKeyProvider({"k1": _make_jwk("k1", alg="EdDSA")}, active_kid="k1")
        return _build_manager(provider, config, entity_key_provider=_default_entity_provider())

    def test_happy_path_signs_with_entity_key_and_submits_bare_sig(self):
        manager = self._manager()
        registry = _make_registry(_BASE_CANONICAL)

        result = manager.publish_to_registry(registry)

        registry.canonical_record_content.assert_called_once_with("agent.example.com", "ent1")
        registry.publish_signature.assert_called_once()
        sig_arg = registry.publish_signature.call_args[0][1]
        assert ":" not in sig_arg, "DNSid1 signature must be bare base64url"
        assert result.domain == "agent.example.com"

    def test_registry_managed_authority_is_rejected_before_signing(self):
        manager = self._manager()
        registry = _make_registry(_BASE_CANONICAL)
        registry.get_registration.return_value.publication_authority = "registry"

        with pytest.raises(ValidationError, match="registry controls"):
            manager.publish_client_controlled_record(registry)

        registry.canonical_record_content.assert_not_called()
        registry.publish_signature.assert_not_called()

    def test_missing_entity_provider_raises(self):
        provider = FakeKeyProvider({"k1": _make_jwk("k1", alg="EdDSA")}, active_kid="k1")
        manager = _build_manager(provider)
        registry = _make_registry(_BASE_CANONICAL)
        with pytest.raises(ArgumentError, match="entity_key_provider"):
            manager.publish_to_registry(registry)
        registry.publish_signature.assert_not_called()

    def test_signing_kid_mismatch_raises(self):
        manager = self._manager()
        registry = _make_registry(_BASE_CANONICAL, signing_kid="other-key")

        with pytest.raises(ValidationError, match="signing kid"):
            manager.publish_to_registry(registry)

        registry.publish_signature.assert_not_called()

    def test_non_publishable_registry_profile_raises(self):
        manager = self._manager()
        registry = _make_registry(_BASE_CANONICAL.replace("dnsid-draft-01", "DNSid1"))

        with pytest.raises(ValidationError, match="unsupported DNSid publish profile"):
            manager.publish_to_registry(registry)

        registry.publish_signature.assert_not_called()

    def test_canonical_mismatch_raises(self):
        manager = self._manager()
        tampered = _BASE_CANONICAL.replace("/status", "/other-status")
        registry = _make_registry(tampered)

        with pytest.raises(ValidationError, match="does not match"):
            manager.publish_to_registry(registry)

        registry.publish_signature.assert_not_called()

    def test_exact_key_age_agreement_is_accepted(self):
        manager = self._manager(_make_config(max_key_age="90d"))
        canonical = _BASE_CANONICAL.replace(
            "gi=example.com;", "gi=example.com;ka=90d;"
        )
        registry = _make_registry(canonical)

        manager.publish_client_controlled_record(registry)

        registry.publish_signature.assert_called_once()

    def test_registry_key_age_is_rejected_when_local_value_is_unset(self):
        manager = self._manager()
        canonical = _BASE_CANONICAL.replace(
            "gi=example.com;", "gi=example.com;ka=90d;"
        )
        registry = _make_registry(canonical)

        with pytest.raises(ValidationError, match="does not match"):
            manager.publish_client_controlled_record(registry)

        assert manager.config.identity.max_key_age == ""
        registry.publish_signature.assert_not_called()

    def test_mismatched_key_ages_are_rejected(self):
        manager = self._manager(_make_config(max_key_age="30d"))
        canonical = _BASE_CANONICAL.replace(
            "gi=example.com;", "gi=example.com;ka=90d;"
        )
        registry = _make_registry(canonical)

        with pytest.raises(ValidationError, match="does not match"):
            manager.publish_client_controlled_record(registry)

        registry.publish_signature.assert_not_called()

    def test_cu_in_both_registry_and_local_passes(self):
        cfg = _make_config(capabilities_url="https://agent.example.com/.well-known/agent-card.json")
        manager = self._manager(cfg)
        canonical_with_cu = (
            "cu=https://agent.example.com/.well-known/agent-card.json;" + _BASE_CANONICAL
        )
        registry = _make_registry(canonical_with_cu)

        result = manager.publish_to_registry(registry)

        registry.publish_signature.assert_called_once()
        assert result.domain == "agent.example.com"

    def test_cu_in_local_but_not_registry_raises(self):
        cfg = _make_config(capabilities_url="https://agent.example.com/.well-known/agent-card.json")
        manager = self._manager(cfg)
        registry = _make_registry(_BASE_CANONICAL)  # no cu in registry canonical

        with pytest.raises(ValidationError, match="does not match"):
            manager.publish_to_registry(registry)

        registry.publish_signature.assert_not_called()

    def test_legacy_publish_profile_rejected(self):
        """The dated draft profile is no longer publishable (design:
        SupportedPublishProfiles = ["dnsid-draft-01"])."""
        cfg = _make_config(publish_profile=_LEGACY_PROFILE)
        # Rejected at construction, before any network work.
        with pytest.raises(ArgumentError, match="unsupported DNSid publish profile"):
            self._manager(cfg)


class TestAwaitRegistryManagedPublication:
    def _manager(self) -> IdentityManager:
        provider = FakeKeyProvider({"k1": _make_jwk("k1", alg="EdDSA")}, active_kid="k1")
        return _build_manager(provider)

    def test_rejects_client_controlled_registration(self):
        manager = self._manager()
        registry = MagicMock(spec=RegistryClient)
        registry.get_registration.return_value = AgentRegistration(
            domain="agent.example.com",
            publication_authority="client",
            registry_status="READY",
            registry_url="https://registry.example.com",
        )

        with pytest.raises(ValidationError, match="client controls"):
            manager.await_registry_managed_publication(registry)
        registry.wait_for_status.assert_not_called()

    def test_verifies_observed_dns_record_after_registry_completion(self):
        manager = self._manager()
        registry = MagicMock(spec=RegistryClient)
        registration = AgentRegistration(
            domain="agent.example.com",
            publication_authority="registry",
            registry_status="READY",
            registry_url="https://registry.example.com",
            dns_published=True,
            raw={"managed": "dnsid"},
        )
        registry.get_registration.return_value = registration
        registry.wait_for_status.return_value = RegistryAgentStatus(
            registry_status="READY",
            dns_published=True,
            protocol_status=None,
            ready_for_publication=False,
            published=True,
            failed=False,
            terminal=False,
        )
        verified = MagicMock()
        verified.domain = "agent.example.com"
        verified.record.v = "dnsid-draft-01"
        verified.record.serialize.return_value = "v=dnsid-draft-01;..."
        verified.dns_ttl = 300
        verified.registry_status = MagicMock()

        with (
            patch.object(manager, "_verify_publication_evidence", return_value=verified) as verify,
            patch.object(manager, "verify_domain") as public_verify,
        ):
            result = manager.await_registry_managed_publication(registry)

        # Protocol-only internal path; public verify_domain (with acceptance) is not used.
        verify.assert_called_once_with("agent.example.com")
        public_verify.assert_not_called()
        assert result.publication_status == "READY"
        assert result.protocol_status is verified.registry_status
