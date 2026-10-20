"""Regression checks for configured signer and account bindings."""

import copy
import importlib
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
import pytest

from dnsid import (
    JWKS,
    DnsIdTxtRecord,
    IdentityManager,
    IdentityManagerDependencies,
    KeySource,
    LoadedConfig,
    LocalKeyProvider,
    LogTrust,
    RegistryClient,
    construct_identity_manager,
)
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, ValidationError, VerificationError
from tests._config import make_config
from tests.test_verification_coalescing import _manager_fixture

DOMAIN = "agent.example.com"
GI = "example.com"
LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"


@pytest.mark.parametrize("accept_counterparties", [True, False])
def test_configured_mtls_signer_validates_publication_without_a_peer(
    tmp_path, ec_pair, accept_counterparties
):
    fixture, resolver, _, domain, keys, status, active = _manager_fixture(ec_pair, mtls=True)
    record = DnsIdTxtRecord.parse(resolver.records[f"_dnsid.{domain}"].concatenate_strings())
    path = tmp_path / "key.json"
    provider = LocalKeyProvider.load(path, create_if_missing=True)
    loaded = LoadedConfig(
        dnsid=make_config(
            domain=domain,
            governance_id=record.gi,
            log_ref=record.lr,
            status_url=record.su,
            policy_flags="mtls",
            trusted_entities=None if accept_counterparties else [],
        ),
        key_source=KeySource(key_ref=str(path)),
    )

    def fetch_keys(uri, allowed_host, **kwargs):
        jwks, certificate = keys(uri, allowed_host, **kwargs)
        if uri == record.ku:
            jwks = JWKS([provider.signing_key()])
        return jwks, certificate

    with (
        fixture,
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
        pytest.warns(UserWarning),
        construct_identity_manager(
            loaded,
            deps=IdentityManagerDependencies(
                dns_resolver=resolver, log_registry=fixture._log_registry
            ),
        ) as manager,
    ):
        assert manager.key_provider.signing_key().kid == provider.signing_key().kid
        _, peer = fetch_keys(record.ku, domain)
        for verify in (manager.verify_domain, manager.refresh_domain):
            with pytest.raises(VerificationError) as error:
                verify(domain)
            assert error.value.code == VerificationCode.TLS_ERROR
            if accept_counterparties:
                assert verify(domain, peer_cert=peer).domain == domain
            else:
                with pytest.raises(VerificationError) as error:
                    verify(domain, peer_cert=peer)
                assert error.value.code == VerificationCode.COUNTERPARTY_NOT_ACCEPTED
        active.state = "REVOKED"
        active.revocation_reason = "keyCompromise"
        with pytest.raises(VerificationError) as error:
            manager._verify_publication_evidence(domain)
        assert error.value.code == VerificationCode.STATUS_NOT_ACTIVE


@pytest.mark.parametrize(
    "source",
    [
        KeySource(provider="google-kms", key_ref="version-1"),
        KeySource(provider="file", settings={"secret": "no"}),
    ],
)
def test_invalid_provider_fails_before_policy_or_discovery(monkeypatch, source):
    loaded = LoadedConfig(
        dnsid=make_config(
            domain=DOMAIN, governance_id=GI, log_ref=LR, status_url=f"https://{DOMAIN}/status"
        ),
        key_source=source,
        log_trust=LogTrust(policy_url="https://policy.example/policy"),
    )
    with (
        patch("dnsid.config_loading._log_registry_from_trust") as policy,
        patch.object(IdentityManager, "_verify_publication_evidence") as discovery,
        pytest.raises(ArgumentError),
    ):
        monkeypatch.setattr(importlib, "import_module", Mock(side_effect=ImportError))
        construct_identity_manager(loaded)
    policy.assert_not_called()
    discovery.assert_not_called()


@pytest.mark.parametrize("mismatch", ["kid", "alg", "key", "gi", "lr", None])
def test_configured_signer_matches_verified_publication(tmp_path, monkeypatch, mismatch):
    path = tmp_path / "key.json"
    provider = LocalKeyProvider.load(path, create_if_missing=True)
    published = copy.deepcopy(provider.signing_key())
    if mismatch == "key":
        published = LocalKeyProvider.generate().signing_key()
    elif mismatch in {"kid", "alg"}:
        setattr(published, mismatch, "changed")
    observed = SimpleNamespace(
        record=SimpleNamespace(
            gi="other.example" if mismatch == "gi" else GI,
            lr="other:log" if mismatch == "lr" else LR,
            v="dnsid-draft-01",
        ),
        jwks=SimpleNamespace(current_operational_signing_key=lambda _: published),
    )
    monkeypatch.setattr(
        IdentityManager, "_verify_publication_evidence", Mock(return_value=observed)
    )
    loaded = LoadedConfig(
        dnsid=make_config(
            domain=DOMAIN, governance_id=GI, log_ref=LR, status_url=f"https://{DOMAIN}/status"
        ),
        key_source=KeySource(key_ref=str(path)),
    )
    with patch.object(IdentityManager, "close", autospec=True) as close:
        with pytest.warns(UserWarning):
            if mismatch:
                with pytest.raises(ValidationError, match="publication"):
                    construct_identity_manager(loaded)
                close.assert_called_once()
            else:
                manager = construct_identity_manager(loaded)
                close.assert_not_called()
                manager.close()


def test_configured_entity_signer_must_match_publication(tmp_path, monkeypatch):
    import json

    from tests.test_local_key_provider_cli import _make_private_jwk

    path = tmp_path / "entity.jwk"
    path.write_text(json.dumps(_make_private_jwk()))
    loaded = LoadedConfig(
        dnsid=make_config(
            domain=DOMAIN, governance_id=GI, log_ref=LR, status_url=f"https://{DOMAIN}/status"
        ),
        key_source=KeySource(entity_key_path=str(path)),
    )
    observed = SimpleNamespace(
        record=SimpleNamespace(gi=GI, lr=LR),
        signing_key=LocalKeyProvider.generate().signing_key(),
    )
    monkeypatch.setattr(
        IdentityManager, "_verify_publication_evidence", Mock(return_value=observed)
    )
    with pytest.raises(ValidationError, match="signer"):
        construct_identity_manager(loaded, key_provider=LocalKeyProvider.generate())


@pytest.mark.parametrize(
    "change,ready",
    [
        ({}, True),
        ({"gi": None}, False),
        ({"ek": None}, False),
        ({"ek": {"status": "pending"}}, False),
        ({"gi": {"domain": GI, "state": "pending", "gate_authorized": True}}, False),
        ({"gi": {"domain": GI, "state": "verified", "gate_authorized": "true"}}, False),
    ],
)
def test_onboarding_readiness_preserves_pending(monkeypatch, change, ready):
    body = {
        "org_id": "org-1",
        "governance_domain": GI,
        "gi": {"domain": GI, "state": "verified", "gate_authorized": True},
        "ek": {"status": "verified"},
        "bindings_ready": True,
        **change,
    }
    with RegistryClient("https://registry.example", api_key="owner") as client:
        monkeypatch.setattr(
            client, "_http_request", lambda *a, **kw: httpx.Response(200, json=body)
        )
        result = client.get_organization_onboarding(expected_org_id="org-1", expected_gi=GI)
    assert result == {**body, "bindings_ready": ready}


@pytest.mark.parametrize(
    "change",
    [
        {"org_id": ""},
        {"org_id": "org-2"},
        {"governance_domain": "other.example"},
        {"governance_domain": "https://example.com"},
        {"governance_domain": 123},
        {"gi": {"domain": "other.example", "state": "verified", "gate_authorized": True}},
    ],
)
def test_onboarding_rejects_binding_mismatch(monkeypatch, change):
    body = {"org_id": "org-1", "governance_domain": GI, **change}
    with RegistryClient("https://registry.example", api_key="owner") as client:
        monkeypatch.setattr(
            client, "_http_request", lambda *a, **kw: httpx.Response(200, json=body)
        )
        with pytest.raises((ArgumentError, ValidationError)):
            client.get_organization_onboarding(expected_org_id="org-1", expected_gi=GI)
