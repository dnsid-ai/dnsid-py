"""Server-compatible provider selection, account reads, and explicit rotation."""

import importlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from dnsid import (
    JWKS,
    KeySource,
    LoadedConfig,
    LocalKeyProvider,
    RegistryClient,
    TransportConfig,
    construct_identity_manager,
    load_file,
    verification_budget,
)
from dnsid.exceptions import (
    ArgumentError,
    ManagedKeyRotationActivationError,
    RegistryRequestError,
    ValidationError,
)
from tests._config import make_config
from tests.test_key_rotation import FakeRotationRegistry, RotationProvider, _hooks, _manager

_CONFIG = make_config(
    domain="agent.test",
    governance_id="example.test",
    log_ref="c2sp-tlog:testnet:https://log.test#instance",
    status_url="https://agent.test/status",
)


@pytest.mark.parametrize(
    "provider,module,remedy",
    [
        ("aws-kms", "boto3", "dnsid[aws]"),
        ("google-kms", "dnsid_google_kms", "dnsid-google-kms"),
        ("azure-key-vault", "dnsid_azure_key_vault", "dnsid-azure-key-vault"),
    ],
)
def test_only_selected_provider_loads_and_injection_wins(monkeypatch, provider, module, remedy):
    seen = []

    def unavailable(name):
        seen.append(name)
        raise ImportError()

    monkeypatch.setattr(importlib, "import_module", unavailable)
    loaded = LoadedConfig(dnsid=_CONFIG, key_source=KeySource(provider=provider, key_ref="stable"))
    with pytest.raises(ArgumentError) as error:
        construct_identity_manager(loaded)
    assert provider in str(error.value) and remedy in str(error.value)
    assert seen == [module]
    key = LocalKeyProvider.generate()
    manager = construct_identity_manager(loaded, key)
    assert manager.key_provider is key and seen == [module]
    manager.close()


def test_configured_factory_opens_existing_key_and_file_selection_warns(tmp_path, monkeypatch):
    key = LocalKeyProvider.generate()
    factory = SimpleNamespace(
        validate_config=Mock(), key_provider_from_config=Mock(return_value=key)
    )
    monkeypatch.setattr(importlib, "import_module", lambda name: factory)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "keySource": {
                    "provider": "google-kms",
                    "keyRef": "version-1",
                    "settings": {"project": "test"},
                },
            }
        )
    )
    loaded = load_file(path)
    loaded.dnsid = _CONFIG
    manager = construct_identity_manager(loaded)
    assert manager.key_provider is key
    factory.validate_config.assert_called()
    factory.key_provider_from_config.assert_called_once()
    manager.close()
    private = tmp_path / "key.json"
    LocalKeyProvider.load(private, create_if_missing=True)
    for provider in (None, "file"):
        loaded.key_source = KeySource(provider=provider, key_ref=str(private))
        with pytest.warns(UserWarning, match="unsuitable for production"):
            manager = construct_identity_manager(loaded)
        manager.close()


@pytest.mark.parametrize(
    "selection",
    [
        {"provider": 1},
        {"keyRef": []},
        {"settings": []},
        {"unknownSelector": {}},
        {"credential": "no"},
        {"settings": {}, "privateJwk": {}},
    ],
)
def test_groundwork_config_rejects_unknown_and_mistyped_fields(tmp_path, selection):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"keySource": selection}))
    with pytest.raises(ArgumentError):
        load_file(path)


@pytest.mark.parametrize(
    "selection",
    [
        KeySource(provider="other", key_ref="existing"),
        KeySource(provider="aws-kms", key_store_path="file", key_ref="existing"),
        KeySource(cli_directory="cli", key_ref="file"),
        KeySource(settings={"privateKey": "no"}),
    ],
)
def test_invalid_selection_never_opens_a_key(selection):
    with pytest.raises(ArgumentError):
        construct_identity_manager(LoadedConfig(dnsid=_CONFIG, key_source=selection))


def test_onboarding_auth_budget_and_error_categories(monkeypatch):
    client = RegistryClient(
        "https://registry.test",
        api_key="owner-token",
        transport_config=TransportConfig(private_address_hosts=frozenset({"registry.test"})),
    )
    body = {
        "org_id": "org-1",
        "governance_domain": "example.test",
        "gi": {"domain": "example.test", "state": "pending", "gate_authorized": False},
        "ek": {"status": "pending"},
    }
    calls = []

    def get(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return httpx.Response(200, json=body)

    monkeypatch.setattr(client, "_http_request", get)
    with verification_budget(1):
        assert client.get_organization_onboarding() == body
    assert calls[0][:2] == ("GET", "https://registry.test/api/v1/org/onboarding")
    assert calls[0][2]["headers"] == {"Authorization": "Bearer owner-token"}
    for status in (403, 503):
        monkeypatch.setattr(
            client,
            "_http_request",
            lambda *args, **kwargs: httpx.Response(
                status,
                json={"error": "UNAVAILABLE", "secret": "owner-token"},
            ),
        )
        with pytest.raises(RegistryRequestError) as error:
            client.get_organization_onboarding()
        assert error.value.status_code == status
        assert "owner-token" not in str(error.value)
    with pytest.raises(ArgumentError):
        RegistryClient("https://registry.test").get_organization_onboarding()


def test_cross_provider_rotation_and_restart_retire_local_signer(tmp_path):
    previous = LocalKeyProvider.load(tmp_path / "old.json", create_if_missing=True)
    target = RotationProvider()
    manager = _manager(target)
    manager._key_provider = previous
    registry = FakeRotationRegistry("pending")
    registry.previous_kid = previous.signing_key().kid
    hooks, persisted, pauses = _hooks()
    providers = dict(
        target_key_provider=target,
        previous_provider_reference="local-store",
        target_provider_reference="kms-store",
    )
    result = manager.rotate_operational_key(
        registry, idempotency_key="rotation", **hooks, **providers
    )
    assert result.previous_provider_reference == "local-store"
    assert previous.list_key_ids() and target.active_kid == "ku-1"
    with pytest.raises(ValidationError, match="references changed"):
        manager.resume_key_rotation(
            registry, result, **hooks, **(providers | {"target_provider_reference": "another"})
        )
    assert len(registry.submit_calls) == 1
    manager.close()
    restarted = _manager(target)
    restarted._key_provider = LocalKeyProvider.load(tmp_path / "old.json")
    registry.submit_state = "accepted"
    completed = restarted.resume_key_rotation(registry, persisted[-1], **hooks, **providers)
    assert completed.activated and restarted.key_provider is target
    assert not LocalKeyProvider.load(tmp_path / "old.json").list_key_ids()
    with pytest.raises(ArgumentError, match="no active"):
        previous = LocalKeyProvider.load(tmp_path / "old.json")
        previous.sign(b"blocked")
    assert registry.submit_calls[0] == registry.submit_calls[1]
    assert len(registry.prepare_calls) == 1 and pauses[-1] is False
    restarted.close()


def test_rotation_requires_verified_current_publication_before_activation():
    provider = RotationProvider()
    manager = _manager(provider)
    manager._verify_publication_evidence.return_value.jwks = JWKS([provider.signing_key()])
    hooks, saved, pauses = _hooks()
    registry = FakeRotationRegistry()
    with pytest.raises(ManagedKeyRotationActivationError) as error:
        manager.rotate_operational_key(registry, idempotency_key="rotation", **hooks)
    assert error.value.rotation.submission.accepted
    assert not error.value.rotation.activated
    assert provider.active_kid == "ku-1" and pauses[-1] is True
    manager._verify_publication_evidence.return_value.jwks = JWKS([provider.jwk("ku-2")])
    manager._verify_publication_evidence.return_value.record.ku = "https://agent.example.com/new-ku"
    result = manager.resume_key_rotation(registry, saved[-1], **hooks)
    assert result.activated and len(registry.submit_calls) == 1
    assert manager.config.identity.ku_url.endswith("/new-ku")
    manager.close()


@pytest.mark.parametrize(
    "algorithm,wire", [("EdDSA", "ED25519_SHA_512"), ("ES256", "ECDSA_SHA_256")]
)
def test_aws_factory_uses_stable_existing_reference_and_algorithm(monkeypatch, algorithm, wire):
    from dnsid.aws_kms_key_provider import AwsKmsKeyProvider

    key = LocalKeyProvider.generate(algorithm)
    module = SimpleNamespace(Session=Mock())
    module.Session.return_value.client.return_value = Mock()
    monkeypatch.setattr(importlib, "import_module", lambda name: module)
    open_key = Mock(return_value=key)
    monkeypatch.setattr(AwsKmsKeyProvider, "load", open_key)
    source = KeySource(
        provider="aws-kms",
        key_ref="arn:aws:kms:stable",
        settings={"region": "us-east-1", "algorithm": algorithm},
    )
    manager = construct_identity_manager(LoadedConfig(dnsid=_CONFIG, key_source=source))
    assert open_key.call_args.args[1].active_key_id == source.key_ref
    assert open_key.call_args.args[1].algorithm == wire
    assert manager.key_provider is key
    module.Session.return_value.client.assert_called_once_with("kms", region_name="us-east-1")
    manager.close()


def test_aws_active_retirement_requires_explicit_verified_rotation_permission():
    from dnsid.aws_kms_key_provider import AwsKmsConfig, AwsKmsKeyProvider
    from tests.test_aws_kms_key_provider import _make_facade_with_ed25519

    facade, kid = _make_facade_with_ed25519()
    provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(active_key_id=kid, algorithm="ED25519_SHA_512"))
    with pytest.raises(ArgumentError):
        provider.supersede(kid)
    provider.supersede(kid, allow_active=True)
    assert provider.list_key_ids() == []
    with pytest.raises(ArgumentError, match="no active"):
        provider.sign(b"blocked")


def test_registry_transport_is_validated_and_snapshotted():
    transport = TransportConfig(private_address_hosts=frozenset({"registry.test"}))
    client = RegistryClient("https://registry.test", transport_config=transport)
    transport.private_address_hosts = frozenset({"other.test"})
    assert client._transport_config.private_address_hosts == frozenset({"registry.test"})
    with pytest.raises(ArgumentError):
        RegistryClient(
            "https://registry.test", transport_config=TransportConfig(dns_server=42)
        )
