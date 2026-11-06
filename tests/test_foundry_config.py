"""Foundry is optional loader data, never core identity or acceptance policy."""

import json
from unittest.mock import Mock, patch

import pytest

from dnsid import (
    FoundryConfig,
    IdentityManagerDependencies,
    KeySource,
    LoadedConfig,
    LocalKeyProvider,
    LogTrust,
    RegistryConfig,
    TransportConfig,
    construct_identity_manager,
    load_environment,
    load_file,
    merge_loaded_config,
)
from dnsid.exceptions import ArgumentError
from dnsid.foundry import KeyMissing, create
from tests.test_foundry import DOMAIN, GI, ORG, FoundryServer


def test_foundry_file_fields_are_partial_and_merge_individually(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"foundry": {"organizationId": ORG, "governanceId": GI}}))
    loaded = load_file(path)
    assert loaded.foundry == FoundryConfig(ORG, GI)
    assert loaded.dnsid.identity is None
    merged = merge_loaded_config(
        loaded, LoadedConfig(foundry=FoundryConfig(governance_id="other.example"))
    )
    assert merged.foundry == FoundryConfig(ORG, "other.example")
    assert loaded.foundry == FoundryConfig(ORG, GI)
    assert merge_loaded_config(loaded, LoadedConfig()).foundry == loaded.foundry
    assert merge_loaded_config(LoadedConfig(), LoadedConfig()).foundry == FoundryConfig()


@pytest.mark.parametrize(
    "foundry",
    [
        {"unknown": "x"},
        {"organizationId": 1},
        {"governanceId": []},
        {"organization_id": ORG},
        None,
    ],
)
def test_unknown_and_mistyped_foundry_file_members_rejected(tmp_path, foundry):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"foundry": foundry}))
    with pytest.raises(ArgumentError):
        load_file(path)


def test_foundry_empty_source_values_absent_and_no_new_environment_names(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"foundry":{"organizationId":"  ","governanceId":""}}')
    assert load_file(path).foundry == FoundryConfig()
    assert (
        load_environment(
            {
                "DNSID_FOUNDRY_ORGANIZATION_ID": ORG,
                "DNSID_FOUNDRY_GOVERNANCE_ID": GI,
                "DNSID_GOVERNANCE_ID": GI,
            }
        ).foundry
        == FoundryConfig()
    )


def test_core_construction_ignores_foundry_expectations():
    manager = construct_identity_manager(LoadedConfig(foundry=FoundryConfig(ORG, GI)))
    assert manager.config.identity is None
    assert manager.config.verification.trusted_entities is None
    manager.close()


def test_deployment_file_plus_environment_plus_code_reaches_same_workflow(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "foundry": {"governanceId": GI},
                "registry": {"registryUrl": FoundryServer._base_url},
            }
        )
    )
    loaded = merge_loaded_config(
        load_file(path), load_environment({"DNSID_REGISTRY_URL": FoundryServer._base_url})
    )
    loaded = merge_loaded_config(loaded, LoadedConfig(foundry=FoundryConfig(organization_id=ORG)))
    key = LocalKeyProvider.generate()
    server = FoundryServer(key)
    deps = IdentityManagerDependencies(log_registry=server.logs)
    monkeypatch.setenv("DNSID_REGISTRY_URL", "https://wrong.example")
    from dnsid.foundry import FileFoundryStore

    with create(
        "from-file",
        config=loaded,
        api_key="explicit",
        key_provider=key,
        registry_client=server,
        deps=deps,
        store=FileFoundryStore(tmp_path / "state"),
    ) as identity:
        assert identity.domain == DOMAIN
    assert server.created[0][0].name == "from-file"


def test_one_argument_facade_loads_environment_and_separate_credential(tmp_path, monkeypatch):
    key = LocalKeyProvider.generate()
    server = FoundryServer(key)
    loaded = LoadedConfig(
        registry=RegistryConfig(server._base_url), log_trust=LogTrust(managed=True)
    )
    with (
        patch("dnsid.foundry._workflow.load_environment", return_value=loaded),
        patch(
            "dnsid.foundry._workflow._operational_key_provider",
            return_value=key,
        ),
        patch("dnsid.foundry._workflow.RegistryClient", return_value=server) as registry,
        patch(
            "dnsid.foundry._workflow._log_registry_from_trust",
            return_value=server.logs,
        ),
        patch("dnsid.foundry.store.Path.home", return_value=tmp_path),
    ):
        monkeypatch.setenv("DNSID_API_KEY", "  secret-from-environment  ")
        # The registry is facade-owned in this case.
        server.close = Mock()
        with create("one-call") as identity:
            assert identity.domain == DOMAIN
        registry.assert_called_once_with(
            server._base_url, api_key="secret-from-environment", transport_config=TransportConfig()
        )
    documents = list((tmp_path / ".dnsid/foundry").glob("*.json"))
    assert len(documents) == 1 and "secret-from-environment" not in documents[0].read_text()


def test_injected_dependencies_ignore_displaced_sources(tmp_path):
    key = LocalKeyProvider.generate()
    server = FoundryServer(key)
    loaded = LoadedConfig(
        key_source=KeySource(
            provider="unavailable-provider", settings={"ignored": "not-a-reference"}
        ),
        log_trust=LogTrust(managed=False),
    )
    from dnsid.foundry import FileFoundryStore

    store = FileFoundryStore(tmp_path / "state")
    with create(
        "injected",
        config=loaded,
        key_provider=key,
        registry_client=server,
        store=store,
        deps=IdentityManagerDependencies(log_registry=server.logs),
    ):
        pass
    with store.lock((server._base_url, ORG, "injected")):
        document = store.load((server._base_url, ORG, "injected"))
    assert document["keySource"]["provider"] == "injected"
    assert "ignored" not in json.dumps(document) and "logTrust" not in document


def test_no_provider_or_trust_never_uses_sandbox(tmp_path):
    server = FoundryServer(LocalKeyProvider.generate())
    with pytest.raises(KeyMissing):
        create("missing", config=LoadedConfig(), registry_client=server)
    assert not server.created


def test_managed_log_fetcher_uses_effective_transport_and_is_owned():
    from dnsid.config_loading import _log_registry_from_trust
    from dnsid.registry import LogRegistry

    transport = TransportConfig(dns_server="1.1.1.1:53")
    with patch(
        "dnsid.c2sp_tlog.create_dnsid_managed_verification_registry", return_value=LogRegistry()
    ) as factory:
        registry = _log_registry_from_trust(LogTrust(managed=True), transport)
    fetcher = factory.call_args.args[0].resource_fetcher
    assert fetcher._transport_config == transport
    assert fetcher in registry._owned_resources
    registry.close()
