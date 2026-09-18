"""Tests for dnsid.environment and dnsid.registry_client helpers."""

from unittest.mock import MagicMock, patch

import pytest

from dnsid.enums import DNSSECMode
from dnsid.environment import (
    config_from_environment,
    identity_manager_from_environment,
    key_store_path_from_environment,
    registry_client_from_environment,
)
from dnsid.environment import (
    dnsid_environment_variables as env_vars,
)
from dnsid.registry_client import required, required_int

# ---------------------------------------------------------------------------
# config_from_environment
# ---------------------------------------------------------------------------


class TestConfigFromEnvironment:
    def _base(self, **extra) -> dict:
        return {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["registry_url"]: "https://registry.example.com/",
            **extra,
        }

    def test_builds_config_and_derives_status_url(self):
        result = config_from_environment(
            self._base(
                **{
                    env_vars["dnssec_mode"]: "required",
                    env_vars["agent_port"]: "3001",
                }
            ),
            require=["registry_url", "agent_port"],
        )

        assert result.config.identity.domain == "alice.example.com"
        assert result.config.identity.governance_id == "example.com"
        assert result.config.identity.log_ref == "noop:0"
        assert result.registry_config.registry_url == "https://registry.example.com/"
        assert result.config.identity.status_url == (
            "https://registry.example.com/api/v1/agent/alice.example.com/status"
        )
        assert result.config.verification.dnssec_mode == DNSSECMode.REQUIRED
        assert result.agent_port == 3001

    def test_uses_explicit_status_url_when_provided(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["status_url"]: "https://status.example.com/alice",
        }
        result = config_from_environment(env)
        assert result.config.identity.status_url == "https://status.example.com/alice"

    def test_defaults_registry_url_to_local_registry(self):
        """When DNSID_REGISTRY_URL is not set, the local registry is used."""
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
        }
        result = config_from_environment(env)
        assert result.registry_config.registry_url == "http://127.0.0.1:7755"
        assert result.config.identity.status_url == (
            "http://127.0.0.1:7755/api/v1/agent/alice.example.com/status"
        )
        assert result.api_key is None

    def test_exposes_api_key_outside_config(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["api_key"]: "testnet",
        }
        result = config_from_environment(env)
        assert result.api_key == "testnet"
        assert "testnet" not in repr(result.config)
        assert "testnet" not in repr(result.registry_config)

    def test_require_raises_when_field_missing(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["status_url"]: "https://status.example.com/alice",
        }
        with pytest.raises(ValueError, match=env_vars["registry_url"]):
            config_from_environment(env, require=["registry_url"])

    def test_invalid_agent_port_raises(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["status_url"]: "https://status.example.com/alice",
            env_vars["agent_port"]: "not-a-port",
        }
        with pytest.raises(ValueError, match="DNSID_AGENT_PORT must be a positive integer"):
            config_from_environment(env)

    def test_invalid_dnssec_mode_raises(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["status_url"]: "https://status.example.com/alice",
            env_vars["dnssec_mode"]: "optional",
        }
        with pytest.raises(ValueError, match="DNSID_DNSSEC_MODE"):
            config_from_environment(env)

    def test_reads_dnssec_mode_validated(self):
        result = config_from_environment(
            self._base(**{env_vars["dnssec_mode"]: "validated"})
        )

        assert result.config.verification.dnssec_mode == DNSSECMode.VALIDATED

    def test_agent_name_and_port_in_result(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["registry_url"]: "https://registry.example.com/",
            env_vars["agent_name"]: "Alice Agent",
            env_vars["agent_port"]: "8080",
        }
        result = config_from_environment(env)
        assert result.agent_name == "Alice Agent"
        assert result.agent_port == 8080

    def test_blank_ek_url_raises(self):
        """An explicitly-set-but-blank DNSID_EK_URL is a misconfiguration, not a fallback."""
        env = self._base(**{env_vars["ek_url"]: ""})
        with pytest.raises(ValueError, match="DNSID_EK_URL is set but blank"):
            config_from_environment(env)

    def test_blank_ku_url_raises(self):
        env = self._base(**{env_vars["ku_url"]: "  "})
        with pytest.raises(ValueError, match="DNSID_KU_URL is set but blank"):
            config_from_environment(env)

    def test_unset_ek_ku_url_auto_derive(self):
        """When the vars are absent entirely, the overrides stay empty (auto-derive)."""
        result = config_from_environment(self._base())
        assert result.config.identity.ek_url == ""
        assert result.config.identity.ku_url == ""

    def test_explicit_ek_ku_url_passthrough(self):
        env = self._base(
            **{
                env_vars["ek_url"]: "https://gov.example.com/.well-known/jwks.json",
                env_vars["ku_url"]: "https://alice.example.com/.well-known/jwks.json",
            }
        )
        result = config_from_environment(env)
        assert result.config.identity.ek_url == "https://gov.example.com/.well-known/jwks.json"
        assert result.config.identity.ku_url == "https://alice.example.com/.well-known/jwks.json"

    def test_agent_name_absent_is_none(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["registry_url"]: "https://registry.example.com/",
        }
        result = config_from_environment(env)
        assert result.agent_name is None

    def test_unknown_require_field_raises(self):
        env = {
            env_vars["domain"]: "alice.example.com",
            env_vars["governance_id"]: "example.com",
            env_vars["registry_url"]: "https://registry.example.com/",
        }
        with pytest.raises(ValueError, match="unknown field"):
            config_from_environment(env, require=["nonexistent_field"])


# ---------------------------------------------------------------------------
# identity_manager_from_environment
# ---------------------------------------------------------------------------


def test_identity_manager_from_environment_prefers_cli_testnet_key_directory():
    key_provider = MagicMock()
    env = {
        "DNSID_DOMAIN": "alice.example.com",
        "DNSID_GOVERNANCE_ID": "example.com",
        "DNSID_STATUS_URL": "https://alice.example.com/status",
        "DNSID_CONFIG_DIR": "/tmp/alice",
        "DNSID_DNS_SERVER": "127.0.0.1:5353",
    }
    with patch(
        "dnsid.local_key_provider.LocalKeyProvider.from_cli_directory",
        return_value=key_provider,
    ) as load:
        manager = identity_manager_from_environment(env)

    load.assert_called_once_with("/tmp/alice")
    assert manager.local_domain == "alice.example.com"
    assert manager.config.transport.dns_server == "127.0.0.1:5353"
    manager.close()


def test_identity_manager_from_environment_falls_back_to_sdk_key_store():
    key_provider = MagicMock()
    env = {
        "DNSID_DOMAIN": "alice.example.com",
        "DNSID_GOVERNANCE_ID": "example.com",
        "DNSID_STATUS_URL": "https://alice.example.com/status",
        "DNSID_KEY_STORE": "/tmp/alice.keys.json",
    }
    with patch(
        "dnsid.local_key_provider.LocalKeyProvider.from_environment",
        return_value=key_provider,
    ) as load:
        manager = identity_manager_from_environment(env)

    load.assert_called_once_with(env)
    manager.close()


# ---------------------------------------------------------------------------
# key_store_path_from_environment
# ---------------------------------------------------------------------------


class TestKeyStorePathFromEnvironment:
    def test_returns_configured_path(self):
        env = {env_vars["key_store_path"]: ".testnet/agents/alice.keys.json"}
        assert key_store_path_from_environment(env) == ".testnet/agents/alice.keys.json"

    def test_falls_back_to_supplied_default(self):
        assert key_store_path_from_environment({}, ".tmp/keys.json") == ".tmp/keys.json"

    def test_falls_back_to_builtin_default(self):
        assert key_store_path_from_environment({}) == ".dnsid/keys.json"


# ---------------------------------------------------------------------------
# required / required_int
# ---------------------------------------------------------------------------


class TestRequired:
    def test_returns_value_when_present(self):
        assert (
            required("DNSID_DOMAIN", {"DNSID_DOMAIN": "alice.example.com"}) == "alice.example.com"
        )

    def test_raises_when_absent(self):
        with pytest.raises(ValueError, match="DNSID_DOMAIN is required"):
            required("DNSID_DOMAIN", {})

    def test_raises_when_empty(self):
        with pytest.raises(ValueError, match="DNSID_DOMAIN is required"):
            required("DNSID_DOMAIN", {"DNSID_DOMAIN": "  "})


class TestRequiredInt:
    def test_returns_int_when_valid(self):
        assert required_int("DNSID_AGENT_PORT", {"DNSID_AGENT_PORT": "3001"}) == 3001

    def test_raises_when_absent(self):
        with pytest.raises(ValueError, match="DNSID_AGENT_PORT is required"):
            required_int("DNSID_AGENT_PORT", {})

    def test_raises_when_not_an_integer(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            required_int("DNSID_AGENT_PORT", {"DNSID_AGENT_PORT": "abc"})

    def test_raises_when_zero_or_negative(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            required_int("DNSID_AGENT_PORT", {"DNSID_AGENT_PORT": "0"})
        with pytest.raises(ValueError, match="must be a positive integer"):
            required_int("DNSID_AGENT_PORT", {"DNSID_AGENT_PORT": "-1"})


class TestRegistryClientFromEnvironment:
    def test_defaults_to_local_registry_without_identity_variables(self):
        client = registry_client_from_environment({})
        assert client._base_url == "http://127.0.0.1:7755"
        assert client._api_key is None

    def test_reads_registry_url_and_api_key(self):
        client = registry_client_from_environment(
            {"DNSID_REGISTRY_URL": "https://api.dnsid.ai/", "DNSID_API_KEY": "k"}
        )
        assert client._base_url == "https://api.dnsid.ai"
        assert client._api_key == "k"
