"""Tests for dnsid.cli_config and LocalKeyProvider.from_cli_directory."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from dnsid import (
    CliConfigResult,
    IdentityManager,
    LocalKeyProvider,
    config_from_cli_directory,
    identity_manager_from_cli_directory,
)
from dnsid._crypto import compute_thumbprint, verify_signature
from dnsid._utils import b64url_decode, b64url_encode
from dnsid.enums import DNSSECMode
from dnsid.models import DEFAULT_REGISTRY_URL

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(tmp_path: Path, **overrides) -> dict:
    base = {
        "domain": "agent.example.com",
        "governance_id": "example.com",
        "server_url": "https://api.example.com",
        "status_url": "https://api.example.com/api/v1/agent/agent.example.com/status",
    }
    base.update(overrides)
    return base


def _write_root_dir(tmp_path: Path, config: dict, *, with_domain_subdir: bool = True) -> Path:
    """Write a root-style ~/.dnsid directory."""
    (tmp_path / "config.json").write_text(json.dumps(config))
    if with_domain_subdir:
        (tmp_path / config["domain"]).mkdir(parents=True, exist_ok=True)
    return tmp_path


def _write_identity_dir(tmp_path: Path, config: dict) -> Path:
    """Write a per-identity directory (no domain sub-directory)."""
    (tmp_path / "config.json").write_text(json.dumps(config))
    return tmp_path


def _make_key_pair() -> tuple[dict, dict]:
    """Return (private_jwk, public_jwk) dicts for a fresh Ed25519 key pair."""
    private = ed25519.Ed25519PrivateKey.generate()
    pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    x = b64url_encode(pub)
    d = b64url_encode(priv)
    kid = str(uuid.uuid4())
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid, "x": x}
    private_jwk = {**public_jwk, "d": d}
    return private_jwk, public_jwk


def _make_private_jwk() -> dict:
    private_jwk, _ = _make_key_pair()
    return private_jwk


def _make_private_jwk_no_kid() -> dict:
    jwk = _make_private_jwk()
    del jwk["kid"]
    return jwk


def _make_private_pem() -> bytes:
    private = ed25519.Ed25519PrivateKey.generate()
    return private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _write_key_pair(directory: Path, *, kid: str | None = None) -> tuple[dict, dict]:
    """Write private.jwk and public.jwk to directory; return (private, public) dicts."""
    private_jwk, public_jwk = _make_key_pair()
    if kid is not None:
        private_jwk = {**private_jwk, "kid": kid}
        public_jwk = {**public_jwk, "kid": kid}
    (directory / "private.jwk").write_text(json.dumps(private_jwk))
    (directory / "public.jwk").write_text(json.dumps(public_jwk))
    return private_jwk, public_jwk


# ---------------------------------------------------------------------------
# config_from_cli_directory — root directory
# ---------------------------------------------------------------------------


class TestConfigFromCliDirectoryRootDir:
    def test_reads_domain_and_governance_id(self, tmp_path):
        cfg = _make_config(tmp_path)
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.domain == "agent.example.com"
        assert result.config.identity.governance_id == "example.com"

    def test_uses_explicit_status_url(self, tmp_path):
        cfg = _make_config(tmp_path, status_url="https://custom.example.com/status")
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.status_url == "https://custom.example.com/status"

    def test_derives_status_url_from_server_url_when_absent(self, tmp_path):
        cfg = _make_config(tmp_path)
        del cfg["status_url"]
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.status_url == (
            "https://api.example.com/api/v1/agent/agent.example.com/status"
        )

    def test_does_not_invent_log_ref_when_absent(self, tmp_path):
        cfg = _make_config(tmp_path)
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.log_ref == ""

    def test_uses_explicit_log_ref(self, tmp_path):
        cfg = _make_config(tmp_path, log_ref="ledger:abc123")
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.log_ref == "ledger:abc123"

    def test_registry_config_uses_server_url(self, tmp_path):
        cfg = _make_config(tmp_path, server_url="https://registry.example.com")
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.registry_config.registry_url == "https://registry.example.com"

    def test_registry_config_defaults_to_api_dnsid_ai_when_server_url_absent(self, tmp_path):
        cfg = _make_config(tmp_path)
        del cfg["server_url"]
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.registry_config.registry_url == DEFAULT_REGISTRY_URL

    def test_key_directory_is_domain_subdir(self, tmp_path):
        cfg = _make_config(tmp_path)
        _write_root_dir(tmp_path, cfg, with_domain_subdir=True)
        result = config_from_cli_directory(tmp_path)
        assert result.key_directory == tmp_path / "agent.example.com"

    def test_returns_cli_config_result(self, tmp_path):
        cfg = _make_config(tmp_path)
        _write_root_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert isinstance(result, CliConfigResult)

    def test_defaults_to_home_dnsid(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        cfg = _make_config(tmp_path)
        dnsid_dir = tmp_path / ".dnsid"
        dnsid_dir.mkdir()
        (dnsid_dir / "config.json").write_text(json.dumps(cfg))
        (dnsid_dir / cfg["domain"]).mkdir()
        result = config_from_cli_directory()
        assert result.config.identity.domain == "agent.example.com"


# ---------------------------------------------------------------------------
# config_from_cli_directory — per-identity directory
# ---------------------------------------------------------------------------


class TestConfigFromCliDirectoryIdentityDir:
    def test_key_directory_is_the_given_dir_when_no_domain_subdir(self, tmp_path):
        cfg = _make_config(tmp_path)
        _write_identity_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.key_directory == tmp_path

    def test_reads_config_correctly(self, tmp_path):
        cfg = _make_config(tmp_path, status_url="https://status.example.com/s")
        _write_identity_dir(tmp_path, cfg)
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.status_url == "https://status.example.com/s"

    def test_key_directory_is_base_when_key_file_present_despite_domain_subdir(self, tmp_path):
        cfg = _make_config(tmp_path)
        _write_identity_dir(tmp_path, cfg)
        # Simulate a same-named child directory that should NOT be picked as key_directory.
        (tmp_path / cfg["domain"]).mkdir()
        (tmp_path / "private.jwk").write_text("{}")  # presence is enough for this test
        result = config_from_cli_directory(tmp_path)
        assert result.key_directory == tmp_path


# ---------------------------------------------------------------------------
# config_from_cli_directory — error cases
# ---------------------------------------------------------------------------


class TestConfigFromCliDirectoryErrors:
    def test_raises_file_not_found_with_helpful_message(self, tmp_path):
        with pytest.raises(
            FileNotFoundError, match="run the DNSid CLI to register your domain first"
        ):
            config_from_cli_directory(tmp_path)

    def test_error_includes_config_path(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="config.json"):
            config_from_cli_directory(tmp_path)

    def test_raises_value_error_for_invalid_json(self, tmp_path):
        (tmp_path / "config.json").write_text("not-json{{{")
        with pytest.raises(ValueError, match="invalid JSON"):
            config_from_cli_directory(tmp_path)

    def test_raises_value_error_when_config_is_json_array(self, tmp_path):
        (tmp_path / "config.json").write_text("[]")
        with pytest.raises(ValueError, match="must contain a JSON object"):
            config_from_cli_directory(tmp_path)

    def test_raises_value_error_when_domain_is_not_a_string(self, tmp_path):
        cfg = _make_config(tmp_path, domain=42)
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        with pytest.raises(ValueError, match="must be a string"):
            config_from_cli_directory(tmp_path)

    def test_raises_value_error_when_domain_missing(self, tmp_path):
        cfg = _make_config(tmp_path)
        del cfg["domain"]
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        with pytest.raises(ValueError, match="'domain' is required"):
            config_from_cli_directory(tmp_path)

    def test_raises_value_error_when_governance_id_missing(self, tmp_path):
        cfg = _make_config(tmp_path)
        del cfg["governance_id"]
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        with pytest.raises(ValueError, match="'governance_id'"):
            config_from_cli_directory(tmp_path)


# ---------------------------------------------------------------------------
# config_from_cli_directory — camelCase aliases
# ---------------------------------------------------------------------------


class TestConfigFromCliDirectoryCamelCaseAliases:
    def test_accepts_governanceId(self, tmp_path):
        cfg = {
            "domain": "agent.example.com",
            "governanceId": "example.com",
            "server_url": "https://api.example.com",
        }
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.governance_id == "example.com"

    def test_accepts_statusUrl(self, tmp_path):
        cfg = _make_config(tmp_path)
        del cfg["status_url"]
        cfg["statusUrl"] = "https://custom.example.com/status"
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.status_url == "https://custom.example.com/status"

    def test_accepts_registryUrl_as_server_url_alias(self, tmp_path):
        cfg = {
            "domain": "agent.example.com",
            "governance_id": "example.com",
            "registryUrl": "https://registry.example.com",
        }
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.registry_config.registry_url == "https://registry.example.com"

    def test_accepts_logRef(self, tmp_path):
        cfg = _make_config(tmp_path, logRef="ledger:abc")
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.log_ref == "ledger:abc"

    def test_snake_case_takes_priority_when_both_present(self, tmp_path):
        cfg = _make_config(
            tmp_path, governance_id="snake.example.com", governanceId="camel.example.com"
        )
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.governance_id == "snake.example.com"


# ---------------------------------------------------------------------------
# config_from_cli_directory — domain normalization for key directory
# ---------------------------------------------------------------------------


class TestConfigFromCliDirectoryDomainNormalization:
    def test_finds_keys_when_config_domain_has_trailing_dot(self, tmp_path):
        cfg = _make_config(tmp_path, domain="agent.example.com.")
        (tmp_path / "agent.example.com").mkdir()
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.key_directory == tmp_path / "agent.example.com"

    def test_finds_keys_when_config_domain_has_uppercase(self, tmp_path):
        cfg = _make_config(tmp_path, domain="Agent.Example.Com")
        (tmp_path / "agent.example.com").mkdir()
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.key_directory == tmp_path / "agent.example.com"

    def test_derived_status_url_uses_normalized_domain(self, tmp_path):
        cfg = _make_config(tmp_path, domain="Agent.Example.Com.")
        del cfg["status_url"]
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.status_url == (
            "https://api.example.com/api/v1/agent/agent.example.com/status"
        )

    def test_derived_status_url_uses_normalized_domain_with_trailing_dot(self, tmp_path):
        cfg = {
            "domain": "agent.example.com.",
            "governance_id": "example.com",
            "server_url": "https://api.example.com",
        }
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert "Agent" not in result.config.identity.status_url
        assert result.config.identity.status_url.endswith("/agent.example.com/status")


# ---------------------------------------------------------------------------
# config_from_cli_directory — kuUrl and capabilitiesUrl
# ---------------------------------------------------------------------------


class TestConfigFromCliDirectoryOptionalProtocolFields:
    def test_reads_ku_url(self, tmp_path):
        cfg = _make_config(tmp_path, ku_url="https://keys.example.com/jwks.json")
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.ku_url == "https://keys.example.com/jwks.json"

    def test_reads_kuUrl_alias(self, tmp_path):
        cfg = _make_config(tmp_path, kuUrl="https://keys.example.com/jwks.json")
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.ku_url == "https://keys.example.com/jwks.json"

    def test_reads_capabilities_url(self, tmp_path):
        cfg = _make_config(
            tmp_path, capabilities_url="https://agent.example.com/.well-known/agent.json"
        )
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert (
            result.config.identity.capabilities_url
            == "https://agent.example.com/.well-known/agent.json"
        )

    def test_reads_capabilitiesUrl_alias(self, tmp_path):
        cfg = _make_config(
            tmp_path, capabilitiesUrl="https://agent.example.com/.well-known/agent.json"
        )
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert (
            result.config.identity.capabilities_url
            == "https://agent.example.com/.well-known/agent.json"
        )

    def test_defaults_to_empty_when_absent(self, tmp_path):
        cfg = _make_config(tmp_path)
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.ku_url == ""
        assert result.config.identity.capabilities_url == ""

    def test_reads_authoritative_publication_fields(self, tmp_path):
        cfg = _make_config(
            tmp_path,
            log_ref="c2sp-tlog:testnet:https://log.example#agent.example.com",
            ek_url="https://example.com/entity.jwks.json",
            ku_url="https://agent.example.com/jwks.json",
            capabilities_url="https://agent.example.com/agent.json",
            publish_profile="dnsid-draft-01",
            max_key_age="30d",
        )
        (tmp_path / "config.json").write_text(json.dumps(cfg))

        protocol = config_from_cli_directory(tmp_path).config.identity

        assert protocol.log_ref == cfg["log_ref"]
        assert protocol.ek_url == cfg["ek_url"]
        assert protocol.ku_url == cfg["ku_url"]
        assert protocol.capabilities_url == cfg["capabilities_url"]
        assert protocol.publish_profile == cfg["publish_profile"]
        assert protocol.max_key_age == cfg["max_key_age"]


class TestConfigFromCliDirectoryEntityKeyPath:
    def test_resolves_export_root_path_relative_to_root_config(self, tmp_path):
        cfg = _make_config(tmp_path, entity_key_path="agent.example.com/entity.jwk")
        _write_root_dir(tmp_path, cfg)

        result = config_from_cli_directory(tmp_path)

        assert result.entity_key_path == tmp_path / "agent.example.com" / "entity.jwk"

    def test_resolves_per_identity_path_relative_to_identity_config(self, tmp_path):
        cfg = _make_config(tmp_path, entity_key_path="entity.jwk")
        _write_identity_dir(tmp_path, cfg)

        result = config_from_cli_directory(tmp_path)

        assert result.entity_key_path == tmp_path / "entity.jwk"

    def test_preserves_absolute_live_config_path(self, tmp_path):
        entity_path = tmp_path / "external" / "entity.jwk"
        cfg = _make_config(tmp_path, entity_key_path=str(entity_path))
        _write_identity_dir(tmp_path, cfg)

        result = config_from_cli_directory(tmp_path)

        assert result.entity_key_path == entity_path


# ---------------------------------------------------------------------------
# LocalKeyProvider.from_cli_directory — private.jwk only
# ---------------------------------------------------------------------------


class TestLocalKeyProviderFromCliDirectoryJwk:
    def test_loads_private_jwk(self, tmp_path):
        jwk = _make_private_jwk()
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert provider.signing_key().kid == jwk["kid"]

    def test_derives_kid_from_thumbprint_when_absent(self, tmp_path):
        jwk = _make_private_jwk_no_kid()
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        expected_kid = compute_thumbprint(jwk)
        assert provider.signing_key().kid == expected_kid

    def test_loaded_key_can_sign(self, tmp_path):
        jwk = _make_private_jwk()
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        sig = provider.sign(b"hello")
        assert isinstance(sig, bytes) and len(sig) == 64

    def test_raises_when_d_field_absent(self, tmp_path):
        jwk = _make_private_jwk()
        del jwk["d"]
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        with pytest.raises(ValueError, match="must include Ed25519 private key material"):
            LocalKeyProvider.from_cli_directory(tmp_path)

    def test_raises_on_invalid_json(self, tmp_path):
        (tmp_path / "private.jwk").write_text("{bad json")
        with pytest.raises(ValueError, match="invalid JSON"):
            LocalKeyProvider.from_cli_directory(tmp_path)

    def test_raises_when_private_jwk_is_json_array(self, tmp_path):
        (tmp_path / "private.jwk").write_text("[]")
        with pytest.raises(ValueError, match="must contain a JSON object"):
            LocalKeyProvider.from_cli_directory(tmp_path)

    def test_raises_when_private_jwk_is_json_number(self, tmp_path):
        (tmp_path / "private.jwk").write_text("42")
        with pytest.raises(ValueError, match="must contain a JSON object"):
            LocalKeyProvider.from_cli_directory(tmp_path)

    def test_list_key_ids_contains_only_active(self, tmp_path):
        jwk = _make_private_jwk()
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert provider.list_key_ids() == [jwk["kid"]]

    def test_raises_when_private_jwk_has_stale_x(self, tmp_path):
        private_jwk, _ = _make_key_pair()
        _, other_public = _make_key_pair()
        stale_jwk = {**private_jwk, "x": other_public["x"]}
        (tmp_path / "private.jwk").write_text(json.dumps(stale_jwk))
        with pytest.raises(ValueError, match="mismatched Ed25519"):
            LocalKeyProvider.from_cli_directory(tmp_path)

    def test_raises_when_private_jwk_has_invalid_d(self, tmp_path):
        private_jwk, _ = _make_key_pair()
        bad_jwk = {**private_jwk, "d": "not-valid-base64url!!!"}
        (tmp_path / "private.jwk").write_text(json.dumps(bad_jwk))
        with pytest.raises(ValueError, match="cannot load Ed25519 private key"):
            LocalKeyProvider.from_cli_directory(tmp_path)

    def test_raises_when_x_field_absent(self, tmp_path):
        private_jwk, _ = _make_key_pair()
        jwk_no_x = {k: v for k, v in private_jwk.items() if k != "x"}
        (tmp_path / "private.jwk").write_text(json.dumps(jwk_no_x))
        with pytest.raises(ValueError, match="must include Ed25519 private key material"):
            LocalKeyProvider.from_cli_directory(tmp_path)


# ---------------------------------------------------------------------------
# LocalKeyProvider.from_cli_directory — public.jwk is ignored
# ---------------------------------------------------------------------------


class TestLocalKeyProviderFromCliDirectoryPublicJwkIgnored:
    def test_public_jwk_is_ignored(self, tmp_path):
        jwk = _make_private_jwk()
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        (tmp_path / "public.jwk").write_text("{bad json")  # malformed — must not matter
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert provider.signing_key().kid == jwk["kid"]

    def test_signing_key_has_no_private_material(self, tmp_path):
        jwk = _make_private_jwk()
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert (
            not hasattr(provider.signing_key(), "d")
            or provider.signing_key().__dict__.get("d") is None
        )

    def test_derives_kid_when_private_jwk_has_empty_string_kid(self, tmp_path):
        private_jwk, _ = _make_key_pair()
        (tmp_path / "private.jwk").write_text(json.dumps({**private_jwk, "kid": ""}))
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert provider.signing_key().kid  # thumbprint, not empty string

    def test_derives_kid_when_private_jwk_has_null_kid(self, tmp_path):
        private_jwk, _ = _make_key_pair()
        (tmp_path / "private.jwk").write_text(json.dumps({**private_jwk, "kid": None}))
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert provider.signing_key().kid  # thumbprint, not null

    def test_raises_when_crv_is_not_ed25519(self, tmp_path):
        private_jwk, _ = _make_key_pair()
        (tmp_path / "private.jwk").write_text(json.dumps({**private_jwk, "crv": "P-256"}))
        with pytest.raises(ValueError, match="must include Ed25519 private key material"):
            LocalKeyProvider.from_cli_directory(tmp_path)


# ---------------------------------------------------------------------------
# LocalKeyProvider.from_cli_directory — private.pem
# ---------------------------------------------------------------------------


class TestLocalKeyProviderFromCliDirectoryPem:
    def test_loads_private_pem(self, tmp_path):
        pem = _make_private_pem()
        (tmp_path / "private.pem").write_text(pem.decode())
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert provider.signing_key().kid  # kid derived from thumbprint

    def test_pem_kid_is_deterministic(self, tmp_path):
        pem = _make_private_pem()
        (tmp_path / "private.pem").write_text(pem.decode())
        p1 = LocalKeyProvider.from_cli_directory(tmp_path)
        p2 = LocalKeyProvider.from_cli_directory(tmp_path)
        assert p1.signing_key().kid == p2.signing_key().kid

    def test_pem_loaded_key_can_sign(self, tmp_path):
        pem = _make_private_pem()
        (tmp_path / "private.pem").write_text(pem.decode())
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        sig = provider.sign(b"world")
        assert isinstance(sig, bytes) and len(sig) == 64

    def test_jwk_takes_precedence_over_pem(self, tmp_path):
        jwk = _make_private_jwk()
        (tmp_path / "private.jwk").write_text(json.dumps(jwk))
        (tmp_path / "private.pem").write_text(_make_private_pem().decode())
        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        assert provider.signing_key().kid == jwk["kid"]


# ---------------------------------------------------------------------------
# LocalKeyProvider.from_cli_directory — error cases
# ---------------------------------------------------------------------------


class TestLocalKeyProviderFromCliDirectoryErrors:
    def test_raises_file_not_found_when_no_key_files(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="private.jwk or private.pem"):
            LocalKeyProvider.from_cli_directory(tmp_path)


# ---------------------------------------------------------------------------
# identity_manager_from_cli_directory
# ---------------------------------------------------------------------------


class TestIdentityManagerFromCliDirectory:
    def _setup(self, tmp_path: Path) -> Path:
        """Write a minimal root-style ~/.dnsid with config and keys."""
        cfg = _make_config(tmp_path)
        domain_dir = tmp_path / cfg["domain"]
        domain_dir.mkdir()
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        _write_key_pair(domain_dir)
        return tmp_path

    def test_returns_identity_manager(self, tmp_path):
        self._setup(tmp_path)
        idm = identity_manager_from_cli_directory(tmp_path)
        assert isinstance(idm, IdentityManager)

    def test_manager_has_correct_domain(self, tmp_path):
        self._setup(tmp_path)
        idm = identity_manager_from_cli_directory(tmp_path)
        assert idm.local_domain == "agent.example.com"

    def test_manager_has_correct_governance_id(self, tmp_path):
        self._setup(tmp_path)
        idm = identity_manager_from_cli_directory(tmp_path)
        assert idm.config.identity.governance_id == "example.com"

    def test_raises_file_not_found_with_helpful_message(self, tmp_path):
        with pytest.raises(
            FileNotFoundError, match="run the DNSid CLI to register your domain first"
        ):
            identity_manager_from_cli_directory(tmp_path)

    def test_works_with_per_identity_directory(self, tmp_path):
        cfg = _make_config(tmp_path)
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        _write_key_pair(tmp_path)
        idm = identity_manager_from_cli_directory(tmp_path)
        assert idm.local_domain == "agent.example.com"

    def test_cli_transport_fields_are_ignored(self, tmp_path):
        # Verification/transport settings come only from the caller's config.
        cfg = _make_config(tmp_path, dns_server="127.0.0.1:5353", ca_bundle_path="/etc/ca.pem")
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.transport.dns_server == ""
        assert result.config.transport.ca_bundle_path == ""

    def test_caller_provided_deps_are_respected(self, tmp_path):
        from dnsid import IdentityManagerDependencies

        cfg = _make_config(tmp_path)
        domain_dir = tmp_path / cfg["domain"]
        domain_dir.mkdir()
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        _write_key_pair(domain_dir)
        custom_deps = IdentityManagerDependencies()
        idm = identity_manager_from_cli_directory(tmp_path, deps=custom_deps)
        assert isinstance(idm, IdentityManager)

    def test_export_config_loads_entity_key_and_publishes_with_it(self, tmp_path):
        cfg = _make_config(
            tmp_path,
            log_ref="c2sp-tlog:testnet:https://log.example#agent.example.com",
            ek_url="https://example.com/entity.jwks.json",
            ku_url="https://agent.example.com/jwks.json",
            capabilities_url="https://agent.example.com/agent.json",
            publish_profile="dnsid-draft-01",
            max_key_age="30d",
            entity_key_path="agent.example.com/entity.jwk",
        )
        domain_dir = tmp_path / cfg["domain"]
        domain_dir.mkdir()
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        operational, _ = _write_key_pair(domain_dir)
        entity = _make_private_jwk()
        (domain_dir / "entity.jwk").write_text(json.dumps(entity))

        idm = identity_manager_from_cli_directory(tmp_path)
        record_text = idm.create_txt_record()

        from dnsid import DnsIdTxtRecord

        record = DnsIdTxtRecord.parse(record_text)
        assert idm.get_entity_key_set().keys[0].kid == entity["kid"]
        assert idm.get_key_set().keys[0].kid == operational["kid"]
        assert verify_signature(
            entity,
            record.canonical().encode("ascii"),
            b64url_decode(record.sg),
        )

    def test_supplied_entity_provider_is_not_overridden(self, tmp_path):
        from dnsid import IdentityManagerDependencies

        cfg = _make_config(tmp_path, entity_key_path="agent.example.com/entity.jwk")
        domain_dir = tmp_path / cfg["domain"]
        domain_dir.mkdir()
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        _write_key_pair(domain_dir)
        (domain_dir / "entity.jwk").write_text(json.dumps(_make_private_jwk()))
        supplied = LocalKeyProvider.generate()

        idm = identity_manager_from_cli_directory(
            tmp_path,
            deps=IdentityManagerDependencies(entity_key_provider=supplied),
        )

        assert idm.get_entity_key_set().keys[0].kid == supplied.signing_key().kid


# ---------------------------------------------------------------------------
# config_from_cli_directory — transport and protocol fields
# ---------------------------------------------------------------------------


class TestConfigFromCliDirectoryCallerConfig:
    def test_verification_and_transport_come_from_caller_config(self, tmp_path):
        import datetime

        from dnsid import DnsidConfig, TransportConfig, VerificationConfig

        cfg = _make_config(tmp_path, dnssec_mode="required", dns_server="10.0.0.1:53")
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        caller = DnsidConfig(
            verification=VerificationConfig(
                dnssec_mode=DNSSECMode.VALIDATED,
                status_check_interval=datetime.timedelta(seconds=30),
            ),
            transport=TransportConfig(ca_bundle_path="/etc/ca.pem"),
        )
        result = config_from_cli_directory(tmp_path, caller)
        assert result.config.verification.dnssec_mode is DNSSECMode.VALIDATED
        assert result.config.verification.status_check_interval == datetime.timedelta(seconds=30)
        assert result.config.transport.ca_bundle_path == "/etc/ca.pem"
        assert result.config.transport.dns_server == ""

    def test_defaults_when_no_caller_config(self, tmp_path):
        cfg = _make_config(tmp_path)
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        result = config_from_cli_directory(tmp_path)
        assert result.config.verification.dnssec_mode is DNSSECMode.AUTO
        assert result.config.verification.trusted_entities is None
        assert result.config.transport.dns_server == ""

    def test_identity_overlay_wins_and_applies_before_derivation(self, tmp_path):
        from dnsid import DnsidConfig, IdentityConfig

        cfg = _make_config(tmp_path)
        del cfg["status_url"]
        (tmp_path / "config.json").write_text(json.dumps(cfg))
        (tmp_path / "other.example.com").mkdir()
        caller = DnsidConfig(
            identity=IdentityConfig(
                domain="Other.Example.Com", governance_id="", log_ref="ledger:x", status_url=""
            )
        )
        result = config_from_cli_directory(tmp_path, caller)
        assert result.config.identity.domain == "Other.Example.Com"
        assert result.config.identity.governance_id == "example.com"  # loaded default kept
        assert result.config.identity.log_ref == "ledger:x"
        # status_url derived from the effective (overlaid, normalized) domain
        assert result.config.identity.status_url.endswith("/agent/other.example.com/status")
        # key files located by the effective domain, not the persisted one
        assert result.key_directory == tmp_path / "other.example.com"


# ---------------------------------------------------------------------------
# LocalKeyProvider.from_domain
# ---------------------------------------------------------------------------


class TestLocalKeyProviderFromDomain:
    def test_loads_keys_from_domain_subdir(self, tmp_path):
        domain_dir = tmp_path / "agent.example.com"
        domain_dir.mkdir()
        private_jwk, _ = _make_key_pair()
        _write_key_pair(domain_dir, kid="domain-key")
        provider = LocalKeyProvider.from_domain("agent.example.com", tmp_path)
        assert provider.signing_key().kid == "domain-key"

    def test_normalises_trailing_dot(self, tmp_path):
        domain_dir = tmp_path / "agent.example.com"
        domain_dir.mkdir()
        _write_key_pair(domain_dir, kid="normalised-key")
        provider = LocalKeyProvider.from_domain("agent.example.com.", tmp_path)
        assert provider.signing_key().kid == "normalised-key"

    def test_loaded_key_can_sign(self, tmp_path):
        domain_dir = tmp_path / "agent.example.com"
        domain_dir.mkdir()
        _write_key_pair(domain_dir)
        provider = LocalKeyProvider.from_domain("agent.example.com", tmp_path)
        sig = provider.sign(b"payload")
        assert isinstance(sig, bytes) and len(sig) == 64

    def test_raises_when_domain_dir_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            LocalKeyProvider.from_domain("agent.example.com", tmp_path)


class TestDnsidConfigDirEnv:
    def test_default_path_honors_dnsid_config_dir(self, tmp_path, monkeypatch):
        """When no path is given, DNSID_CONFIG_DIR selects the identity dir
        (set by `dnsid testnet run` for child processes)."""
        cfg = _make_config(tmp_path)
        _write_root_dir(tmp_path, cfg)
        monkeypatch.setenv("DNSID_CONFIG_DIR", str(tmp_path))
        result = config_from_cli_directory()
        assert result.config.identity.domain == cfg["domain"]

    def test_explicit_path_wins_over_env(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        _write_root_dir(tmp_path, cfg)
        monkeypatch.setenv("DNSID_CONFIG_DIR", str(tmp_path / "does-not-exist"))
        result = config_from_cli_directory(tmp_path)
        assert result.config.identity.domain == cfg["domain"]
