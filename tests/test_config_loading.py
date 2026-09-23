"""Configuration loading (design 12): loaders parse, constructors default.

One test per row of the design's Validation Scenarios table, plus loader,
merge, and construct contract checks.
"""

from __future__ import annotations

import datetime
import json
import ssl
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

from dnsid import (
    DnsidConfig,
    IdentityConfig,
    IdentityManager,
    IdentityManagerDependencies,
    KeySource,
    LoadedConfig,
    LocalKeyProvider,
    LogRegistry,
    LogTrust,
    RegistryConfig,
    TransportConfig,
    TrustedEntity,
    VerificationConfig,
    construct_identity_manager,
    identity_manager_from_dnsid,
    identity_manager_from_environment,
    identity_manager_from_file,
    load_cli_directory,
    load_environment,
    load_file,
    merge_loaded_config,
    registry_client_from_environment,
)
from dnsid.enums import DNSSECMode
from dnsid.exceptions import ArgumentError
from tests.test_c2sp_trust_profile import _document as _trust_profile_document
from tests.test_c2sp_verification_registry import _policy_document
from tests.test_local_key_provider_cli import _make_private_jwk, _write_key_pair

_LOG_REF = "c2sp-tlog:public:https://log.example#abc"


def _identity_env(**extra: str) -> dict[str, str]:
    """A complete local identity via environment variables."""
    return {
        "DNSID_DOMAIN": "agent.example.com",
        "DNSID_GOVERNANCE_ID": "example.com",
        "DNSID_STATUS_URL": "https://api.example.com/status/agent.example.com",
        "DNSID_LOG_REF": _LOG_REF,
        **extra,
    }


def _cli_config(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "server_url": "https://api.example.com",
        "agent_id": "ag_1",
        "domain": "agent.example.com",
        "governance_id": "example.com",
        "status_url": "https://api.example.com/api/v1/agent/agent.example.com/status",
        "log_ref": _LOG_REF,
        "environment": "production",
    }
    base.update(overrides)
    return base


def _write_cli_dir(tmp_path: Path, config: dict[str, object], *, keys: bool = True) -> Path:
    (tmp_path / "config.json").write_text(json.dumps(config))
    if keys:
        domain_dir = tmp_path / str(config["domain"])
        domain_dir.mkdir(exist_ok=True)
        _write_key_pair(domain_dir)
    return tmp_path


def _write_file(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "dnsid.json"
    path.write_text(json.dumps(document))
    return path


def _key_store(tmp_path: Path) -> str:
    path = tmp_path / "keys.json"
    LocalKeyProvider.load(path, create_if_missing=True)
    return str(path)


@contextmanager
def _tls_server(tmp_path: Path, body: bytes):
    """Serve *body* over TLS on localhost; yields (url, ca_bundle_path)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem, key_pem = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_pem, key_pem)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"https://localhost:{server.server_address[1]}/policy", str(cert_pem)
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Validation Scenarios (design 12), in table order
# ---------------------------------------------------------------------------


def test_transport_and_verification_only_is_verification_only():
    env = {
        "DNSID_DNS_SERVER": "127.0.0.1:7753",
        "DNSID_PRIVATE_HOSTS": ".test",
        "DNSID_DNSSEC_MODE": "required",
    }
    loaded = load_environment(env)
    assert loaded.dnsid.identity is None
    manager = construct_identity_manager(loaded)
    assert manager.local_domain == ""
    assert manager.config.transport.dns_server == "127.0.0.1:7753"
    assert manager.config.transport.private_address_hosts == frozenset({".test"})
    assert manager.config.verification.dnssec_mode is DNSSECMode.REQUIRED
    manager.close()


def test_domain_without_log_ref_fails_without_placeholder():
    env = _identity_env()
    del env["DNSID_LOG_REF"]
    loaded = load_environment(env)
    assert loaded.dnsid.identity.log_ref == ""
    with pytest.raises(ArgumentError, match="log_ref"):
        construct_identity_manager(loaded, key_provider=LocalKeyProvider.generate())


def test_status_url_not_derived_from_registry_url():
    env = _identity_env(DNSID_REGISTRY_URL="https://registry.example.com")
    del env["DNSID_STATUS_URL"]
    loaded = load_environment(env)
    assert loaded.dnsid.identity.status_url == ""
    assert loaded.registry.registry_url == "https://registry.example.com"
    with pytest.raises(ArgumentError, match="status_url"):
        construct_identity_manager(loaded, key_provider=LocalKeyProvider.generate())


def test_cli_status_url_not_derived_from_server_url(tmp_path):
    cfg = _cli_config()
    del cfg["status_url"]
    loaded = load_cli_directory(_write_cli_dir(tmp_path, cfg))
    assert loaded.dnsid.identity.status_url == ""
    assert loaded.registry == RegistryConfig()  # server_url is not SDK configuration
    with pytest.raises(ArgumentError, match="status_url"):
        construct_identity_manager(loaded)


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_whitespace_dns_server_is_absent(value):
    loaded = load_environment({"DNSID_DNS_SERVER": value})
    assert loaded.dnsid.transport.dns_server == ""
    assert loaded == LoadedConfig()


def test_private_hosts_of_only_separators_is_absent():
    assert load_environment({"DNSID_PRIVATE_HOSTS": " , "}) == LoadedConfig()
    hosts = load_environment({"DNSID_PRIVATE_HOSTS": " .test , registry.dnsid.test ,, "})
    assert hosts.dnsid.transport.private_address_hosts == frozenset(
        {".test", "registry.dnsid.test"}
    )


def test_bogus_dnssec_mode_fails_in_loader():
    with pytest.raises(ArgumentError, match="DNSID_DNSSEC_MODE"):
        load_environment({"DNSID_DNSSEC_MODE": "bogus"})


def test_overlay_empty_trusted_entities_replaces_file_list(tmp_path):
    path = _write_file(
        tmp_path,
        {"dnsid": {"verification": {"trustedEntities": [{"governanceId": "acme.example"}]}}},
    )
    overlay = DnsidConfig(verification=VerificationConfig(trusted_entities=[]))
    merged = merge_loaded_config(load_file(path), LoadedConfig(dnsid=overlay))
    assert merged.dnsid.verification.trusted_entities == []
    manager = construct_identity_manager(merged)
    assert manager.config.verification.trusted_entities == ()
    manager.close()


def test_overlay_omitting_trusted_entities_keeps_file_list(tmp_path):
    path = _write_file(
        tmp_path,
        {"dnsid": {"verification": {"trustedEntities": [{"governanceId": "acme.example"}]}}},
    )
    merged = merge_loaded_config(load_file(path), LoadedConfig(dnsid=DnsidConfig()))
    assert merged.dnsid.verification.trusted_entities == [TrustedEntity("acme.example")]


def test_overlay_auto_dnssec_mode_replaces_file_required(tmp_path):
    path = _write_file(tmp_path, {"dnsid": {"verification": {"dnssecMode": "required"}}})
    auto = DnsidConfig(verification=VerificationConfig(dnssec_mode=DNSSECMode.AUTO))
    merged = merge_loaded_config(load_file(path), LoadedConfig(dnsid=auto))
    assert merged.dnsid.verification.dnssec_mode is DNSSECMode.AUTO
    manager = construct_identity_manager(merged)
    assert manager.config.verification.dnssec_mode is DNSSECMode.AUTO
    manager.close()


def test_overlay_omitting_dnssec_mode_keeps_file_required(tmp_path):
    path = _write_file(tmp_path, {"dnsid": {"verification": {"dnssecMode": "required"}}})
    merged = merge_loaded_config(load_file(path), LoadedConfig(dnsid=DnsidConfig()))
    assert merged.dnsid.verification.dnssec_mode is DNSSECMode.REQUIRED
    manager = construct_identity_manager(merged)
    assert manager.config.verification.dnssec_mode is DNSSECMode.REQUIRED
    manager.close()


def test_absent_dnssec_mode_resolves_to_auto_in_snapshot():
    manager = IdentityManager(DnsidConfig())
    assert manager.config.verification.dnssec_mode is DNSSECMode.AUTO
    manager.close()


def test_environment_policy_url_replaces_file_managed_trust_atomically(tmp_path):
    path = _write_file(tmp_path, {"logTrust": {"managed": True}})
    merged = merge_loaded_config(
        load_file(path), load_environment({"DNSID_LOG_POLICY_URL": "https://p.example/x"})
    )
    assert merged.log_trust == LogTrust(policy_url="https://p.example/x")


def test_policy_file_and_policy_url_both_set_fails_at_construction(tmp_path):
    policy = tmp_path / "policy.txt"
    policy.write_bytes(_policy_document())
    loaded = load_environment(
        {"DNSID_LOG_POLICY_FILE": str(policy), "DNSID_LOG_POLICY_URL": "https://p.example/x"}
    )
    assert loaded.log_trust.policy_document == _policy_document()
    assert loaded.log_trust.policy_url == "https://p.example/x"
    with pytest.raises(ArgumentError, match="exactly one"):
        construct_identity_manager(loaded)


def test_caller_log_registry_wins_over_loaded_trust():
    loaded = LoadedConfig(log_trust=LogTrust(policy_url="not a url", policy_document=b"x"))
    registry = LogRegistry()
    manager = construct_identity_manager(
        loaded, deps=IdentityManagerDependencies(log_registry=registry)
    )
    assert manager._log_registry is registry
    manager.close()


def test_policy_fetch_uses_ca_bundle_and_private_host_allowance(tmp_path):
    with _tls_server(tmp_path, _policy_document()) as (url, ca_bundle):
        env = {
            "DNSID_LOG_POLICY_URL": url,
            "DNSID_CA_BUNDLE": ca_bundle,
            "DNSID_PRIVATE_HOSTS": "localhost",
        }
        manager = identity_manager_from_environment(env)
        assert manager._log_registry is not None
        manager.close()

        del env["DNSID_PRIVATE_HOSTS"]
        with pytest.raises(Exception, match="fetching C2SP resource"):
            identity_manager_from_environment(env)


def test_trust_profile_file_constructs_with_bundle_lifetime_default(tmp_path):
    profile = tmp_path / "trust.json"
    profile.write_bytes(_trust_profile_document())
    loaded = load_environment({"DNSID_LOG_TRUST_PROFILE_FILE": str(profile)})
    assert loaded.log_trust.profile is not None
    assert loaded.log_trust.profile.log_prefix == "https://log.example"
    manager = construct_identity_manager(loaded)
    reader = manager._log_registry.new_reader("c2sp-tlog:public:https://log.example#x")
    assert reader._options.max_bundle_lifetime_ms == 600_000
    assert reader._options.checkpoint_freshness_ms == 600_000
    assert reader._options.max_clock_skew_ms == 0
    manager.close()


def test_cli_directory_wins_over_key_store(tmp_path):
    (tmp_path / "cli").mkdir()
    cli_dir = _write_cli_dir(tmp_path / "cli", _cli_config())
    cli_key = json.loads((cli_dir / "agent.example.com" / "private.jwk").read_text())
    env = _identity_env(DNSID_CONFIG_DIR=str(cli_dir), DNSID_KEY_STORE=_key_store(tmp_path))
    manager = identity_manager_from_environment(env)
    assert manager.get_key_set().keys[0].kid == cli_key["kid"]
    manager.close()


def test_cli_entity_key_path_supplies_entity_provider(tmp_path):
    cfg = _cli_config(
        ek_url="https://example.com/entity.jwks.json",
        ku_url="https://agent.example.com/jwks.json",
        entity_key_path="agent.example.com/entity.jwk",
    )
    cli_dir = _write_cli_dir(tmp_path, cfg)
    entity = _make_private_jwk()
    (cli_dir / "agent.example.com" / "entity.jwk").write_text(json.dumps(entity))

    loaded = load_cli_directory(cli_dir)
    assert loaded.key_source == KeySource(
        cli_directory=str(cli_dir),
        entity_key_path=str(cli_dir / "agent.example.com" / "entity.jwk"),
    )
    manager = construct_identity_manager(loaded)
    assert manager.get_entity_key_set().keys[0].kid == entity["kid"]
    manager.close()


def test_from_dnsid_default_reads_home_not_config_dir_variable(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".dnsid").mkdir(parents=True)
    _write_cli_dir(home / ".dnsid", _cli_config())
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("DNSID_CONFIG_DIR", str(tmp_path / "elsewhere"))
    manager = identity_manager_from_dnsid()
    assert manager.local_domain == "agent.example.com"
    manager.close()


def test_convenience_equals_manual_composition(tmp_path):
    cli_dir = _write_cli_dir(tmp_path, _cli_config())
    env = _identity_env(
        DNSID_CONFIG_DIR=str(cli_dir), DNSID_KU_URL="https://agent.example.com/jwks"
    )
    overlay = DnsidConfig(verification=VerificationConfig(dnssec_mode=DNSSECMode.REQUIRED))

    convenient = identity_manager_from_environment(env, overlay)
    manual = construct_identity_manager(
        merge_loaded_config(load_environment(env), LoadedConfig(dnsid=overlay))
    )
    assert convenient.config == manual.config
    assert convenient.get_key_set().keys[0].kid == manual.get_key_set().keys[0].kid
    convenient.close()
    manual.close()


def test_tooling_variables_are_ignored():
    env = _identity_env()
    tooling = {
        "DNSID_PUBLIC_URL": "https://agent.example.com",
        "DNSID_AGENT_PORT": "3001",
        "DNSID_AGENT_NAME": "Alice",
        "DNSID_AGENT_UPSTREAM": "http://localhost:3001",
        "DNSID_SERVER": "https://api.example.com",
        "DNSID_UNKNOWN_FUTURE": "x",
    }
    assert load_environment({**env, **tooling}) == load_environment(env)


def test_file_unknown_member_or_bad_log_trust_variants_fail(tmp_path):
    with pytest.raises(ArgumentError, match="unknown member 'extra'"):
        load_file(_write_file(tmp_path, {"extra": 1}))
    with pytest.raises(ArgumentError, match="unknown member 'bogus'"):
        load_file(_write_file(tmp_path, {"logTrust": {"bogus": True}}))
    with pytest.raises(ArgumentError, match="logTrust requires one of"):
        load_file(_write_file(tmp_path, {"logTrust": {}}))
    two = load_file(
        _write_file(tmp_path, {"logTrust": {"managed": True, "policyUrl": "https://p"}})
    )
    with pytest.raises(ArgumentError, match="exactly one"):
        construct_identity_manager(two)
    with pytest.raises(ArgumentError, match="managed must be true"):
        construct_identity_manager(
            load_file(_write_file(tmp_path, {"logTrust": {"managed": False}}))
        )


def test_invalid_dnsid_config_fails_before_policy_fetch():
    loaded = LoadedConfig(
        dnsid=DnsidConfig(
            verification=VerificationConfig(status_check_interval=datetime.timedelta(seconds=-1))
        ),
        log_trust=LogTrust(policy_url="https://policy.example/dnsid-policy"),
    )
    with patch("dnsid.c2sp_tlog.verification_registry.fetch_bounded_bytes") as fetch:
        with pytest.raises(ArgumentError, match="status_check_interval"):
            construct_identity_manager(loaded)
    fetch.assert_not_called()


def test_constructors_read_neither_environment_nor_files(monkeypatch):
    for name, value in _identity_env(DNSID_DNS_SERVER="127.0.0.1:1").items():
        monkeypatch.setenv(name, value)
    manager = IdentityManager(DnsidConfig())
    assert manager.local_domain == ""
    assert manager.config.transport.dns_server == ""
    manager.close()


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def test_environment_full_schema_maps_every_variable(tmp_path):
    policy = tmp_path / "policy.txt"
    policy.write_bytes(_policy_document())
    env = {
        "DNSID_DOMAIN": " agent.example.com ",
        "DNSID_GOVERNANCE_ID": "example.com",
        "DNSID_STATUS_URL": "https://api.example.com/status",
        "DNSID_LOG_REF": _LOG_REF,
        "DNSID_EK_URL": "https://example.com/ek",
        "DNSID_KU_URL": "https://agent.example.com/ku",
        "DNSID_PUBLISH_PROFILE": "dnsid-draft-01",
        "DNSID_CAPABILITIES_URL": "https://agent.example.com/agent.json",
        "DNSID_DNSSEC_MODE": "validated",
        "DNSID_DNS_SERVER": "127.0.0.1:7753",
        "DNSID_CA_BUNDLE": "/tmp/ca.pem",
        "DNSID_PRIVATE_HOSTS": ".test",
        "DNSID_LOG_POLICY_FILE": str(policy),
        "DNSID_REGISTRY_URL": "https://registry.example.com",
        "DNSID_API_KEY": "secret",
        "DNSID_CONFIG_DIR": "/tmp/cli",
        "DNSID_KEY_STORE": "/tmp/keys.json",
    }
    assert load_environment(env) == LoadedConfig(
        dnsid=DnsidConfig(
            identity=IdentityConfig(
                domain="agent.example.com",
                governance_id="example.com",
                status_url="https://api.example.com/status",
                log_ref=_LOG_REF,
                ek_url="https://example.com/ek",
                ku_url="https://agent.example.com/ku",
                publish_profile="dnsid-draft-01",
                capabilities_url="https://agent.example.com/agent.json",
            ),
            verification=VerificationConfig(dnssec_mode=DNSSECMode.VALIDATED),
            transport=TransportConfig(
                dns_server="127.0.0.1:7753",
                ca_bundle_path="/tmp/ca.pem",
                private_address_hosts=frozenset({".test"}),
            ),
        ),
        log_trust=LogTrust(policy_document=_policy_document()),
        registry=RegistryConfig(registry_url="https://registry.example.com"),
        registry_credential="secret",
        key_source=KeySource(cli_directory="/tmp/cli", key_store_path="/tmp/keys.json"),
    )


def test_environment_defaults_to_process_environment(monkeypatch):
    monkeypatch.setenv("DNSID_REGISTRY_URL", "https://registry.example.com")
    assert load_environment().registry.registry_url == "https://registry.example.com"


def test_cli_loader_maps_persisted_fields_and_ignores_non_sdk_fields(tmp_path):
    cfg = _cli_config(
        ek_url="https://example.com/ek",
        ku_url="https://agent.example.com/ku",
        capabilities_url="https://agent.example.com/agent.json",
        publish_profile="dnsid-draft-01",
        max_key_age="90d",
    )
    loaded = load_cli_directory(_write_cli_dir(tmp_path, cfg, keys=False))
    assert loaded.dnsid.identity == IdentityConfig(
        domain="agent.example.com",
        governance_id="example.com",
        status_url=cfg["status_url"],
        log_ref=_LOG_REF,
        ek_url="https://example.com/ek",
        ku_url="https://agent.example.com/ku",
        capabilities_url="https://agent.example.com/agent.json",
        publish_profile="dnsid-draft-01",
        max_key_age="90d",
    )
    assert loaded.dnsid.verification == VerificationConfig()
    assert loaded.key_source == KeySource(cli_directory=str(tmp_path))
    assert loaded.log_trust == LogTrust()


def test_cli_loader_errors(tmp_path):
    with pytest.raises(FileNotFoundError, match="run the DNSid CLI"):
        load_cli_directory(tmp_path)
    (tmp_path / "config.json").write_text("[]")
    with pytest.raises(ArgumentError, match="JSON object"):
        load_cli_directory(tmp_path)
    (tmp_path / "config.json").write_text(json.dumps({"domain": 5}))
    with pytest.raises(ArgumentError, match="domain must be a str"):
        load_cli_directory(tmp_path)
    (tmp_path / "config.json").write_text(json.dumps({"agent_id": "x"}))
    assert load_cli_directory(tmp_path).dnsid.identity is None


def test_cli_loader_resolves_relative_entity_key_path_against_config_dir(tmp_path):
    loaded = load_cli_directory(
        _write_cli_dir(tmp_path, _cli_config(entity_key_path="entity.jwk"), keys=False)
    )
    assert loaded.key_source.entity_key_path == str(tmp_path / "entity.jwk")
    absolute = tmp_path / "external" / "entity.jwk"
    loaded = load_cli_directory(
        _write_cli_dir(tmp_path, _cli_config(entity_key_path=str(absolute)), keys=False)
    )
    assert loaded.key_source.entity_key_path == str(absolute)


def test_file_loader_maps_every_section(tmp_path):
    path = _write_file(
        tmp_path,
        {
            "dnsid": {
                "identity": {"domain": "agent.example.com", "logRef": _LOG_REF},
                "verification": {
                    "dnssecMode": "required",
                    "statusCheckInterval": 30,
                    "trustedEntities": [
                        {"governanceId": "acme.example", "entityKeyThumbprints": ["a", "b"]}
                    ],
                },
                "transport": {"dnsServer": "127.0.0.1:53", "privateAddressHosts": [".test"]},
            },
            "logTrust": {"managed": True},
            "registry": {"registryUrl": "https://registry.example"},
        },
    )
    assert load_file(path) == LoadedConfig(
        dnsid=DnsidConfig(
            identity=IdentityConfig(domain="agent.example.com", log_ref=_LOG_REF),
            verification=VerificationConfig(
                dnssec_mode=DNSSECMode.REQUIRED,
                status_check_interval=datetime.timedelta(seconds=30),
                trusted_entities=[TrustedEntity("acme.example", ["a", "b"])],
            ),
            transport=TransportConfig(
                dns_server="127.0.0.1:53", private_address_hosts=frozenset({".test"})
            ),
        ),
        log_trust=LogTrust(managed=True),
        registry=RegistryConfig(registry_url="https://registry.example"),
    )


def test_file_loader_inline_profile_is_parsed(tmp_path):
    path = _write_file(tmp_path, {"logTrust": {"profile": json.loads(_trust_profile_document())}})
    assert load_file(path).log_trust.profile.log_prefix == "https://log.example"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ('{"dnsid": {}, "dnsid": {}}', "duplicate JSON member"),
        ("[]", "must be a JSON object"),
        ("{", "invalid JSON"),
        ('{"dnsid": {"identity": {"fqdn": "x"}}}', "fqdn"),
        ('{"dnsid": {"identity": {"governance_id": "x"}}}', "camelCase"),
        ('{"dnsid": {"verification": {"dnssecMode": "bogus"}}}', "dnssecMode"),
        ('{"dnsid": {"verification": {"statusCheckInterval": "30"}}}', "statusCheckInterval"),
        ('{"dnsid": {"transport": {"privateAddressHosts": ".test"}}}', "privateAddressHosts"),
        ('{"registry": {"registryUrl": 1}}', "registryUrl must be a str"),
        ('{"logTrust": {"managed": "yes"}}', "managed must be a bool"),
    ],
)
def test_file_loader_rejects_malformed_documents(tmp_path, document, message):
    path = tmp_path / "dnsid.json"
    path.write_text(document)
    with pytest.raises(ArgumentError, match=message):
        load_file(path)


def test_file_mistyped_identity_value_fails_at_construction(tmp_path):
    path = _write_file(tmp_path, {"dnsid": {"identity": {"domain": 5}}})
    with pytest.raises(ArgumentError, match="identity.domain must be a string"):
        construct_identity_manager(load_file(path), key_provider=LocalKeyProvider.generate())


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def test_merge_is_field_wise_and_log_trust_is_atomic():
    base = LoadedConfig(
        dnsid=DnsidConfig(
            identity=IdentityConfig(domain="a.example", governance_id="example", log_ref="m:1"),
            transport=TransportConfig(dns_server="1.1.1.1:53"),
        ),
        log_trust=LogTrust(managed=True),
        registry_credential="base",
        key_source=KeySource(cli_directory="/cli"),
    )
    overlay = LoadedConfig(
        dnsid=DnsidConfig(
            identity=IdentityConfig(status_url="https://s.example", log_ref="m:2"),
            transport=TransportConfig(ca_bundle_path="/ca.pem"),
        ),
        log_trust=LogTrust(policy_document=b"policy"),
        key_source=KeySource(key_store_path="/keys.json"),
    )
    merged = merge_loaded_config(base, overlay)
    assert merged.dnsid.identity == IdentityConfig(
        domain="a.example", governance_id="example", log_ref="m:2", status_url="https://s.example"
    )
    assert merged.dnsid.transport == TransportConfig(
        dns_server="1.1.1.1:53", ca_bundle_path="/ca.pem"
    )
    assert merged.log_trust == LogTrust(policy_document=b"policy")
    assert merged.registry_credential == "base"
    assert merged.key_source == KeySource(cli_directory="/cli", key_store_path="/keys.json")
    # Inputs are untouched.
    assert base.log_trust == LogTrust(managed=True)


def test_merge_absent_sections_stay_absent_and_lists_replace():
    assert merge_loaded_config(LoadedConfig(), LoadedConfig()) == LoadedConfig()
    base = LoadedConfig(
        dnsid=DnsidConfig(
            verification=VerificationConfig(trusted_entities=[TrustedEntity("a.example")]),
            transport=TransportConfig(private_address_hosts=frozenset({".a"})),
        )
    )
    overlay = LoadedConfig(
        dnsid=DnsidConfig(
            verification=VerificationConfig(trusted_entities=[TrustedEntity("b.example")]),
            transport=TransportConfig(private_address_hosts=frozenset({".b"})),
        )
    )
    merged = merge_loaded_config(base, overlay).dnsid
    assert merged.verification.trusted_entities == [TrustedEntity("b.example")]
    assert merged.transport.private_address_hosts == frozenset({".b"})


# ---------------------------------------------------------------------------
# Construct
# ---------------------------------------------------------------------------


def test_key_store_alone_supplies_operational_key(tmp_path):
    store = _key_store(tmp_path)
    manager = identity_manager_from_environment(_identity_env(DNSID_KEY_STORE=store))
    assert manager.get_key_set().keys[0].kid == LocalKeyProvider.load(store).signing_key().kid
    manager.close()


def test_identity_without_key_source_requires_caller_key_provider():
    with pytest.raises(ArgumentError, match="requires a key_provider"):
        identity_manager_from_environment(_identity_env())


def test_caller_key_providers_win(tmp_path):
    cli_dir = _write_cli_dir(tmp_path, _cli_config(entity_key_path="agent.example.com/entity.jwk"))
    (cli_dir / "agent.example.com" / "entity.jwk").write_text(json.dumps(_make_private_jwk()))
    operational, entity = LocalKeyProvider.generate(), LocalKeyProvider.generate()
    manager = identity_manager_from_dnsid(
        cli_dir,
        key_provider=operational,
        deps=IdentityManagerDependencies(entity_key_provider=entity),
    )
    assert manager.get_key_set().keys[0].kid == operational.signing_key().kid
    assert manager.get_entity_key_set().keys[0].kid == entity.signing_key().kid
    manager.close()


def test_overlay_applies_before_validation_and_key_lookup(tmp_path):
    cfg = _cli_config()
    del cfg["log_ref"]
    cli_dir = _write_cli_dir(tmp_path, cfg, keys=False)
    other_dir = cli_dir / "other.example.com"
    other_dir.mkdir()
    other_key, _ = _write_key_pair(other_dir)
    overlay = DnsidConfig(identity=IdentityConfig(domain="Other.Example.Com.", log_ref="m:1"))
    manager = identity_manager_from_dnsid(cli_dir, overlay)
    assert manager.local_domain == "other.example.com"
    assert manager.config.identity.governance_id == "example.com"  # loaded value kept
    assert manager.get_key_set().keys[0].kid == other_key["kid"]
    manager.close()


def test_per_identity_directory_key_files(tmp_path):
    _write_cli_dir(tmp_path, _cli_config(), keys=False)
    key, _ = _write_key_pair(tmp_path)
    manager = identity_manager_from_dnsid(tmp_path)
    assert manager.get_key_set().keys[0].kid == key["kid"]
    manager.close()


def test_managed_trust_selects_managed_registry():
    with patch("dnsid.c2sp_tlog.create_dnsid_managed_verification_registry") as factory:
        factory.return_value = LogRegistry()
        manager = construct_identity_manager(LoadedConfig(log_trust=LogTrust(managed=True)))
    factory.assert_called_once_with()
    assert manager._log_registry is factory.return_value
    manager.close()


def test_construct_does_not_mutate_caller_deps():
    deps = IdentityManagerDependencies()
    manager = construct_identity_manager(
        LoadedConfig(log_trust=LogTrust(policy_document=_policy_document())), deps=deps
    )
    assert deps.log_registry is None
    assert manager._log_registry is not None
    manager.close()


def test_identity_manager_from_file(tmp_path):
    path = _write_file(
        tmp_path,
        {
            "dnsid": {
                "identity": {
                    "domain": "agent.example.com",
                    "governanceId": "example.com",
                    "statusUrl": "https://api.example.com/status",
                    "logRef": _LOG_REF,
                }
            }
        },
    )
    manager = identity_manager_from_file(path, key_provider=LocalKeyProvider.generate())
    assert manager.local_domain == "agent.example.com"
    manager.close()


# ---------------------------------------------------------------------------
# Registry client
# ---------------------------------------------------------------------------


def test_registry_client_from_environment_defaults_and_reads_credential():
    client = registry_client_from_environment({})
    assert client._base_url == "http://127.0.0.1:7755"
    assert client._api_key is None
    client = registry_client_from_environment(
        {"DNSID_REGISTRY_URL": "https://api.dnsid.ai/", "DNSID_API_KEY": " k "}
    )
    assert client._base_url == "https://api.dnsid.ai"
    assert client._api_key == "k"
    with pytest.raises(ValueError):
        registry_client_from_environment({"DNSID_REGISTRY_URL": "http://example.com"})


def test_removed_environment_readers_are_gone():
    import dnsid

    for name in (
        "config_from_environment",
        "config_from_cli_directory",
        "identity_manager_from_cli_directory",
        "key_store_path_from_environment",
        "dnsid_environment_variables",
        "EnvironmentConfigResult",
        "CliConfigResult",
        "required",
        "required_int",
        "LocalKeyProviderEnvironmentOptions",
    ):
        assert not hasattr(dnsid, name), name
    assert not hasattr(LocalKeyProvider, "from_environment")


def test_loaded_config_repr_hides_registry_credential() -> None:
    loaded = load_environment({"DNSID_API_KEY": "secret-token"})
    assert loaded.registry_credential == "secret-token"
    assert "secret-token" not in repr(loaded)
