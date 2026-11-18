"""GCP composition contract, code-blind against compliance@939d241.

Authority: docs/sdk-design/{01-core-identity-manager,12-configuration-loading}.md
and docs/key-provider-packages.md. No cloud service or lifecycle dependency runs.
Direct KMS algorithm/integrity tests await agreement on the client injection seam.
"""

from __future__ import annotations

import importlib
import json
from types import ModuleType

import pytest

from dnsid import ArgumentError
from dnsid.config_loading import (
    KeySource,
    LoadedConfig,
    construct_identity_manager,
    load_file,
    merge_loaded_config,
)

VERSION = "projects/fixture/locations/global/keyRings/runtime/cryptoKeys/agent/cryptoKeyVersions/7"


class FactoryReached(Exception):
    """Test-owned stop before opening keys or doing publication work."""


def publication_document(source):
    """Independent input from the documented deployment schema, not SDK output."""
    return {
        "dnsid": {
            "identity": {
                "domain": "agent.example.test",
                "governanceId": "example.test",
                "statusUrl": "https://agent.example.test/status",
                "logRef": "c2sp-tlog:fixture",
                "ekUrl": "https://example.test/entity.jwks",
                "kuUrl": "https://agent.example.test/jwks",
            }
        },
        "keySource": source,
    }


def load_document(tmp_path, source):
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(publication_document(source)), encoding="utf-8")
    return load_file(path)


def selected_imports(monkeypatch, module=None):
    """Fake only optional-provider imports; leave ordinary Python imports intact."""
    original = importlib.import_module
    calls = []

    def selected(name, package=None):
        if name.startswith((
            "dnsid.google_kms_key_provider", "dnsid_aws", "dnsid_azure",
            "google.cloud", "google_crc32c",
        )):
            calls.append(name)
            if name == "dnsid.google_kms_key_provider":
                return module if module is not None else original(name, package)
            if module is not None and name in {"google.cloud.kms_v1", "google_crc32c"}:
                return ModuleType(name)
            raise ModuleNotFoundError(f"test dependency unavailable: {name}", name=name)
        return original(name, package)

    monkeypatch.setattr(importlib, "import_module", selected)
    return calls


def test_given_cloud_document_when_loaded_then_reference_is_preserved(tmp_path, monkeypatch):
    """**Mode**: fake-only (optional import observer). GWT: loader does not open KMS."""
    calls = selected_imports(monkeypatch)
    loaded = load_document(tmp_path, {"provider": "google-kms", "keyRef": VERSION})
    assert loaded.key_source.provider == "google-kms"
    assert loaded.key_source.key_ref == VERSION
    assert loaded.key_source.settings is None
    assert calls == []


def test_given_local_source_when_cloud_overlaid_then_operational_group_is_replaced():
    """**Mode**: real-capable (pure configuration; no external dependencies)."""
    base = LoadedConfig(key_source=KeySource(
        cli_directory="/unused/cli", key_store_path="/unused/private.jwk",
        entity_key_path="/independent/entity.jwk",
    ))
    overlay = LoadedConfig(key_source=KeySource(provider="google-kms", key_ref=VERSION))
    merged = merge_loaded_config(base, overlay)
    assert merged.key_source.provider == "google-kms"
    assert merged.key_source.key_ref == VERSION
    assert merged.key_source.cli_directory is None
    assert merged.key_source.key_store_path is None
    assert merged.key_source.entity_key_path == "/independent/entity.jwk"
    assert base.key_source.cli_directory == "/unused/cli"


def test_given_selected_google_when_constructed_then_only_fixed_factory_is_resolved(
    tmp_path, monkeypatch,
):
    """**Mode**: fake-only (optional package stops before key opening)."""
    module = ModuleType("dnsid.google_kms_key_provider")
    events = []

    def validate_config(source):
        events.append(("validate", source.provider, source.key_ref))

    def key_provider_from_config(source):
        events.append(("open", source.provider, source.key_ref))
        raise FactoryReached

    module.validate_config = validate_config
    module.key_provider_from_config = key_provider_from_config
    calls = selected_imports(monkeypatch, module)
    loaded = load_document(tmp_path, {"provider": "google-kms", "keyRef": VERSION})
    try:
        construct_identity_manager(loaded)
    except Exception as error:
        assert isinstance(error, FactoryReached), (
            f"selected installed Google factory must be reached before publication; got {error!r}"
        )
    else:
        pytest.fail("construction returned without opening the selected existing-key provider")
    assert set(calls) == {
        "dnsid.google_kms_key_provider", "google.cloud.kms_v1", "google_crc32c",
    }
    assert events == [("validate", "google-kms", VERSION), ("open", "google-kms", VERSION)]


def test_given_missing_google_when_constructed_then_error_names_install_remedy(
    tmp_path, monkeypatch,
):
    """**Mode**: fake-only (Google dependency deliberately unavailable)."""
    calls = selected_imports(monkeypatch)
    loaded = load_document(tmp_path, {"provider": "google-kms", "keyRef": VERSION})
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    with pytest.raises(ArgumentError) as caught:
        construct_identity_manager(loaded)
    message = str(caught.value).lower()
    assert "google-kms" in message
    assert "dnsid[gcp]" in message, "missing-provider error must name the installable extra"
    assert "install" in message, "missing-provider error must tell the caller how to remedy it"
    assert set(calls) == {"dnsid.google_kms_key_provider", "google.cloud.kms_v1"}
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before


def test_given_factory_rejection_when_constructed_then_no_fallback_or_open(tmp_path, monkeypatch):
    """**Mode**: fake-only (validation rejects before any service operation)."""
    module = ModuleType("dnsid.google_kms_key_provider")
    opened = []

    def validate_config(source):
        raise ArgumentError("fixture rejects unsupported algorithm before opening key")

    def key_provider_from_config(source):
        opened.append(source)
        raise AssertionError("invalid source must never be opened")

    module.validate_config = validate_config
    module.key_provider_from_config = key_provider_from_config
    calls = selected_imports(monkeypatch, module)
    loaded = load_document(tmp_path, {"provider": "google-kms", "keyRef": VERSION})
    with pytest.raises(ArgumentError) as caught:
        construct_identity_manager(loaded)
    assert "fixture rejects unsupported algorithm" in str(caught.value)
    assert opened == []
    assert set(calls) == {
        "dnsid.google_kms_key_provider", "google.cloud.kms_v1", "google_crc32c",
    }


def test_given_verifier_when_source_present_then_no_optional_provider_is_loaded(monkeypatch):
    """**Mode**: fake-only (import observer); no local identity needs a signer."""
    calls = selected_imports(monkeypatch)
    loaded = LoadedConfig(key_source=KeySource(provider="google-kms", key_ref=VERSION))
    construct_identity_manager(loaded)
    assert calls == []


def test_given_unversioned_google_key_when_constructed_then_reference_is_rejected(tmp_path):
    """**Mode**: real-capable (invalid input rejected without contacting KMS).

    Given an installed provider selected through the existing public boundary,
    when the reference names a mutable CryptoKey instead of a CryptoKeyVersion,
    then the caller receives an actionable version-reference validation error.
    """
    loaded = load_document(tmp_path, {
        "provider": "google-kms",
        "keyRef": "projects/fixture/locations/global/keyRings/runtime/cryptoKeys/agent",
    })
    with pytest.raises(ArgumentError) as caught:
        construct_identity_manager(loaded)
    assert "cryptokeyversion" in str(caught.value).lower(), (
        "google-kms must validate an existing immutable CryptoKeyVersion reference; "
        f"got {caught.value!r}"
    )


def test_given_injected_signer_when_cloud_selected_then_displaced_package_is_not_loaded(
    tmp_path, monkeypatch, ed_provider,
):
    """**Mode**: fake-only (signer and import observer); lifecycle work is held.

    Stop at the existing harness publication boundary, observing only whether
    composition imported the displaced package before handing off the manager.
    """
    from dnsid import IdentityManager

    class PublicationBoundary(Exception):
        pass

    def stop(*args, **kwargs):
        raise PublicationBoundary

    monkeypatch.setattr(IdentityManager, "_verify_publication_evidence", stop)
    calls = selected_imports(monkeypatch)
    loaded = load_document(tmp_path, {
        "provider": "google-kms", "keyRef": VERSION,
        "settings": {"displacedInvalidSetting": "must not validate"},
    })
    try:
        construct_identity_manager(loaded, key_provider=ed_provider)
    except PublicationBoundary:
        pass
    assert calls == []
