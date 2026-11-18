"""Operational file warning at fresh startup (shared design 12; known-foundry#57).

Mode: fake-only for publication evidence, real local storage/signing and native
subprocess warning delivery. The existing local_publication fixture bypasses
publication verification: these are NOT full functional publication proofs.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from dnsid import KeySource, LoadedConfig, LocalKeyProvider, construct_identity_manager
from tests.test_config_loading import _identity_env, _write_file
from tests.test_registration_groundwork import _CONFIG

# Reuse the existing bounded publication seam, not a second publication framework.
_STARTUP = """
import sys
from pytest import MonkeyPatch
from dnsid import (LoadedConfig, construct_identity_manager, load_file,
                   load_environment, merge_loaded_config)
from dnsid._crypto import verify_signature
from tests.conftest import local_publication

with MonkeyPatch.context() as patches:
    local_publication.__wrapped__(patches)
    loaded = merge_loaded_config(load_file(sys.argv[1]), load_environment())
    with construct_identity_manager(loaded) as manager:
        key = manager.key_provider.signing_key()
        payload = b"startup warning regression"
        assert verify_signature(key._raw, payload, manager.key_provider.sign(payload))
        print(key.kid)
"""


@pytest.mark.parametrize("provider", [None, "file"], ids=["default", "explicit-file"])
def test_each_fresh_start_warns_with_existing_file_keys(tmp_path, provider):
    # Given the same existing keys/config across two independent application starts.
    store = tmp_path / "keys.json"
    key = LocalKeyProvider.load(store, create_if_missing=True).signing_key()
    source = {"keyStorePath": str(store)}
    if provider is not None:
        source["provider"] = provider
    config = _write_file(tmp_path, {"keySource": source})
    before = store.read_bytes()
    home = tmp_path / "home"
    home.mkdir()
    env = {
        name: value for name, value in os.environ.items()
        if not name.startswith(("DNSID_", "AWS_", "PYTHON"))
    }
    env.update(_identity_env(), HOME=str(home))
    for _ in range(2):
        # When real load -> merge -> construct runs with native default filters.
        result = subprocess.run(  # noqa: S603 -- fixed Python program and fixture path
            [sys.executable, "-c", _STARTUP, str(config)],
            cwd=Path(__file__).resolve().parents[1],
            env=env, capture_output=True, text=True, timeout=20,
        )
        # Then startup succeeds, reuses the key, and emits actionable native stderr.
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == key.kid
        diagnostic = result.stderr.lower()
        assert "userwarning:" in diagnostic
        assert "local" in diagnostic and "unsuitable for production" in diagnostic
        assert "cloud" in diagnostic and "provider" in diagnostic
        assert store.read_bytes() == before


@pytest.mark.parametrize("provider", [None, "file"], ids=["default", "explicit-file"])
def test_injection_displaces_unreadable_file_source(tmp_path, provider, no_local_key_warning):
    """Mode: real-capable; injected operational provider, no external dependencies."""
    # Given an unreadable displaced source and an explicitly injected signer.
    key = LocalKeyProvider.generate()
    loaded = LoadedConfig(
        dnsid=_CONFIG,
        key_source=KeySource(provider=provider, key_store_path=str(tmp_path / "missing.json")),
    )
    # When constructing, then injection wins without a local-file selection warning.
    with construct_identity_manager(loaded, key_provider=key) as manager:
        assert manager.key_provider is key
