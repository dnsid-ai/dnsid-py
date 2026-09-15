"""Tests for LocalKeyProvider.load() create_if_missing behaviour."""

from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from dnsid import ArgumentError, LocalKeyProvider, local_key_provider
from dnsid._utils import b64url_encode


def _create_and_generate(path: str) -> tuple[str, str]:
    provider = LocalKeyProvider.load(path, create_if_missing=True)
    return provider.signing_key().kid, provider.generate_key()


class TestLocalKeyProviderLoad:
    def test_raises_when_missing_and_not_creating(self, tmp_path: Path) -> None:
        missing = tmp_path / "keys.json"
        with pytest.raises(FileNotFoundError):
            LocalKeyProvider.load(missing)

    def test_creates_store_when_requested(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        provider = LocalKeyProvider.load(path, create_if_missing=True)
        assert len(provider.list_key_ids()) == 1
        assert path.exists()

    def test_loads_existing_store(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        original = LocalKeyProvider.load(path, create_if_missing=True)
        original_kid = original.signing_key().kid

        loaded = LocalKeyProvider.load(path)
        assert loaded.signing_key().kid == original_kid

    @pytest.mark.parametrize("create_if_missing", [False, True])
    def test_existing_store_loads_without_writable_sidecar(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, create_if_missing: bool
    ) -> None:
        path = tmp_path / "keys.json"
        original = LocalKeyProvider.load(path, create_if_missing=True)
        before = path.read_bytes()
        path.with_suffix(".json.lock").unlink()

        def read_only_lock(path: Path):
            raise PermissionError("read-only key directory")

        monkeypatch.setattr(local_key_provider, "_key_store_lock", read_only_lock)
        loaded = LocalKeyProvider.load(path, create_if_missing=create_if_missing)
        assert loaded.signing_key() == original.signing_key()
        assert loaded.signing_key().verify(b"payload", loaded.sign(b"payload"))
        with pytest.raises(PermissionError, match="read-only key directory"):
            loaded.generate_key()
        assert path.read_bytes() == before
        assert loaded._store.to_dict() == original._store.to_dict()
        assert not path.with_suffix(".json.lock").exists()

    def test_create_if_missing_false_is_default(self, tmp_path: Path) -> None:
        """Explicit False and the default should both raise on missing file."""
        missing = tmp_path / "sub" / "keys.json"
        with pytest.raises(FileNotFoundError):
            LocalKeyProvider.load(missing, create_if_missing=False)

    def test_second_load_reuses_existing_key(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        first = LocalKeyProvider.load(path, create_if_missing=True)
        first_kid = first.signing_key().kid

        second = LocalKeyProvider.load(path, create_if_missing=True)
        assert second.signing_key().kid == first_kid

    def test_created_file_has_restricted_permissions(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        LocalKeyProvider.load(path, create_if_missing=True)
        mode = path.stat().st_mode
        assert stat.filemode(mode) == "-rw-------"

    def test_temporary_file_is_private_before_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "keys.json"
        real_dump = json.dump
        writes = []

        def assert_private(data, file, **kwargs):
            assert stat.S_IMODE(os.fstat(file.fileno()).st_mode) == 0o600
            writes.append(file.name)
            return real_dump(data, file, **kwargs)

        monkeypatch.setattr(local_key_provider.json, "dump", assert_private)
        previous_umask = os.umask(0)
        try:
            provider = LocalKeyProvider.load(path, create_if_missing=True)
            provider.generate_key()
        finally:
            os.umask(previous_umask)
        assert len(writes) == 2

    def test_creates_and_reloads_es256_store(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        provider = LocalKeyProvider.load(path, create_if_missing=True, algorithm="ES256")
        key = provider.signing_key()
        signature = provider.sign(b"payload")

        assert (key.kty, key.alg) == ("EC", "ES256")
        assert key._raw["crv"] == "P-256"
        assert len(signature) == 64
        assert key.verify(b"payload", signature)
        assert LocalKeyProvider.load(path).signing_key() == key

    def test_rejects_unknown_generation_algorithm(self) -> None:
        with pytest.raises(ArgumentError, match="unsupported local key algorithm"):
            LocalKeyProvider.generate("RS256")


class TestKeyStoreDurability:
    @pytest.mark.parametrize("operation", ["generate_key", "activate", "supersede"])
    @pytest.mark.parametrize("failure", ["dump", "fsync", "replace"])
    def test_failed_write_preserves_disk_and_memory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, failure: str
    ) -> None:
        path = tmp_path / "keys.json"
        provider = LocalKeyProvider.load(path, create_if_missing=True)
        old = provider.signing_key().kid
        active = provider.generate_key()
        provider.activate(active)
        pending = provider.generate_key()
        original = path.read_bytes()

        def fail(*args: object, **kwargs: object) -> None:
            raise OSError("simulated disk failure")

        target = local_key_provider.json if failure == "dump" else local_key_provider.os
        monkeypatch.setattr(target, failure, fail)
        args = {"generate_key": (), "activate": (pending,), "supersede": (old,)}
        with pytest.raises(OSError, match="simulated disk failure"):
            getattr(provider, operation)(*args[operation])
        assert path.read_bytes() == original
        assert provider.signing_key().kid == active
        assert provider.list_key_ids() == [active, old]
        assert provider.jwk(pending).kid == pending
        assert not list(tmp_path.glob(".keys.json.*"))

    def test_failed_migration_preserves_legacy_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "keys.json"
        LocalKeyProvider.load(path, create_if_missing=True)
        path.write_text(json.dumps(json.loads(path.read_text())["active"]))
        original = path.read_bytes()

        def fail(*args: object, **kwargs: object) -> None:
            raise OSError("simulated replace failure")

        with monkeypatch.context() as patch:
            patch.setattr(local_key_provider.os, "replace", fail)
            with pytest.raises(OSError, match="simulated replace failure"):
                LocalKeyProvider.load(path)
        assert path.read_bytes() == original
        assert LocalKeyProvider.load(path).signing_key().kid == json.loads(original)["kid"]

    def test_truncated_store_is_not_regenerated(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        path.write_text('{"active":')
        with pytest.raises(json.JSONDecodeError):
            LocalKeyProvider.load(path, create_if_missing=True)
        assert path.read_text() == '{"active":'

    def test_stale_providers_merge_lifecycle_changes(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        first = LocalKeyProvider.load(path, create_if_missing=True)
        second = LocalKeyProvider.load(path)
        old = first.signing_key().kid
        a = first.generate_key()
        b = second.generate_key()
        first.activate(b)
        second.supersede(old)
        loaded = LocalKeyProvider.load(path)
        assert loaded.list_key_ids() == [b]
        assert loaded.jwk(a).kid == a

    def test_threads_preserve_all_pending_keys(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        provider = LocalKeyProvider.load(path, create_if_missing=True)
        with ThreadPoolExecutor(max_workers=4) as pool:
            pending = list(pool.map(lambda _: provider.generate_key(), range(12)))
        assert {key["kid"] for key in json.loads(path.read_text())["pending"]} == set(pending)

    def test_processes_serialize_creation_and_updates(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.json"
        with ProcessPoolExecutor(max_workers=4, mp_context=get_context("spawn")) as pool:
            results = list(pool.map(_create_and_generate, [str(path)] * 12))
        assert len({active for active, _ in results}) == 1
        data = json.loads(path.read_text())
        assert {key["kid"] for key in data["pending"]} == {pending for _, pending in results}
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="POSIX directory durability barrier")
    def test_directory_sync_failure_reports_committed_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "keys.json"
        provider = LocalKeyProvider.load(path, create_if_missing=True)
        pending = provider.generate_key()
        real_sync = os.fsync

        def sync(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory sync failed")
            real_sync(fd)

        monkeypatch.setattr(local_key_provider.os, "fsync", sync)
        with pytest.raises(OSError, match="directory sync failed"):
            provider.activate(pending)
        assert provider.signing_key().kid == pending
        assert LocalKeyProvider.load(path).signing_key().kid == pending


class TestLocalKeyProviderEs256:
    def test_rotation_preserves_algorithm(self) -> None:
        provider = LocalKeyProvider.generate("ES256")
        previous = provider.signing_key().kid
        pending = provider.generate_key()

        assert provider.jwk(pending).alg == "ES256"
        assert provider.jwk(pending).verify(b"proof", provider.sign_key(pending, b"proof"))
        provider.activate(pending)
        provider.supersede(previous)
        assert provider.signing_key().kid == pending

    @pytest.mark.parametrize("key_format", ["jwk", "pem"])
    def test_loads_cli_p256_private_key(self, tmp_path: Path, key_format: str) -> None:
        private = ec.generate_private_key(ec.SECP256R1())
        if key_format == "pem":
            (tmp_path / "private.pem").write_bytes(
                private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
        else:
            public = private.public_key().public_numbers()
            value = private.private_numbers().private_value
            (tmp_path / "private.jwk").write_text(
                json.dumps(
                    {
                        "kty": "EC",
                        "crv": "P-256",
                        "alg": "ES256",
                        "x": b64url_encode(public.x.to_bytes(32, "big")),
                        "y": b64url_encode(public.y.to_bytes(32, "big")),
                        "d": b64url_encode(value.to_bytes(32, "big")),
                    }
                )
            )

        provider = LocalKeyProvider.from_cli_directory(tmp_path)
        signature = provider.sign(b"payload")
        assert provider.signing_key().alg == "ES256"
        assert provider.signing_key().verify(b"payload", signature)
