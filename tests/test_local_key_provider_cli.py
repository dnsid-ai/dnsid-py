"""Tests for LocalKeyProvider.from_cli_directory / from_domain."""

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

from dnsid import LocalKeyProvider
from dnsid._crypto import compute_thumbprint
from dnsid._utils import b64url_encode

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
