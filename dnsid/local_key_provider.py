"""File-backed EdDSA and ES256 KeyProvider."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ._crypto import ec_sign, ed25519_sign, jwk_from_dict
from ._utils import b64url_decode, b64url_encode
from .exceptions import ArgumentError
from .interfaces import KeyProvider
from .models import JWK

# ---------------------------------------------------------------------------
# Internal storage types
# ---------------------------------------------------------------------------


class _StoredKey:
    __slots__ = ("kty", "crv", "alg", "use", "kid", "x", "y", "d")

    def __init__(
        self,
        kty: str,
        crv: str,
        alg: str,
        use: str,
        kid: str,
        x: str,
        d: str,
        y: str = "",
    ) -> None:
        self.kty = kty
        self.crv = crv
        self.alg = alg
        self.use = use
        self.kid = kid
        self.x = x
        self.y = y
        self.d = d  # private scalar (base64url)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "kty": self.kty,
            "crv": self.crv,
            "alg": self.alg,
            "use": self.use,
            "kid": self.kid,
            "x": self.x,
            "d": self.d,
        }
        if self.y:
            result["y"] = self.y
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> _StoredKey:
        return cls(
            kty=data["kty"],
            crv=data["crv"],
            alg=data.get(
                "alg", "ES256" if (data.get("kty"), data.get("crv")) == ("EC", "P-256") else "EdDSA"
            ),
            use=data.get("use", "sig"),
            kid=data["kid"],
            x=data["x"],
            y=data.get("y", ""),
            d=data["d"],
        )

    def public_jwk(self) -> JWK:
        return jwk_from_dict(
            {
                "kty": self.kty,
                "crv": self.crv,
                "alg": self.alg,
                "use": self.use,
                "kid": self.kid,
                "x": self.x,
                **({"y": self.y} if self.y else {}),
            }
        )

    def private_key(self) -> ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey:
        private_bytes = b64url_decode(self.d)
        if self.kty == "OKP" and self.crv == "Ed25519":
            return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        if self.kty == "EC" and self.crv == "P-256":
            return ec.derive_private_key(int.from_bytes(private_bytes, "big"), ec.SECP256R1())
        raise ValueError(f"unsupported local key type: kty={self.kty!r}, crv={self.crv!r}")


class _KeyStore:
    __slots__ = ("active", "retained", "pending")

    def __init__(
        self,
        active: _StoredKey,
        retained: list[_StoredKey] | None = None,
        pending: list[_StoredKey] | None = None,
    ) -> None:
        self.active = active
        self.retained: list[_StoredKey] = retained if retained is not None else []
        self.pending: list[_StoredKey] = pending if pending is not None else []

    def to_dict(self) -> dict[str, Any]:
        return {
            "active": self.active.to_dict(),
            "retained": [k.to_dict() for k in self.retained],
            "pending": [k.to_dict() for k in self.pending],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> _KeyStore:
        return cls(
            active=_StoredKey.from_dict(data["active"]),
            retained=[_StoredKey.from_dict(k) for k in data.get("retained", [])],
            pending=[_StoredKey.from_dict(k) for k in data.get("pending", [])],
        )


@contextmanager
def _key_store_lock(path: Path) -> Iterator[None]:
    """Lock a stable sidecar, not the inode replaced by atomic writes."""
    with open(
        path.with_name(path.name + ".lock"),
        "a+b",
        opener=lambda name, flags: os.open(name, flags, 0o600),
    ) as lock:
        if sys.platform == "win32":
            import msvcrt

            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if sys.platform == "win32":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _write_key_store(path: Path, store: _KeyStore) -> None:
    """Replace a store atomically; callers hold the sidecar lock."""
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(store.to_dict(), file, indent=2)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        # ponytail: Windows syncs the file only; native durability APIs if required.
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def _stored_key_from_private(
    private: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
    kid: str,
) -> _StoredKey:
    if isinstance(private, ed25519.Ed25519PrivateKey):
        public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        secret_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return _StoredKey(
            kty="OKP",
            crv="Ed25519",
            alg="EdDSA",
            use="sig",
            kid=kid,
            x=b64url_encode(public_bytes),
            d=b64url_encode(secret_bytes),
        )
    if isinstance(private, ec.EllipticCurvePrivateKey) and isinstance(
        private.curve, ec.SECP256R1
    ):
        public_numbers = private.public_key().public_numbers()
        secret_value = private.private_numbers().private_value
        return _StoredKey(
            kty="EC",
            crv="P-256",
            alg="ES256",
            use="sig",
            kid=kid,
            x=b64url_encode(public_numbers.x.to_bytes(32, "big")),
            y=b64url_encode(public_numbers.y.to_bytes(32, "big")),
            d=b64url_encode(secret_value.to_bytes(32, "big")),
        )
    raise ValueError("local keys must use Ed25519 or P-256")


def _validate_and_normalize_private_jwk(data: dict[str, object], jwk_path: Path) -> _StoredKey:
    """Validate an Ed25519 or P-256 private JWK."""
    from ._crypto import compute_thumbprint

    kty_crv = (data.get("kty"), data.get("crv"))
    required = ("x", "d") if kty_crv == ("OKP", "Ed25519") else ("x", "y", "d")
    if kty_crv not in {("OKP", "Ed25519"), ("EC", "P-256")} or not all(
        isinstance(data.get(name), str) for name in required
    ):
        raise ValueError(
            f"{jwk_path} must include Ed25519 private key material "
            "(kty='OKP', crv='Ed25519', x, d) or P-256 private key material "
            "(kty='EC', crv='P-256', x, y, d)"
        )

    try:
        private_bytes = b64url_decode(str(data["d"]))
        if kty_crv == ("OKP", "Ed25519"):
            private: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey = (
                ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            )
        else:
            private = ec.derive_private_key(
                int.from_bytes(private_bytes, "big"), ec.SECP256R1()
            )
        normalized = _stored_key_from_private(private, "")
    except Exception as exc:
        key_name = "Ed25519" if kty_crv == ("OKP", "Ed25519") else "P-256"
        raise ValueError(f"cannot load {key_name} private key from {jwk_path}: {exc}") from exc

    if data["x"] != normalized.x or data.get("y", "") != normalized.y:
        raise ValueError(f"{jwk_path} has mismatched Ed25519 or P-256 public/private key material")

    public = normalized.public_jwk()._raw
    kid_val = data.get("kid")
    normalized.kid = (
        str(kid_val)
        if isinstance(kid_val, str) and kid_val
        else compute_thumbprint(public)
    )
    return normalized


def _generate_stored_key(algorithm: str = "EdDSA") -> _StoredKey:
    if algorithm == "EdDSA":
        private: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey = (
            ed25519.Ed25519PrivateKey.generate()
        )
    elif algorithm == "ES256":
        private = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ArgumentError(f"unsupported local key algorithm: {algorithm!r}")
    # The kid is the RFC 7638 thumbprint, as the Go SDK does: the registry
    # refuses a public key whose kid is anything else ("kid does not match
    # computed thumbprint"), and published JWKS are verified the same way.
    from ._crypto import compute_thumbprint

    stored = _stored_key_from_private(private, "")
    stored.kid = compute_thumbprint(stored.public_jwk()._raw)
    return stored


def _sign_stored_key(key: _StoredKey, payload: bytes) -> bytes:
    private = key.private_key()
    if isinstance(private, ed25519.Ed25519PrivateKey):
        return ed25519_sign(private, payload)
    return ec_sign(private, "ES256", payload)


# ---------------------------------------------------------------------------
# LocalKeyProvider
# ---------------------------------------------------------------------------


class LocalKeyProvider(KeyProvider):
    """File-backed EdDSA or ES256 KeyProvider with key lifecycle management.

    The key store is a JSON file with the shape::

        {
          "active":   { ...JWK with "d" field... },
          "retained": [ ... ],
          "pending":  [ ... ]
        }

    If the file does not exist it is created with a freshly generated key.
    If the file contains the old flat-JWK format (no "active" key) it is
    automatically migrated to the new format.

    File-backed lifecycle mutations reload and update the store under a stable
    ``.lock`` sidecar; do not delete that sidecar while providers are running.
    Writes use private temporary files and atomic replacement. POSIX writes sync
    both file and directory; Windows syncs the file but has no directory barrier.
    Use a local filesystem with working advisory locks and atomic replacement.
    Existing current-format stores can be loaded read-only without a sidecar.
    Creation, migration, and mutations require a writable directory and lock.
    All writers must use this locking protocol.

    Signing reads an in-memory snapshot. After another provider rotates keys,
    reload this provider before signing; coordinate rotation/pause hooks across
    all signers. On a persistence error, reload and reconcile before retrying:
    replacement may have succeeded even if the final durability barrier failed.

    For ephemeral use (demos, tests) call ``LocalKeyProvider.generate()`` — it
    keeps the key in memory only and never touches the filesystem.
    """

    def __init__(self, store: _KeyStore, file_path: Path | None) -> None:
        """Initialize from an in-memory key store.

        Prefer the factory methods (:meth:`load`,
        :meth:`from_cli_directory`, :meth:`from_domain`, :meth:`generate`).

        Args:
            store: Parsed key store holding the active/retained/pending keys.
            file_path: JSON file to persist key lifecycle changes to, or
                ``None`` for an in-memory (non-persisted) provider.
        """
        self._store = store
        self._file_path = file_path
        self._mutation_lock = threading.Lock()

    # ---- Factory methods ----

    @classmethod
    def load(
        cls,
        path: Path | str,
        create_if_missing: bool = False,
        algorithm: str = "EdDSA",
    ) -> LocalKeyProvider:
        """Load from *path*.

        Args:
            path: Path to the JSON key-store file.
            create_if_missing: When ``True``, create and persist a fresh key store
                if the file does not exist. When ``False`` (default), raise
                :exc:`FileNotFoundError` if the file is absent.
            algorithm: Algorithm for a newly created store: ``EdDSA`` (default)
                or ``ES256``. Ignored when loading an existing store.
        """
        p = Path(path).resolve()
        try:
            data = json.loads(p.read_text())
        except FileNotFoundError:
            if not create_if_missing:
                raise
        else:
            # Atomic replacement gives readers a complete in-memory snapshot.
            if "active" in data:
                return cls(_KeyStore.from_dict(data), p)
        # Creation and migration must re-read under the lock before writing.
        if create_if_missing:
            p.parent.mkdir(parents=True, exist_ok=True)
        with _key_store_lock(p):
            if p.exists():
                data = json.loads(p.read_text())
                # Auto-migrate without truncating the only copy of the old key.
                needs_rewrite = "active" not in data and "d" in data
                if needs_rewrite:
                    data = {"active": data, "retained": [], "pending": []}
                store = _KeyStore.from_dict(data)
                if needs_rewrite:
                    _write_key_store(p, store)
            elif create_if_missing:
                store = _KeyStore(active=_generate_stored_key(algorithm))
                _write_key_store(p, store)
                print(f"generated new key → {p}", file=sys.stderr)
            else:
                raise FileNotFoundError(f"key store not found: {p}")
        return cls(store, p)

    @classmethod
    def from_cli_directory(cls, key_directory: Path | str) -> LocalKeyProvider:
        """Load from a DNSid CLI identity directory.

        Tries ``private.jwk`` first (preferred), then falls back to
        ``private.pem`` (PKCS#8 PEM).  The loaded key becomes the sole active
        key; no retained or pending keys are present.

        This is a read-only view — :meth:`generate_key`, :meth:`activate`, and
        :meth:`supersede` work in memory but are not persisted because the source
        files use the CLI's single-key format rather than the SDK key store
        format.

        Args:
            key_directory: Directory written by the DNSid CLI (e.g.
                ``~/.dnsid/<domain>``).  Usually obtained from
                :attr:`CliConfigResult.key_directory`.

        Raises:
            FileNotFoundError: If neither ``private.jwk`` nor ``private.pem``
                exists in *key_directory*.
            ValueError: If the key file cannot be parsed or does not contain
                valid Ed25519 or P-256 private key material.
        """
        d = Path(key_directory)

        jwk_path = d / "private.jwk"
        if jwk_path.exists():
            return cls.from_private_jwk(jwk_path)

        pem_path = d / "private.pem"
        if pem_path.exists():
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            try:
                private = load_pem_private_key(pem_path.read_bytes(), password=None)
            except Exception as exc:
                raise ValueError(f"failed to parse {pem_path}: {exc}") from exc
            if not isinstance(private, (ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
                raise ValueError(f"{pem_path} must contain an Ed25519 or P-256 private key")
            try:
                stored = _stored_key_from_private(private, "")
            except ValueError as exc:
                raise ValueError(
                    f"{pem_path} must contain an Ed25519 or P-256 private key"
                ) from exc
            from ._crypto import compute_thumbprint

            stored.kid = compute_thumbprint(stored.public_jwk()._raw)
            return cls(_KeyStore(active=stored), file_path=None)

        raise FileNotFoundError(f"no key file found in {d}: expected private.jwk or private.pem")

    @classmethod
    def from_private_jwk(cls, path: Path | str) -> LocalKeyProvider:
        """Load a read-only provider from one CLI-style private JWK file."""
        jwk_path = Path(path)
        try:
            raw = json.loads(jwk_path.read_text())
        except FileNotFoundError:
            raise FileNotFoundError(f"private JWK not found: {jwk_path}") from None
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {jwk_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"{jwk_path} must contain a JSON object, got {type(raw).__name__}")
        stored = _validate_and_normalize_private_jwk(raw, jwk_path)
        return cls(_KeyStore(active=stored), file_path=None)

    @classmethod
    def from_domain(
        cls,
        domain: str,
        dnsid_dir: Path | str | None = None,
    ) -> LocalKeyProvider:
        """Load from a DNSid CLI root directory for the given domain.

        Convenience wrapper around :meth:`from_cli_directory` that constructs
        the identity key path from the domain name, defaulting to
        ``~/.dnsid/<normalized-domain>``.

        Args:
            domain: Agent FQDN (trailing dot and casing are normalised).
            dnsid_dir: Root DNSid directory. Defaults to ``~/.dnsid``.

        Raises:
            FileNotFoundError: If neither ``private.jwk`` nor ``private.pem``
                exists in the identity directory.
            ValueError: If the key file cannot be parsed.
        """
        from ._utils import normalize_fqdn

        base = Path(dnsid_dir) if dnsid_dir is not None else Path.home() / ".dnsid"
        normalized = normalize_fqdn(domain, agent_fqdn=True)
        return cls.from_cli_directory(base / normalized)

    @classmethod
    def generate(cls, algorithm: str = "EdDSA") -> LocalKeyProvider:
        """Return an ephemeral in-memory provider using EdDSA or ES256."""
        return cls(_KeyStore(active=_generate_stored_key(algorithm)), file_path=None)

    # ---- KeyProvider runtime methods ----

    def signing_key(self) -> JWK:
        """Return the public JWK of the current active signing key."""
        return self._store.active.public_jwk()

    def jwk(self, kid: str) -> JWK:
        """Return the public JWK for *kid* (active, retained, or pending).

        Raises:
            ArgumentError: If *kid* is not found.
        """
        if self._store.active.kid == kid:
            return self._store.active.public_jwk()
        for k in self._store.retained:
            if k.kid == kid:
                return k.public_jwk()
        for k in self._store.pending:
            if k.kid == kid:
                return k.public_jwk()
        raise ArgumentError(f"key not found: {kid!r}")

    def list_key_ids(self) -> list[str]:
        """Return the active key ID followed by all retained key IDs."""
        return [self._store.active.kid] + [k.kid for k in self._store.retained]

    def sign(self, payload: bytes) -> bytes:
        """Sign *payload* with the current active key in JOSE wire format."""
        return _sign_stored_key(self._store.active, payload)

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        """Sign *payload* with a specified active or pending key.

        Raises:
            ArgumentError: If *kid* is neither the active key nor a pending key.
        """
        if self._store.active.kid == kid:
            return _sign_stored_key(self._store.active, payload)
        for k in self._store.pending:
            if k.kid == kid:
                return _sign_stored_key(k, payload)
        raise ArgumentError(f"key is not active or pending for signing: {kid!r}")

    # ---- KeyProvider management methods ----

    def generate_key(self) -> str:
        """Generate a pending key using the active key's algorithm.

        Persists the updated store when the provider is file-backed.

        Returns:
            The kid of the newly generated key.
        """
        with self._mutate() as store:
            key = _generate_stored_key(store.active.alg)
            store.pending.append(key)
        return key.kid

    def activate(self, kid: str) -> None:
        """Promote *kid* from pending to active; current active moves to retained.

        Persists the updated store when the provider is file-backed.

        Raises:
            ArgumentError: If no pending key matches *kid*.
        """
        with self._mutate() as store:
            idx = next((i for i, k in enumerate(store.pending) if k.kid == kid), -1)
            if idx == -1:
                raise ArgumentError(f"no pending key with kid {kid!r}")
            incoming = store.pending.pop(idx)
            store.retained.append(store.active)
            store.active = incoming

    def supersede(self, kid: str) -> None:
        """Rotate a retained key out of live use entirely.

        Persists the updated store when the provider is file-backed.

        Raises:
            ArgumentError: If *kid* is the active key or not a retained key.
        """
        with self._mutate() as store:
            if store.active.kid == kid:
                raise ArgumentError("cannot supersede the active key; activate a replacement first")
            idx = next((i for i, k in enumerate(store.retained) if k.kid == kid), -1)
            if idx == -1:
                raise ArgumentError(f"no retained key with kid {kid!r}")
            store.retained.pop(idx)

    # ---- private ----

    @contextmanager
    def _mutate(self) -> Iterator[_KeyStore]:
        with self._mutation_lock:
            if self._file_path is None:
                store = _KeyStore.from_dict(self._store.to_dict())
                yield store
                self._store = store
                return
            with _key_store_lock(self._file_path):
                # Reload under the lock: another provider may have advanced the store.
                self._store = _KeyStore.from_dict(json.loads(self._file_path.read_text()))
                store = _KeyStore.from_dict(self._store.to_dict())
                yield store
                try:
                    _write_key_store(self._file_path, store)
                finally:
                    # A directory fsync can fail AFTER replace. Reflect the actual
                    # file, but still propagate the indeterminate durability error.
                    self._store = _KeyStore.from_dict(json.loads(self._file_path.read_text()))
