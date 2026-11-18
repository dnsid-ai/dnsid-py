"""Owner-only, atomic recovery documents with deadline-bounded process locks.

Back up the whole directory and the independent key-provider state. Container-local
files do not provide recovery after a container or volume is lost. Recovery files
contain public bindings only; they cannot recreate private keys.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any, Protocol

from .._utils import normalize_fqdn
from .._verification_budget import BudgetExhausted, remaining_seconds
from ..c2sp_tlog.canonical import canonical_bytes, parse_json_no_duplicate_members
from ..models import JWK
from .errors import FoundryBusy, FoundryStateError

OperationKey = tuple[str, str, str]
_PHASES = {
    "creation-pending",
    "identity-known",
    "proof-pending",
    "issuance-accepted",
    "complete",
}


def validate_name(name: str) -> str:
    """Validate exact Unicode scalar values without changing the input."""
    from ..exceptions import ArgumentError

    if (
        not isinstance(name, str)
        or not name
        or len(name) > 255
        or any(0xD800 <= ord(c) <= 0xDFFF for c in name)
    ):
        raise ArgumentError("registration name must contain 1 to 255 Unicode scalar values")
    return name


def registration_key(organization_id: str, name: str, initial_key_id: str) -> str:
    """Derive the cross-binding named registration replay key."""
    return _digest(
        [
            "dnsid-managed-registration-v1",
            organization_id,
            validate_name(name),
            initial_key_id,
        ]
    )


def issuance_key(registration: str) -> str:
    """Derive the one issuance key from the original registration key."""
    return _digest(["dnsid-managed-issuance-v1", registration])


def _digest(value: Any) -> str:
    from .._utils import b64url_encode

    return b64url_encode(hashlib.sha256(canonical_bytes(value)).digest())


def recovery_document(data: bytes) -> dict[str, Any]:
    """Import UTF-8 JSON, rejecting duplicates, bad Unicode, versions, and phases."""
    try:
        document = parse_json_no_duplicate_members(data)
        if not isinstance(document, dict):
            raise ValueError("operation must be an object")
        validate_operation(document)
        return document
    except FoundryStateError:
        raise
    except Exception as cause:
        raise FoundryStateError("invalid Foundry recovery document", cause=cause) from cause


def validate_operation(document: dict[str, Any], key: OperationKey | None = None) -> None:
    """Validate phase requirements before a write or any registry mutation."""
    try:
        canonical_bytes(document)  # Also rejects invalid Unicode in unknown members.
        if type(document.get("schemaVersion")) is not int or document["schemaVersion"] != 1:
            raise ValueError("unsupported recovery schemaVersion")
        phase = document.get("phase")
        if phase not in _PHASES:
            raise ValueError("unsupported recovery phase")
        required = (
            "registryUrl",
            "organizationId",
            "name",
            "governanceId",
            "keySource",
            "initialPublicKey",
            "creationInput",
        )
        if any(member not in document for member in required):
            raise ValueError("missing creation bindings")
        for member in ("registryUrl", "organizationId", "governanceId"):
            if not isinstance(document[member], str) or not document[member].strip():
                raise ValueError("invalid operation binding")
        validate_name(document["name"])
        if normalize_fqdn(document["governanceId"]) != document["governanceId"]:
            raise ValueError("governanceId must be normalized")
        actual = (document["registryUrl"], document["organizationId"], document["name"])
        if key is not None and actual != key:
            raise ValueError("operation key mismatch")
        from ..registry_client import _live_public_jwk_dict

        initial = JWK.from_dict(document["initialPublicKey"])
        _live_public_jwk_dict(initial)
        if "currentPublicKey" in document:
            # A verified later rotation can use another supported algorithm.
            from ..models import JWKS

            JWKS([JWK.from_dict(document["currentPublicKey"])]).validate_operational()
        if "signingPaused" in document and type(document["signingPaused"]) is not bool:
            raise ValueError("signingPaused must be boolean")
        creation = document["creationInput"]
        if not isinstance(document["keySource"], dict) or not isinstance(creation, dict):
            raise ValueError("invalid provider reference or frozen input")
        creation_key = JWK.from_dict(creation["public_key"])
        _live_public_jwk_dict(creation_key)
        if initial.thumbprint() != creation_key.thumbprint() and (
            "currentPublicKey" not in document
            or document.get("issuance", {}).get("submission", {}).get("state") != "accepted"
        ):
            raise ValueError("a different initial key requires accepted issuance and a current key")
        if creation.get("name") != document["name"] or (
            creation.get("tier") != "live"
            or creation.get("managed") is not True
            or set(creation)
            - {
                "name",
                "public_key",
                "tier",
                "managed",
                "environment",
                "capabilities_url",
            }
        ):
            raise ValueError("frozen creation input conflicts with bindings")
        expected_request = registration_key(
            document["organizationId"], document["name"], creation_key.thumbprint()
        )
        if "requestId" in document and document["requestId"] != expected_request:
            raise ValueError("requestId mismatch")
        if (
            "domain" in document
            and normalize_fqdn(
                document["domain"],
                agent_fqdn=True,
            )
            != document["domain"]
        ):
            raise ValueError("domain must be normalized")
        if phase != "creation-pending":
            if any(not document.get(f) for f in ("identityId", "domain", "requestId")):
                raise ValueError("phase requires identity facts")
        if phase == "proof-pending" and not isinstance(document.get("proof"), dict):
            raise ValueError("phase requires proof")
        if phase in {"issuance-accepted", "complete"}:
            if any(
                not document.get(f)
                for f in (
                    "publicationConfig",
                    "entityPublicKey",
                    "issuance",
                )
            ):
                raise ValueError("phase requires issuance and publication bindings")
            issuance = document["issuance"]
            if issuance.get("submission", {}).get("state") != "accepted":
                raise ValueError("phase requires accepted issuance")

        if "issuance" in document:
            from ..c2sp_tlog.managed_issuance import _validate
            from ._issuance import decode_issuance

            state = decode_issuance(document["issuance"], document["domain"])
            if state.idempotency_key != issuance_key(expected_request) or (
                state.governance_id != document["governanceId"]
                or state.operational_public_key.thumbprint() != initial.thumbprint()
            ):
                raise ValueError("issuance conflicts with creation bindings")
            _validate(
                state,
                JWK.from_dict(document["entityPublicKey"]),
                document["publicationConfig"]["logRef"],
            )
            if phase == "complete" and (not state.complete or state.activation_blocked):
                raise ValueError("completion phase conflicts with issuance convergence")

        # Recovery documents must not carry private JWK material, even in extensions.
        def public_only(value: Any) -> None:
            if isinstance(value, dict):
                if "kty" in value and any(
                    k in value
                    for k in (
                        "d",
                        "p",
                        "q",
                        "dp",
                        "dq",
                        "qi",
                        "k",
                        "oth",
                    )
                ):
                    raise ValueError("recovery document contains private key material")
                for item in value.values():
                    public_only(item)
            elif isinstance(value, list):
                for item in value:
                    public_only(item)

        public_only(document)
    except Exception as cause:
        raise FoundryStateError("conflicting or corrupt Foundry state", cause=cause) from cause


class FoundryStore(Protocol):
    """Named durable operations; each call holds one exclusive lock."""

    def lock(self, key: OperationKey) -> AbstractContextManager[None]:
        """Wait for exclusive in-process and cross-process ownership."""
        ...

    def load(self, key: OperationKey) -> dict[str, Any] | None:
        """Load and validate an operation under its lock."""
        ...

    def save(self, key: OperationKey, document: dict[str, Any]) -> None:
        """Atomically and durably update an operation under its lock."""
        ...

    def export_operation(self, key: OperationKey) -> bytes:
        """Export the locked operation as UTF-8 RFC 8785 JSON."""
        ...

    def import_operation(self, data: bytes) -> OperationKey:
        """Validate and import a document without replacing conflicting state."""
        ...

    def load_by_id(self, identity_id: str) -> dict[str, Any] | None:
        """Load a retained historical operation by its immutable identity ID."""
        ...


class FileFoundryStore:
    """Recovery files under ``~/.dnsid/foundry/`` unless a directory is supplied."""

    def __init__(self, directory: str | Path | None = None) -> None:
        """Select storage without reading or creating it yet."""
        self.directory = (
            Path(directory) if directory is not None else Path.home() / ".dnsid/foundry"
        )
        self._ownership = threading.local()

    def _path(self, key: OperationKey) -> Path:
        return self.directory / (_digest(list(key)) + ".json")

    def _owned(self, key: OperationKey) -> None:
        if getattr(self._ownership, "key", None) != key:
            raise FoundryStateError("Foundry writes and reads require the operation lock")
        remaining_seconds()

    @contextmanager
    def lock(self, key: OperationKey) -> Iterator[None]:
        """Hold a stable sidecar lock across atomic replacement of the document."""
        remaining_seconds()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _private(self.directory, directory=True)
        path = self._path(key).with_suffix(".lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        acquired = False
        try:
            _private(path)
            if sys.platform == "win32":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
            while not acquired:
                try:
                    if sys.platform == "win32":
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    remaining_seconds()
                except OSError as cause:
                    if cause.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise
                    try:
                        time.sleep(remaining_seconds(0.025))
                    except BudgetExhausted as expired:
                        raise FoundryBusy(
                            "another caller owns this Foundry operation",
                            resumable=True,
                        ) from expired
            self._ownership.key = key
            yield
        finally:
            self._ownership.key = None
            if acquired:
                if sys.platform == "win32":
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def load(self, key: OperationKey) -> dict[str, Any] | None:
        """Read and validate the locked named operation."""
        self._owned(key)
        path = self._path(key)
        if not path.exists():
            if path.is_symlink():
                raise FoundryStateError("recovery document is a dangling symlink")
            return None
        _private(path)
        document = recovery_document(path.read_bytes())
        validate_operation(document, key)
        return document

    def save(self, key: OperationKey, document: dict[str, Any]) -> None:
        """Fsync an owner-only temporary file, replace, and sync its directory."""
        self._owned(key)
        validate_operation(document, key)
        previous = self.load(key)
        if previous is not None:
            for member in ("creationInput", "identityId", "domain"):
                if member in previous and previous[member] != document.get(member):
                    raise FoundryStateError("cannot replace established operation facts")
            if previous["initialPublicKey"] != document["initialPublicKey"] and (
                previous.get("issuance", {}).get("submission", {}).get("state") == "accepted"
                or document.get("issuance", {}).get("submission", {}).get("state") != "accepted"
            ):
                raise FoundryStateError("initial key can change only when recovering issuance")
        descriptor, name = tempfile.mkstemp(prefix=".foundry-", dir=self.directory)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical_bytes(document))
                stream.flush()
                os.fsync(stream.fileno())
            self._owned(key)
            os.replace(temporary, self._path(key))
            if os.name != "nt":
                descriptor = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def export_operation(self, key: OperationKey) -> bytes:
        """Export the locked operation as UTF-8 RFC 8785 JSON."""
        document = self.load(key)
        if document is None:
            raise FoundryStateError("no saved operation to export")
        return canonical_bytes(document)

    def import_operation(self, data: bytes) -> OperationKey:
        """Import under the destination lock; never overwrite conflicting state."""
        document = recovery_document(data)
        key = (document["registryUrl"], document["organizationId"], document["name"])
        with self.lock(key):
            existing = self.load(key)
            if existing is not None and existing != document:
                raise FoundryStateError("import conflicts with an existing operation")
            self.save(key, document)
        return key

    def load_by_id(self, identity_id: str) -> dict[str, Any] | None:
        """Address retained historical operations by ID without changing named state."""
        for path in self.directory.glob("*.json"):
            _private(path)
            candidate = recovery_document(path.read_bytes())
            if candidate.get("identityId") == identity_id:
                key = (candidate["registryUrl"], candidate["organizationId"], candidate["name"])
                with self.lock(key):
                    return self.load(key)
        return None


def _private(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or (
        os.name != "nt" and (info.st_mode & 0o077 or info.st_uid != os.getuid())
    ):
        raise FoundryStateError("Foundry storage must be owner-only, without symlinks")
