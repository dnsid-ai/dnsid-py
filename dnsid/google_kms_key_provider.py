"""Optional synchronous Google Cloud KMS Ed25519 signing support.

Credentials use Google's ambient credential chain. Opening a version only reads
its public key; it never creates or replaces cloud keys. Service exceptions pass
through unchanged, without logging payloads or credential material.
"""

from __future__ import annotations

import re
import threading
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._crypto import jwk_from_dict
from ._utils import b64url_encode
from .config_loading import KeySource
from .exceptions import ArgumentError, NoActiveSigningKeyError
from .interfaces import KeyProvider
from .models import JWK

__all__ = ["GoogleKmsKeyProvider", "validate_config", "key_provider_from_config"]

_VERSION = re.compile(
    r"projects/[^/\s#]+/locations/[^/\s#]+/keyRings/[^/\s#]+/"
    r"cryptoKeys/[^/\s#]+/cryptoKeyVersions/[1-9][0-9]*"
)


def _validate_version(name: str) -> None:
    if not isinstance(name, str) or _VERSION.fullmatch(name) is None:
        raise ArgumentError("google-kms requires a fully qualified immutable CryptoKeyVersion name")


def validate_config(source: KeySource) -> None:
    """Validate existing-version selection without credentials or service calls."""
    if source.provider != "google-kms":
        raise ArgumentError("expected google-kms provider")
    _validate_version(source.key_ref or "")
    settings = source.settings or {}
    if set(settings) - {"algorithm"} or settings.get("algorithm", "EdDSA") != "EdDSA":
        raise ArgumentError("google-kms supports only algorithm EdDSA and no credential settings")


def key_provider_from_config(source: KeySource) -> GoogleKmsKeyProvider:
    """Open the selected existing version with the official synchronous client."""
    from google.cloud import kms_v1

    validate_config(source)
    return GoogleKmsKeyProvider(kms_v1.KeyManagementServiceClient(), source.key_ref or "")


class GoogleKmsKeyProvider(KeyProvider):
    """Sign raw data using an immutable software EC_SIGN_ED25519 version.

    Public key IDs are RFC 7638 thumbprints, never cloud resource names.
    Generation leaves keys pending until explicit activation. Supersession is
    local only and never retires a cloud version. State is process-local;
    application-owned rotation persistence and recovery remain outside this
    provider. Reopening a version explicitly selects it as the initial signer.
    """

    def __init__(self, client: Any, key_version_name: str) -> None:
        """Read and validate an existing version through a synchronous KMS client."""
        _validate_version(key_version_name)
        self._client = client
        self._parent = key_version_name.rsplit("/cryptoKeyVersions/", 1)[0]
        self._lock = threading.RLock()
        key = self._read_public_key(key_version_name)
        self._keys = {key["kid"]: key}
        self._versions = {key["kid"]: key_version_name}
        self._pending: set[str] = set()
        self._retained: set[str] = set()
        self._active: str | None = key["kid"]

    def _read_public_key(self, key_version_name: str) -> dict[str, str]:
        import google_crc32c
        from google.cloud import kms_v1

        response = self._client.get_public_key(request={"name": key_version_name})
        if response.name != key_version_name:
            raise ArgumentError("google-kms public response version mismatch")
        if response.algorithm != kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519:
            raise ArgumentError("google-kms requires EC_SIGN_ED25519")
        if response.protection_level != kms_v1.ProtectionLevel.SOFTWARE:
            raise ArgumentError("google-kms requires SOFTWARE protection")
        pem = response.pem.encode("utf-8")
        if response.pem_crc32c != google_crc32c.value(pem):
            raise ArgumentError("google-kms public key CRC32C mismatch")
        try:
            public = serialization.load_pem_public_key(pem)
        except (ValueError, TypeError):
            raise ArgumentError("google-kms returned invalid public SPKI") from None
        if not isinstance(public, Ed25519PublicKey):
            raise ArgumentError("google-kms public key is not Ed25519")
        raw = {
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
            "x": b64url_encode(public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )),
        }
        raw["kid"] = jwk_from_dict(raw).thumbprint()
        return raw

    def signing_key(self) -> JWK:
        """Return the active public JWK, or fail locally when none is active."""
        with self._lock:
            if self._active is None:
                raise NoActiveSigningKeyError("google-kms has no active signing key")
            return self.jwk(self._active)

    def jwk(self, kid: str) -> JWK:
        """Return a public JWK by thumbprint, including pending and archived keys."""
        with self._lock:
            if kid not in self._keys:
                raise ArgumentError("google-kms unknown key ID")
            return jwk_from_dict(dict(self._keys[kid]))

    def list_key_ids(self) -> list[str]:
        """Return only the current signing key ID, excluding pending and old keys."""
        with self._lock:
            return [self._active] if self._active is not None else []

    def generation_algorithm(self) -> str:
        """Return the fixed JOSE generation algorithm without cloud access."""
        return "EdDSA"

    def generate_key(self) -> str:
        """Create a pending Ed25519 version under the originally configured parent.

        Creation uses the parent's version template. Both the creation response
        and public key must confirm software Ed25519 before local registration.
        Failure after creation never promotes a key or retries by creating another.
        """
        from google.cloud import kms_v1

        with self._lock:
            response = self._client.create_crypto_key_version(request={"parent": self._parent})
            name = response.name
            _validate_version(name)
            if name.rsplit("/cryptoKeyVersions/", 1)[0] != self._parent:
                raise ArgumentError("google-kms created version parent mismatch")
            if name in self._versions.values():
                raise ArgumentError("google-kms created version is already known")
            if (
                response.algorithm
                != kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519
                or response.protection_level != kms_v1.ProtectionLevel.SOFTWARE
                or response.state != kms_v1.CryptoKeyVersion.CryptoKeyVersionState.ENABLED
            ):
                raise ArgumentError("google-kms created version must be enabled software Ed25519")
            key = self._read_public_key(name)
            kid = key["kid"]
            if kid in self._keys:
                raise ArgumentError("google-kms public key is already bound to another version")
            self._keys[kid] = key
            self._versions[kid] = name
            self._pending.add(kid)
            return kid

    def activate(self, kid: str) -> None:
        """Promote only a pending key; previous keys immediately lose signing eligibility."""
        with self._lock:
            if kid not in self._pending:
                raise ArgumentError("google-kms activation requires a pending key")
            if self._active is not None:
                self._retained.add(self._active)
            self._pending.remove(kid)
            self._active = kid

    def supersede(self, kid: str, *, allow_active: bool = False) -> None:
        """Locally retire an active or retained key without any cloud mutation.

        ``allow_active`` is reserved for an accepted, publicly verified
        cross-provider rotation. Explicit active supersession leaves no signer;
        it never activates a replacement implicitly.

        Raises:
            ArgumentError: If *kid* is active without ``allow_active=True``,
                or is not an active or retained key.
        """
        with self._lock:
            if kid == self._active:
                if not allow_active:
                    raise ArgumentError(
                        "cannot supersede the active key; activate a replacement first"
                    )
                self._active = None
            elif kid in self._retained:
                self._retained.remove(kid)
            else:
                raise ArgumentError("google-kms supersession requires an active or retained key")

    def sign(self, payload: bytes) -> bytes:
        """Sign with the active version; no active signer fails before cloud access."""
        with self._lock:
            if self._active is None:
                raise NoActiveSigningKeyError("google-kms has no active signing key")
            return self.sign_key(self._active, payload)

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        """Sign only with an active or pending key, checking version and CRC32C binding."""
        import google_crc32c

        with self._lock:
            if kid != self._active and kid not in self._pending:
                raise ArgumentError("google-kms signing requires an active or pending key")
            version = self._versions[kid]
            response = self._client.asymmetric_sign(request={
                "name": version, "data": payload,
                "data_crc32c": google_crc32c.value(payload),
            })
            signature = bytes(response.signature)
            if response.name != version:
                raise ArgumentError("google-kms signing response version mismatch")
            if response.verified_data_crc32c is not True:
                raise ArgumentError("google-kms did not verify data CRC32C")
            if len(signature) != 64 or response.signature_crc32c != google_crc32c.value(signature):
                raise ArgumentError("google-kms signature integrity failure")
            return signature
