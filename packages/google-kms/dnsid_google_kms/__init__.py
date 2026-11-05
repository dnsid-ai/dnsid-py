"""Optional synchronous Google Cloud KMS Ed25519 signing support.

Credentials use Google's ambient credential chain. Opening a version only reads
its public key; it never creates or replaces cloud keys. Service exceptions pass
through unchanged, without logging payloads or credential material.
"""

from __future__ import annotations

import re
from typing import Any

import google_crc32c
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from google.cloud import kms_v1

from dnsid import ArgumentError
from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.config_loading import KeySource
from dnsid.models import JWK

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
    validate_config(source)
    return GoogleKmsKeyProvider(kms_v1.KeyManagementServiceClient(), source.key_ref or "")


class GoogleKmsKeyProvider:
    """Sign raw data using an immutable software EC_SIGN_ED25519 version.

    This runtime slice does not yet implement the KeyProvider lifecycle interface.
    Public key IDs are RFC 7638 thumbprints, never cloud resource names.
    """

    def __init__(self, client: Any, key_version_name: str) -> None:
        """Read and validate an existing version through a synchronous KMS client."""
        _validate_version(key_version_name)
        self._client = client
        self._version = key_version_name
        response = client.get_public_key(request={"name": key_version_name})
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
        self._public = public
        raw = {
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
            "x": b64url_encode(public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )),
        }
        raw["kid"] = jwk_from_dict(raw).thumbprint()
        self._key = raw

    def signing_key(self) -> JWK:
        """Return a fresh public JWK for the configured signer."""
        return jwk_from_dict(dict(self._key))

    def jwk(self, kid: str) -> JWK:
        """Return the known public key by thumbprint."""
        if kid != self._key["kid"]:
            raise ArgumentError("google-kms unknown key ID")
        return self.signing_key()

    def list_key_ids(self) -> list[str]:
        """Return only the current signing key ID."""
        return [self._key["kid"]]

    def sign(self, payload: bytes) -> bytes:
        """Sign raw data and reject unbound or corrupted KMS responses."""
        response = self._client.asymmetric_sign(request={
            "name": self._version, "data": payload,
            "data_crc32c": google_crc32c.value(payload),
        })
        signature = bytes(response.signature)
        if response.name != self._version:
            raise ArgumentError("google-kms signing response version mismatch")
        if response.verified_data_crc32c is not True:
            raise ArgumentError("google-kms did not verify data CRC32C")
        if len(signature) != 64 or response.signature_crc32c != google_crc32c.value(signature):
            raise ArgumentError("google-kms signature integrity failure")
        return signature
