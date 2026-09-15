"""AWS KMS-backed KeyProvider."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

from ._crypto import jwk_from_dict
from ._utils import b64url_encode
from .exceptions import ArgumentError
from .interfaces import KeyProvider
from .models import JWK

AwsKmsSigningAlgorithm = Literal["ECDSA_SHA_256", "ED25519_SHA_512"]
AwsKmsKeySpec = Literal["ECC_NIST_P256", "ECC_NIST_EDWARDS25519"]

_AWS_KMS_RAW_SIGN_LIMIT_BYTES = 4096


# ---------------------------------------------------------------------------
# State and config
# ---------------------------------------------------------------------------


@dataclass
class AwsKmsKeyState:
    """Mutable lifecycle state for AwsKmsKeyProvider.

    Persist the return value of ``state_snapshot()`` after ``generate_key()``,
    ``activate()``, or ``supersede()``; pass it back in as ``config.state`` on
    the next process start.
    """

    active_key_id: str
    retained_key_ids: list[str] = field(default_factory=list)
    pending_key_ids: list[str] = field(default_factory=list)


@dataclass
class AwsKmsConfig:
    """Configuration for AwsKmsKeyProvider."""

    algorithm: AwsKmsSigningAlgorithm
    """KMS signing algorithm — must match the key spec."""

    active_key_id: str = ""
    """ARN, key ID, alias, or alias ARN of the current signing key.
    Ignored when ``state`` is supplied."""

    retained_key_ids: list[str] = field(default_factory=list)
    """KMS key IDs retained for signature verification. Ignored when ``state`` is supplied."""

    pending_key_ids: list[str] = field(default_factory=list)
    """KMS key IDs generated but not yet activated. Ignored when ``state`` is supplied."""

    state: AwsKmsKeyState | None = None
    """Preferred mutable state object. Takes precedence over top-level key ID fields."""

    key_spec: AwsKmsKeySpec | None = None
    """Key spec for new keys created by ``generate_key()``. Defaults from ``algorithm``."""

    description: str | None = None
    """Description passed to KMS when ``generate_key()`` creates a new key."""

    tags: dict[str, str] | None = None
    """Tags passed to KMS when ``generate_key()`` creates a new key."""

    schedule_key_deletion_on_supersede: bool = False
    """Call ``ScheduleKeyDeletion`` when a retained key is superseded."""

    deletion_window_in_days: int = 30
    """Waiting period for ``ScheduleKeyDeletion``. AWS allows 7–30 days."""


# ---------------------------------------------------------------------------
# Facade (narrow, mockable KMS interface)
# ---------------------------------------------------------------------------


class AwsKmsFacade(ABC):
    """Narrow, mockable interface over an AWS KMS client.

    Implement this to inject a test double; use ``BotoKmsFacade`` for production.
    """

    @abstractmethod
    def create_signing_key(
        self,
        key_spec: AwsKmsKeySpec,
        description: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> str:
        """Create a new SIGN_VERIFY key. Returns the key ARN."""

    @abstractmethod
    def get_public_key(self, key_id: str) -> dict[str, Any]:
        """Fetch public key info for *key_id*.

        Returns a dict with keys:
          ``key_id`` (str | None), ``public_key`` (bytes), ``key_spec`` (str | None),
          ``key_usage`` (str | None), ``signing_algorithms`` (list[str] | None).
        """

    @abstractmethod
    def sign(
        self,
        key_id: str,
        message: bytes,
        signing_algorithm: AwsKmsSigningAlgorithm,
        message_type: Literal["RAW", "DIGEST"],
    ) -> dict[str, Any]:
        """Sign *message* with *key_id*.

        Returns a dict with keys:
          ``key_id`` (str | None), ``signature`` (bytes), ``signing_algorithm`` (str | None).
        """

    def schedule_key_deletion(self, key_id: str, pending_window_in_days: int) -> None:
        """Schedule deletion of *key_id* after a waiting period.

        Optional; only required when ``schedule_key_deletion_on_supersede`` is
        ``True``.  Raises NotImplementedError when the facade does not support
        key deletion.
        """
        raise NotImplementedError(
            "This AwsKmsFacade does not implement schedule_key_deletion; "
            "set schedule_key_deletion_on_supersede=False or use BotoKmsFacade"
        )


# ---------------------------------------------------------------------------
# BotoKmsFacade — production adapter wrapping a boto3 KMS client
# ---------------------------------------------------------------------------


class BotoKmsFacade(AwsKmsFacade):
    """Adapter wrapping a ``boto3`` KMS client.

    Usage::

        import boto3
        from dnsid import AwsKmsKeyProvider, AwsKmsConfig, BotoKmsFacade

        facade = BotoKmsFacade(boto3.client("kms", region_name="us-east-1"))
        provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(
            active_key_id="alias/dnsid-current",
            algorithm="ECDSA_SHA_256",
        ))
    """

    def __init__(self, client: Any) -> None:
        """Wrap a ``boto3`` KMS client.

        Args:
            client: A ``boto3`` KMS client, e.g. ``boto3.client("kms")``.
        """
        self._client = client

    def create_signing_key(
        self,
        key_spec: AwsKmsKeySpec,
        description: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> str:
        """Create a new SIGN_VERIFY key via KMS ``CreateKey``.

        Returns:
            The new key ARN.

        Raises:
            ArgumentError: If the KMS response includes no key ARN or key ID.
        """
        kwargs: dict[str, Any] = {"KeyUsage": "SIGN_VERIFY", "KeySpec": key_spec}
        if description is not None:
            kwargs["Description"] = description
        if tags:
            kwargs["Tags"] = [{"TagKey": k, "TagValue": v} for k, v in tags.items()]
        response = self._client.create_key(**kwargs)
        metadata = response.get("KeyMetadata", {})
        key_id = metadata.get("Arn") or metadata.get("KeyId")
        if not key_id:
            raise ArgumentError(
                "AWS KMS CreateKey response did not include KeyMetadata.Arn or KeyMetadata.KeyId"
            )
        return str(key_id)

    def get_public_key(self, key_id: str) -> dict[str, Any]:
        """Fetch public key info for *key_id* via KMS ``GetPublicKey``.

        Returns:
            A dict with keys ``key_id``, ``public_key``, ``key_spec``,
            ``key_usage``, and ``signing_algorithms``.

        Raises:
            ArgumentError: If the KMS response includes no public key bytes.
        """
        response = self._client.get_public_key(KeyId=key_id)
        pub = response.get("PublicKey")
        if not pub:
            raise ArgumentError(
                f"AWS KMS GetPublicKey response did not include PublicKey for {key_id}"
            )
        return {
            "key_id": response.get("KeyId"),
            "public_key": bytes(pub),
            "key_spec": response.get("KeySpec"),
            "key_usage": response.get("KeyUsage"),
            "signing_algorithms": response.get("SigningAlgorithms"),
        }

    def sign(
        self,
        key_id: str,
        message: bytes,
        signing_algorithm: AwsKmsSigningAlgorithm,
        message_type: Literal["RAW", "DIGEST"],
    ) -> dict[str, Any]:
        """Sign *message* with *key_id* via KMS ``Sign``.

        Returns:
            A dict with keys ``key_id``, ``signature``, and ``signing_algorithm``.

        Raises:
            ArgumentError: If the KMS response includes no signature.
        """
        response = self._client.sign(
            KeyId=key_id,
            Message=message,
            MessageType=message_type,
            SigningAlgorithm=signing_algorithm,
        )
        sig = response.get("Signature")
        if not sig:
            raise ArgumentError(f"AWS KMS Sign response did not include Signature for {key_id}")
        return {
            "key_id": response.get("KeyId"),
            "signature": bytes(sig),
            "signing_algorithm": response.get("SigningAlgorithm"),
        }

    def schedule_key_deletion(self, key_id: str, pending_window_in_days: int) -> None:
        """Schedule deletion of *key_id* via KMS ``ScheduleKeyDeletion``."""
        self._client.schedule_key_deletion(
            KeyId=key_id,
            PendingWindowInDays=pending_window_in_days,
        )


# ---------------------------------------------------------------------------
# AwsKmsKeyProvider
# ---------------------------------------------------------------------------


class AwsKmsKeyProvider(KeyProvider):
    """AWS KMS-backed DNSid KeyProvider.

    AWS KMS owns all private key material and performs signing. This provider
    manages DNSid's active/pending/retained key lifecycle, fetches public keys
    as JWKs, and routes sign() calls through KMS.

    Construct with :meth:`load` — it resolves any aliases to canonical key IDs
    before the provider is used::

        provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(
            active_key_id="alias/dnsid-current",
            algorithm="ECDSA_SHA_256",
        ))

    Persistence is the caller's responsibility: after ``generate_key()``,
    ``activate()``, or ``supersede()`` call ``state_snapshot()`` and save the result.
    """

    def __init__(self, client: AwsKmsFacade, config: AwsKmsConfig) -> None:
        """Initialize from a facade and config without resolving aliases.

        Prefer :meth:`load`, which also resolves aliases to canonical KMS key
        IDs and warms the JWK cache.

        Args:
            client: Facade over the AWS KMS client.
            config: Provider configuration and initial key lifecycle state.

        Raises:
            ArgumentError: If any configured key ID is empty or contains '#'.
        """
        self._client = client
        self._state = _state_from_config(config)
        self._algorithm: AwsKmsSigningAlgorithm = config.algorithm
        self._key_spec: AwsKmsKeySpec = config.key_spec or _default_key_spec(config.algorithm)
        self._description = config.description
        self._tags = config.tags
        self._schedule_deletion = config.schedule_key_deletion_on_supersede
        self._deletion_window = config.deletion_window_in_days
        self._jwk_cache: dict[str, JWK] = {}

        _validate_kid(self._state.active_key_id)
        for kid in self._state.retained_key_ids + self._state.pending_key_ids:
            _validate_kid(kid)

    @classmethod
    def load(cls, client: AwsKmsFacade, config: AwsKmsConfig) -> AwsKmsKeyProvider:
        """Create a provider and resolve all key IDs/aliases to canonical KMS key IDs.

        Makes a ``GetPublicKey`` call for every configured key ID to resolve aliases
        and warm the JWK cache.
        """
        provider = cls(client, config)
        provider._state.active_key_id = provider._public_jwk(provider._state.active_key_id).kid
        provider._state.retained_key_ids = [
            provider._public_jwk(kid).kid for kid in provider._state.retained_key_ids
        ]
        provider._state.pending_key_ids = [
            provider._public_jwk(kid).kid for kid in provider._state.pending_key_ids
        ]
        return provider

    def state_snapshot(self) -> AwsKmsKeyState:
        """Return a copy of the current key lifecycle state for persistence."""
        return AwsKmsKeyState(
            active_key_id=self._state.active_key_id,
            retained_key_ids=list(self._state.retained_key_ids),
            pending_key_ids=list(self._state.pending_key_ids),
        )

    # ------------------------------------------------------------------
    # KeyProvider runtime methods
    # ------------------------------------------------------------------

    def signing_key(self) -> JWK:
        """Return the public JWK of the current active signing key."""
        return self._public_jwk(self._state.active_key_id)

    def jwk(self, kid: str) -> JWK:
        """Return the public JWK for *kid*.

        Raises:
            ArgumentError: If *kid* is neither the active key nor a retained key.
        """
        if kid != self._state.active_key_id and kid not in self._state.retained_key_ids:
            raise ArgumentError(f"key not found: {kid!r}")
        return self._public_jwk(kid)

    def list_key_ids(self) -> list[str]:
        """Return the active key ID followed by all retained key IDs."""
        return [self._state.active_key_id] + list(self._state.retained_key_ids)

    def sign(self, payload: bytes) -> bytes:
        """Sign *payload* with the active KMS key.

        Uses RAW signing up to the KMS 4096-byte limit; larger ECDSA payloads
        are hashed locally and signed as a DIGEST.  ECDSA signatures are
        converted from DER to the JOSE IEEE P1363 format.

        Returns:
            Raw signature bytes in JOSE wire format.

        Raises:
            ArgumentError: If the payload exceeds the RAW limit for Ed25519,
                or the KMS response is inconsistent (missing signature,
                algorithm mismatch, or unexpected signing key).
        """
        use_digest = (
            len(payload) > _AWS_KMS_RAW_SIGN_LIMIT_BYTES and self._algorithm == "ECDSA_SHA_256"
        )
        if len(payload) > _AWS_KMS_RAW_SIGN_LIMIT_BYTES and not use_digest:
            raise ArgumentError(
                f"AWS KMS RAW signing payload exceeds {_AWS_KMS_RAW_SIGN_LIMIT_BYTES} bytes"
            )

        message = hashlib.sha256(payload).digest() if use_digest else payload
        message_type: Literal["RAW", "DIGEST"] = "DIGEST" if use_digest else "RAW"

        result = self._client.sign(
            self._state.active_key_id, message, self._algorithm, message_type
        )
        if not result["signature"]:
            raise ArgumentError("AWS KMS sign response did not include a signature")

        returned_alg = result.get("signing_algorithm")
        if returned_alg and returned_alg != self._algorithm:
            raise ArgumentError(
                f"AWS KMS signing algorithm mismatch: expected {self._algorithm}, "
                f"got {returned_alg}"
            )

        returned_key_id = result.get("key_id")
        if returned_key_id and returned_key_id != self._state.active_key_id:
            signed_kid = self._public_jwk(returned_key_id).kid
            if signed_kid != self._state.active_key_id:
                raise ArgumentError(
                    f"AWS KMS signed with unexpected key: expected {self._state.active_key_id}, "
                    f"got {returned_key_id}"
                )

        return _signature_bytes_for_jose(self._algorithm, result["signature"])

    # ------------------------------------------------------------------
    # KeyProvider management methods
    # ------------------------------------------------------------------

    def generate_key(self) -> str:
        """Generate a new KMS key in the pending state.

        Returns:
            The canonical KMS key ID of the new key.

        Raises:
            ArgumentError: If key creation succeeds but the public key cannot
                be loaded.
        """
        key_id = self._client.create_signing_key(self._key_spec, self._description, self._tags)
        if not key_id:
            raise ArgumentError("AWS KMS create key response did not include a key ID")
        try:
            kid = self._public_jwk(key_id).kid
        except Exception as e:
            raise ArgumentError(
                f"created AWS KMS key {key_id} but failed to load its public key: {e}"
            ) from e
        self._state.pending_key_ids.append(kid)
        return kid

    def activate(self, kid: str) -> None:
        """Promote *kid* from pending to active; current active moves to retained.

        Raises:
            ArgumentError: If no pending key matches *kid*.
        """
        canonical_kid = self._public_jwk(kid).kid
        if canonical_kid not in self._state.pending_key_ids:
            raise ArgumentError(f"no pending key with kid {kid!r}")
        self._state.pending_key_ids.remove(canonical_kid)
        self._state.retained_key_ids.append(self._state.active_key_id)
        self._state.active_key_id = canonical_kid

    def supersede(self, kid: str) -> None:
        """Rotate a retained key out of live use.

        Schedules KMS key deletion first when
        ``schedule_key_deletion_on_supersede`` is enabled.

        Raises:
            ArgumentError: If *kid* is the active key, is not a retained key,
                or deletion scheduling is enabled but unsupported by the facade.
        """
        if self._state.active_key_id == kid:
            raise ArgumentError("cannot supersede the active key; activate a replacement first")
        if kid not in self._state.retained_key_ids:
            raise ArgumentError(f"no retained key with kid {kid!r}")

        if self._schedule_deletion:
            try:
                self._client.schedule_key_deletion(kid, self._deletion_window)
            except NotImplementedError as e:
                raise ArgumentError(str(e)) from e

        self._state.retained_key_ids.remove(kid)
        self._jwk_cache.pop(kid, None)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _public_jwk(self, kid: str) -> JWK:
        if kid in self._jwk_cache:
            return self._jwk_cache[kid]

        result = self._client.get_public_key(kid)
        pub_bytes = result.get("public_key")
        if not pub_bytes:
            raise ArgumentError(f"AWS KMS public key response did not include PublicKey for {kid}")
        if result.get("key_usage") != "SIGN_VERIFY":
            raise ArgumentError(f"AWS KMS key {kid} is not a SIGN_VERIFY key")
        if result.get("key_spec") != self._key_spec:
            raise ArgumentError(
                f"AWS KMS key {kid} spec mismatch: expected {self._key_spec}, "
                f"got {result.get('key_spec', 'unknown')}"
            )
        signing_algs = result.get("signing_algorithms") or []
        if self._algorithm not in signing_algs:
            raise ArgumentError(f"AWS KMS key {kid} does not support {self._algorithm}")

        canonical_kid = result.get("key_id") or kid
        _validate_kid(canonical_kid)
        jwk = _spki_to_jwk(pub_bytes, self._algorithm, canonical_kid)
        self._jwk_cache[kid] = jwk
        self._jwk_cache[canonical_kid] = jwk
        return jwk


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _state_from_config(config: AwsKmsConfig) -> AwsKmsKeyState:
    if config.state is not None:
        return config.state
    if not config.active_key_id:
        raise ArgumentError("AWS KMS key provider requires an active key ID")
    return AwsKmsKeyState(
        active_key_id=config.active_key_id,
        retained_key_ids=list(config.retained_key_ids),
        pending_key_ids=list(config.pending_key_ids),
    )


def _validate_kid(kid: str) -> None:
    if not kid:
        raise ArgumentError("AWS KMS key ID must be non-empty")
    if "#" in kid:
        raise ArgumentError("AWS KMS key ID must not contain '#'")


def _default_key_spec(algorithm: AwsKmsSigningAlgorithm) -> AwsKmsKeySpec:
    if algorithm == "ECDSA_SHA_256":
        return "ECC_NIST_P256"
    return "ECC_NIST_EDWARDS25519"


def _jose_alg_for_aws(algorithm: AwsKmsSigningAlgorithm) -> str:
    if algorithm == "ECDSA_SHA_256":
        return "ES256"
    return "EdDSA"


def _spki_to_jwk(spki: bytes, algorithm: AwsKmsSigningAlgorithm, kid: str) -> JWK:
    """Parse a DER-encoded SPKI public key and return it as a JWK."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    try:
        pub_key = load_der_public_key(spki)
    except Exception as e:
        raise ArgumentError(f"failed to import AWS KMS public key for {kid}: {e}") from e

    alg = _jose_alg_for_aws(algorithm)

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        numbers = pub_key.public_numbers()
        coord_len = 32  # P-256
        raw: dict[str, Any] = {
            "kty": "EC",
            "crv": "P-256",
            "alg": alg,
            "use": "sig",
            "kid": kid,
            "x": b64url_encode(numbers.x.to_bytes(coord_len, "big")),
            "y": b64url_encode(numbers.y.to_bytes(coord_len, "big")),
        }
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        pub_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        raw = {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": alg,
            "use": "sig",
            "kid": kid,
            "x": b64url_encode(pub_bytes),
        }
    else:
        raise ArgumentError(
            f"unsupported AWS KMS public key type for {kid}: {type(pub_key).__name__}"
        )

    return jwk_from_dict(raw)


def _signature_bytes_for_jose(algorithm: AwsKmsSigningAlgorithm, signature: bytes) -> bytes:
    """Convert a KMS signature to the JOSE wire format (IEEE P1363 for ECDSA)."""
    if algorithm == "ECDSA_SHA_256":
        return _der_ecdsa_to_p1363(signature, coord_len=32)
    return signature  # Ed25519: KMS returns raw bytes directly


def _der_ecdsa_to_p1363(der: bytes, coord_len: int) -> bytes:
    """Convert a DER-encoded ECDSA signature to IEEE P1363 (r || s) format for JOSE."""
    r, s = decode_dss_signature(der)
    return r.to_bytes(coord_len, "big") + s.to_bytes(coord_len, "big")
