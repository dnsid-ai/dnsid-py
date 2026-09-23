---
title: "Python: Key providers"
description: "Key management backends: file-backed local keys and AWS KMS."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

## `LocalKeyProvider`

```python
from dnsid import LocalKeyProvider
```

*Bases:* `KeyProvider`

File-backed EdDSA or ES256 KeyProvider with key lifecycle management.

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

### `LocalKeyProvider` constructor

```python
LocalKeyProvider(store: _KeyStore, file_path: Path | None) -> None
```

Initialize from an in-memory key store.

Prefer the factory methods (`load`,
`from_cli_directory`, `from_domain`, `generate`).

**Arguments:**

- `store` (`_KeyStore`): Parsed key store holding the active/retained/pending keys.
- `file_path` (`Path | None`): JSON file to persist key lifecycle changes to, or ``None`` for an in-memory (non-persisted) provider.

### `load`

```python
LocalKeyProvider.load(path: Path | str, create_if_missing: bool = False, algorithm: str = 'EdDSA') -> LocalKeyProvider
```

Load from *path*.

**Arguments:**

- `path` (`Path | str`): Path to the JSON key-store file.
- `create_if_missing` (`bool`): When ``True``, create and persist a fresh key store if the file does not exist. When ``False`` (default), raise `FileNotFoundError` if the file is absent. — default `False`
- `algorithm` (`str`): Algorithm for a newly created store: ``EdDSA`` (default) or ``ES256``. Ignored when loading an existing store. — default `'EdDSA'`

### `from_cli_directory`

```python
LocalKeyProvider.from_cli_directory(key_directory: Path | str) -> LocalKeyProvider
```

Load from a DNSid CLI identity directory.

Tries ``private.jwk`` first (preferred), then falls back to
``private.pem`` (PKCS#8 PEM).  The loaded key becomes the sole active
key; no retained or pending keys are present.

This is a read-only view — `generate_key`, `activate`, and
`supersede` work in memory but are not persisted because the source
files use the CLI's single-key format rather than the SDK key store
format.

**Arguments:**

- `key_directory` (`Path | str`): Directory written by the DNSid CLI (e.g. ``~/.dnsid/<domain>``). Usually obtained from `CliConfigResult.key_directory`.

**Raises:**

- `FileNotFoundError`: If neither ``private.jwk`` nor ``private.pem`` exists in *key_directory*.
- `ValueError`: If the key file cannot be parsed or does not contain valid Ed25519 or P-256 private key material.

### `from_private_jwk`

```python
LocalKeyProvider.from_private_jwk(path: Path | str) -> LocalKeyProvider
```

Load a read-only provider from one CLI-style private JWK file.

### `from_domain`

```python
LocalKeyProvider.from_domain(domain: str, dnsid_dir: Path | str | None = None) -> LocalKeyProvider
```

Load from a DNSid CLI root directory for the given domain.

Convenience wrapper around `from_cli_directory` that constructs
the identity key path from the domain name, defaulting to
``~/.dnsid/<normalized-domain>``.

**Arguments:**

- `domain` (`str`): Agent FQDN (trailing dot and casing are normalised).
- `dnsid_dir` (`Path | str | None`): Root DNSid directory. Defaults to ``~/.dnsid``. — default `None`

**Raises:**

- `FileNotFoundError`: If neither ``private.jwk`` nor ``private.pem`` exists in the identity directory.
- `ValueError`: If the key file cannot be parsed.

### `generate`

```python
LocalKeyProvider.generate(algorithm: str = 'EdDSA') -> LocalKeyProvider
```

Return an ephemeral in-memory provider using EdDSA or ES256.

### `signing_key`

```python
LocalKeyProvider.signing_key() -> JWK
```

Return the public JWK of the current active signing key.

### `jwk`

```python
LocalKeyProvider.jwk(kid: str) -> JWK
```

Return the public JWK for *kid* (active, retained, or pending).

**Raises:**

- `ArgumentError`: If *kid* is not found.

### `list_key_ids`

```python
LocalKeyProvider.list_key_ids() -> list[str]
```

Return the active key ID followed by all retained key IDs.

### `sign`

```python
LocalKeyProvider.sign(payload: bytes) -> bytes
```

Sign *payload* with the current active key in JOSE wire format.

### `sign_key`

```python
LocalKeyProvider.sign_key(kid: str, payload: bytes) -> bytes
```

Sign *payload* with a specified active or pending key.

**Raises:**

- `ArgumentError`: If *kid* is neither the active key nor a pending key.

### `generate_key`

```python
LocalKeyProvider.generate_key() -> str
```

Generate a pending key using the active key's algorithm.

Persists the updated store when the provider is file-backed.

**Returns:**

- `str` — The kid of the newly generated key.

### `activate`

```python
LocalKeyProvider.activate(kid: str) -> None
```

Promote *kid* from pending to active; current active moves to retained.

Persists the updated store when the provider is file-backed.

**Raises:**

- `ArgumentError`: If no pending key matches *kid*.

### `supersede`

```python
LocalKeyProvider.supersede(kid: str) -> None
```

Rotate a retained key out of live use entirely.

Persists the updated store when the provider is file-backed.

**Raises:**

- `ArgumentError`: If *kid* is the active key or not a retained key.

## `AwsKmsKeyProvider`

```python
from dnsid import AwsKmsKeyProvider
```

*Bases:* `KeyProvider`

AWS KMS-backed DNSid KeyProvider.

AWS KMS owns all private key material and performs signing. This provider
manages DNSid's active/pending/retained key lifecycle, fetches public keys
as JWKs, and routes sign() calls through KMS.

Construct with `load` — it resolves any aliases to canonical key IDs
before the provider is used::

    provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(
        active_key_id="alias/dnsid-current",
        algorithm="ECDSA_SHA_256",
    ))

Persistence is the caller's responsibility: after ``generate_key()``,
``activate()``, or ``supersede()`` call ``state_snapshot()`` and save the result.

### `AwsKmsKeyProvider` constructor

```python
AwsKmsKeyProvider(client: AwsKmsFacade, config: AwsKmsConfig) -> None
```

Initialize from a facade and config without resolving aliases.

Prefer `load`, which also resolves aliases to canonical KMS key
IDs and warms the JWK cache.

**Arguments:**

- `client` (`AwsKmsFacade`): Facade over the AWS KMS client.
- `config` (`AwsKmsConfig`): Provider configuration and initial key lifecycle state.

**Raises:**

- `ArgumentError`: If any configured key ID is empty or contains '#'.

### `load`

```python
AwsKmsKeyProvider.load(client: AwsKmsFacade, config: AwsKmsConfig) -> AwsKmsKeyProvider
```

Create a provider and resolve all key IDs/aliases to canonical KMS key IDs.

Makes a ``GetPublicKey`` call for every configured key ID to resolve aliases
and warm the JWK cache.

### `state_snapshot`

```python
AwsKmsKeyProvider.state_snapshot() -> AwsKmsKeyState
```

Return a copy of the current key lifecycle state for persistence.

### `signing_key`

```python
AwsKmsKeyProvider.signing_key() -> JWK
```

Return the public JWK of the current active signing key.

### `jwk`

```python
AwsKmsKeyProvider.jwk(kid: str) -> JWK
```

Return the public JWK for *kid*.

**Raises:**

- `ArgumentError`: If *kid* is neither the active key nor a retained key.

### `list_key_ids`

```python
AwsKmsKeyProvider.list_key_ids() -> list[str]
```

Return the active key ID followed by all retained key IDs.

### `sign`

```python
AwsKmsKeyProvider.sign(payload: bytes) -> bytes
```

Sign *payload* with the active KMS key.

Uses RAW signing up to the KMS 4096-byte limit; larger ECDSA payloads
are hashed locally and signed as a DIGEST.  ECDSA signatures are
converted from DER to the JOSE IEEE P1363 format.

**Returns:**

- `bytes` — Raw signature bytes in JOSE wire format.

**Raises:**

- `ArgumentError`: If the payload exceeds the RAW limit for Ed25519, or the KMS response is inconsistent (missing signature, algorithm mismatch, or unexpected signing key).

### `generate_key`

```python
AwsKmsKeyProvider.generate_key() -> str
```

Generate a new KMS key in the pending state.

**Returns:**

- `str` — The canonical KMS key ID of the new key.

**Raises:**

- `ArgumentError`: If key creation succeeds but the public key cannot be loaded.

### `activate`

```python
AwsKmsKeyProvider.activate(kid: str) -> None
```

Promote *kid* from pending to active; current active moves to retained.

**Raises:**

- `ArgumentError`: If no pending key matches *kid*.

### `supersede`

```python
AwsKmsKeyProvider.supersede(kid: str) -> None
```

Rotate a retained key out of live use.

Schedules KMS key deletion first when
``schedule_key_deletion_on_supersede`` is enabled.

**Raises:**

- `ArgumentError`: If *kid* is the active key, is not a retained key, or deletion scheduling is enabled but unsupported by the facade.

## `AwsKmsConfig`

```python
from dnsid import AwsKmsConfig
```

Configuration for AwsKmsKeyProvider.

**Attributes:**

- `algorithm` (`AwsKmsSigningAlgorithm`): KMS signing algorithm — must match the key spec.
- `active_key_id` (`str`): ARN, key ID, alias, or alias ARN of the current signing key. Ignored when ``state`` is supplied.
- `retained_key_ids` (`list[str]`): KMS key IDs retained for signature verification. Ignored when ``state`` is supplied.
- `pending_key_ids` (`list[str]`): KMS key IDs generated but not yet activated. Ignored when ``state`` is supplied.
- `state` (`AwsKmsKeyState | None`): Preferred mutable state object. Takes precedence over top-level key ID fields.
- `key_spec` (`AwsKmsKeySpec | None`): Key spec for new keys created by ``generate_key()``. Defaults from ``algorithm``.
- `description` (`str | None`): Description passed to KMS when ``generate_key()`` creates a new key.
- `tags` (`dict[str, str] | None`): Tags passed to KMS when ``generate_key()`` creates a new key.
- `schedule_key_deletion_on_supersede` (`bool`): Call ``ScheduleKeyDeletion`` when a retained key is superseded.
- `deletion_window_in_days` (`int`): Waiting period for ``ScheduleKeyDeletion``. AWS allows 7–30 days.

## `AwsKmsKeyState`

```python
from dnsid import AwsKmsKeyState
```

Mutable lifecycle state for AwsKmsKeyProvider.

Persist the return value of ``state_snapshot()`` after ``generate_key()``,
``activate()``, or ``supersede()``; pass it back in as ``config.state`` on
the next process start.

## `BotoKmsFacade`

```python
from dnsid import BotoKmsFacade
```

*Bases:* `AwsKmsFacade`

Adapter wrapping a ``boto3`` KMS client.

Usage::

    import boto3
    from dnsid import AwsKmsKeyProvider, AwsKmsConfig, BotoKmsFacade

    facade = BotoKmsFacade(boto3.client("kms", region_name="us-east-1"))
    provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(
        active_key_id="alias/dnsid-current",
        algorithm="ECDSA_SHA_256",
    ))

### `BotoKmsFacade` constructor

```python
BotoKmsFacade(client: Any) -> None
```

Wrap a ``boto3`` KMS client.

**Arguments:**

- `client` (`Any`): A ``boto3`` KMS client, e.g. ``boto3.client("kms")``.

### `create_signing_key`

```python
BotoKmsFacade.create_signing_key(key_spec: AwsKmsKeySpec, description: str | None = None, tags: dict[str, str] | None = None) -> str
```

Create a new SIGN_VERIFY key via KMS ``CreateKey``.

**Returns:**

- `str` — The new key ARN.

**Raises:**

- `ArgumentError`: If the KMS response includes no key ARN or key ID.

### `get_public_key`

```python
BotoKmsFacade.get_public_key(key_id: str) -> dict[str, Any]
```

Fetch public key info for *key_id* via KMS ``GetPublicKey``.

**Returns:**

- `dict[str, Any]` — A dict with keys ``key_id``, ``public_key``, ``key_spec``,
- `dict[str, Any]` — ``key_usage``, and ``signing_algorithms``.

**Raises:**

- `ArgumentError`: If the KMS response includes no public key bytes.

### `sign`

```python
BotoKmsFacade.sign(key_id: str, message: bytes, signing_algorithm: AwsKmsSigningAlgorithm, message_type: Literal['RAW', 'DIGEST']) -> dict[str, Any]
```

Sign *message* with *key_id* via KMS ``Sign``.

**Returns:**

- `dict[str, Any]` — A dict with keys ``key_id``, ``signature``, and ``signing_algorithm``.

**Raises:**

- `ArgumentError`: If the KMS response includes no signature.

### `schedule_key_deletion`

```python
BotoKmsFacade.schedule_key_deletion(key_id: str, pending_window_in_days: int) -> None
```

Schedule deletion of *key_id* via KMS ``ScheduleKeyDeletion``.

## `AwsKmsFacade`

```python
from dnsid import AwsKmsFacade
```

*Bases:* `ABC`

Narrow, mockable interface over an AWS KMS client.

Implement this to inject a test double; use ``BotoKmsFacade`` for production.

### `create_signing_key`

```python
AwsKmsFacade.create_signing_key(key_spec: AwsKmsKeySpec, description: str | None = None, tags: dict[str, str] | None = None) -> str
```

Create a new SIGN_VERIFY key. Returns the key ARN.

### `get_public_key`

```python
AwsKmsFacade.get_public_key(key_id: str) -> dict[str, Any]
```

Fetch public key info for *key_id*.

> **Returns a dict with keys:** ``key_id`` (str | None), ``public_key`` (bytes), ``key_spec`` (str | None), ``key_usage`` (str | None), ``signing_algorithms`` (list[str] | None).

### `sign`

```python
AwsKmsFacade.sign(key_id: str, message: bytes, signing_algorithm: AwsKmsSigningAlgorithm, message_type: Literal['RAW', 'DIGEST']) -> dict[str, Any]
```

Sign *message* with *key_id*.

> **Returns a dict with keys:** ``key_id`` (str | None), ``signature`` (bytes), ``signing_algorithm`` (str | None).

### `schedule_key_deletion`

```python
AwsKmsFacade.schedule_key_deletion(key_id: str, pending_window_in_days: int) -> None
```

Schedule deletion of *key_id* after a waiting period.

Optional; only required when ``schedule_key_deletion_on_supersede`` is
``True``.  Raises NotImplementedError when the facade does not support
key deletion.
