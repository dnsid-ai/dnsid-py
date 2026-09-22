---
title: "Python: Transparency log (c2sp-tlog)"
description: "LogReader for C2SP tile-log transparency logs (dnsid.c2sp_tlog)."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

Everything on this page is imported from `dnsid.c2sp_tlog`. The subpackage is wire-compatible with the other DNSid SDKs' c2sp-tlog implementations.

## `C2SP_SPEC_REVISIONS`

```python
from dnsid.c2sp_tlog import C2SP_SPEC_REVISIONS
```

*Type:* `dict[str, str]`

*Value:* `{'tlog-checkpoint': 'v1.0.0', 'tlog-tiles': 'v0.1.0', 'tlog-proof': 'ab17a74116563005f908b9167e6421cc929a5c2b', 'tlog-policy': '1896a5aea5559b3203d275d0206d872f59348cf5', 'tlog-witness': 'v1.0.0', 'tlog-cosignature': 'v1.0.1', 'tlog-mirror': 'd0fe789122c75b903bfc1680b0b8b8dc570f0db3', 'signed-note': 'v1.0.0'}`

## `C2spBoundedResourceFetcher`

```python
from dnsid.c2sp_tlog import C2spBoundedResourceFetcher
```

*Bases:* `Protocol`

Fetcher that enforces a decoded response limit during each read.

Implementations also provide cancellation or finite request deadlines so a
resource read cannot wait indefinitely.

### `fetch_bounded`

```python
C2spBoundedResourceFetcher.fetch_bounded(url: str, max_bytes: int) -> bytes
```

Fetch exactly *url* and return at most *max_bytes* decoded bytes.

### `security_guarantees`

```python
C2spBoundedResourceFetcher.security_guarantees() -> C2spResourceFetchGuarantees
```

Declare the public-read security capabilities enforced by the fetcher.

## `C2spChain`

```python
from dnsid.c2sp_tlog import C2spChain
```

Logical stream-chain metadata required in every scope.

## `C2spCheckpointConsistencyError`

```python
from dnsid.c2sp_tlog import C2spCheckpointConsistencyError
```

*Bases:* `C2spTlogVerificationError`

A checkpoint violates previously accepted trust; never automatically retry.

``category`` identifies the failed check: ``LOG_ROLLBACK`` (smaller size),
``LOG_FORK`` (same size, different root), or ``LOG_INCONSISTENT`` (growing
tree is not an extension). None establishes whether recovery was authorized.
At the LogReader boundary this becomes a non-transient ``VerificationError``
with the same category and this typed error as its ``__cause__``.

### `C2spCheckpointConsistencyError` constructor

```python
C2spCheckpointConsistencyError(message: str, category: C2spLifecycleErrorCategory, trusted: TrustedCheckpoint, observed: TrustedCheckpoint) -> None
```

Capture both checkpoints so routing never requires message matching.

**Arguments:**

- `message` (`str`): Description of the failed consistency check.
- `category` (`C2spLifecycleErrorCategory`): The observed rollback, fork, or inconsistency category.
- `trusted` (`TrustedCheckpoint`): Previously accepted checkpoint.
- `observed` (`TrustedCheckpoint`): Candidate that failed the consistency check.

## `C2spCheckpointStoreError`

```python
from dnsid.c2sp_tlog import C2spCheckpointStoreError
```

*Bases:* `C2spTlogError`

Trusted storage is unavailable, corrupt, or changed during recovery.

Fails closed as non-transient ``LOG_ERROR`` at the LogReader boundary.
Restore storage or investigate before retrying; never substitute empty trust.

## `C2spConsistencyProofSource`

```python
from dnsid.c2sp_tlog import C2spConsistencyProofSource
```

*Bases:* `Protocol`

Optional source for RFC 6962 checkpoint consistency proofs.

### `fetch_consistency_proof`

```python
C2spConsistencyProofSource.fetch_consistency_proof(reference: ParsedC2spTlogLr, from_size: int, to_size: int) -> list[bytes]
```

Return the RFC 6962 consistency proof from *from_size* to *to_size*.

## `C2spEventContext`

```python
from dnsid.c2sp_tlog import C2spEventContext
```

Stream context stamped into (and validated against) public entries.

## `C2spLifecycleErrorCategory`

```python
from dnsid.c2sp_tlog import C2spLifecycleErrorCategory
```

Stable failure categories used by C2SP lifecycle selection.

**Members:**

- `CHAIN_CONTINUITY` = `'CHAIN_CONTINUITY'`
- `DUPLICATE_ISSUANCE` = `'DUPLICATE_ISSUANCE'`
- `INVALID_EVIDENCE` = `'INVALID_EVIDENCE'`
- `INCOMPLETE_STREAM` = `'INCOMPLETE_STREAM'`
- `INVALID_MIGRATION` = `'INVALID_MIGRATION'`
- `KEY_CONTINUITY` = `'KEY_CONTINUITY'`
- `TERMINAL_STATE` = `'TERMINAL_STATE'`
- `LOG_ROLLBACK` = `'LOG_ROLLBACK'`
- `LOG_FORK` = `'LOG_FORK'`
- `LOG_INCONSISTENT` = `'LOG_INCONSISTENT'`
- `CHECKPOINT_STORE_ERROR` = `'CHECKPOINT_STORE_ERROR'`

## `C2spMigrationVerificationLimits`

```python
from dnsid.c2sp_tlog import C2spMigrationVerificationLimits
```

Cumulative bounds for recursive previous-log verification.

## `C2spProvenEntry`

```python
from dnsid.c2sp_tlog import C2spProvenEntry
```

Untrusted single-entry evidence returned by a ``C2spTlogSource``.

## `C2spResourceFetchGuarantees`

```python
from dnsid.c2sp_tlog import C2spResourceFetchGuarantees
```

Capabilities required for policy and public standard-resource reads.

## `C2spScanLimits`

```python
from dnsid.c2sp_tlog import C2spScanLimits
```

Resource limits for the built-in complete C2SP log scanner.

C2SP entry-bundle geometry is fixed at 256 entries. Defaults bound the
scanner to one million entries, 1 MiB checkpoints, exactly 16,777,472
bytes per bundle, and 256 MiB total entry-bundle bytes.

## `C2spSignatureValue`

```python
from dnsid.c2sp_tlog import C2spSignatureValue
```

One member of an entry's sigs object: signer key ID plus signature.

## `C2spSignerRole`

```python
from dnsid.c2sp_tlog import C2spSignerRole
```

Lifecycle signer roles for c2sp-tlog envelopes.

The first three reuse their shared DNSid meanings; NEW_OPERATIONAL is
owned by this binding and is only the KEY_ROTATION proof of possession.

**Members:**

- `ENTITY` = `'Entity'`
- `OPERATIONAL_COUNTERSIGNATURE` = `'OperationalCountersignature'`
- `PREVIOUS_OPERATIONAL` = `'PreviousOperational'`
- `NEW_OPERATIONAL` = `'NewOperational'`

## `C2spStreamBundleVerifierOptions`

```python
from dnsid.c2sp_tlog import C2spStreamBundleVerifierOptions
```

Local trust and resource limits for portable stream bundle verification.

``policy_bytes`` and ``bundle_keys`` are independent trust inputs; neither
is taken from the bundle. Times and configured lifetime/freshness bounds
are milliseconds, matching `C2spTlogReaderOptions`.

## `C2spStreamEvidence`

```python
from dnsid.c2sp_tlog import C2spStreamEvidence
```

*Value:* `StreamEvidence`

## `C2spTlogError`

```python
from dnsid.c2sp_tlog import C2spTlogError
```

*Bases:* `Exception`

Base error for the c2sp-tlog package.

During verify_domain these surface as VerificationError with LOG_ERROR.

## `C2spTlogOriginPolicy`

```python
from dnsid.c2sp_tlog import C2spTlogOriginPolicy
```

Trust policy for one checkpoint origin.

## `C2spTlogParseError`

```python
from dnsid.c2sp_tlog import C2spTlogParseError
```

*Bases:* `C2spTlogError`

Raised when C2SP wire data (checkpoints, proofs, entries) is malformed.

## `C2spTlogPolicy`

```python
from dnsid.c2sp_tlog import C2spTlogPolicy
```

Local C2SP trust policy: per-origin log/witness keys and quorum.

## `C2spTlogQuorumRule`

```python
from dnsid.c2sp_tlog import C2spTlogQuorumRule
```

A quorum rule node: kind is 'none', 'witness', or 'threshold'.

## `C2spTlogReader`

```python
from dnsid.c2sp_tlog import C2spTlogReader
```

*Bases:* `LogReader`

LogReader over a C2SP tile log, verified against a local trust policy.

Read paths authenticate the checkpoint and select the signed lifecycle
from either a strictly verified per-domain bundle or a complete raw scan.

For a draft 01 record this reader performs the binding-level lifecycle
checks verify_domain requires:

* Checkpoint authentication — signed-note signature against the pinned
  log key plus witness-quorum cosignatures, with append-only consistency
  against the stored trusted checkpoint (anti-rollback).
* Stream lifecycle verification — scans every entry of the identity's
  stream and selects the entries forming a valid signed lifecycle: an
  ISSUANCE (or verified MIGRATION genesis) establishing the entity and
  operational keys, followed by rotations and entity-signed lifecycle
  events, with logical-event hash chaining in every scope.
* Bilateral ISSUANCE binding — the record's ek/ku anchors must match the
  logged entity and operational keys, both signatures verified
  (`verify_bilateral_binding`).
* Operational continuity — the current operational key must descend from
  the logged initial operational key through recorded rotations.
* Non-termination — no REVOCATION or RETIREMENT event for the domain, under a
  sufficiently fresh checkpoint (``checkpoint_freshness_ms``).
* Merkle inclusion — entry inclusion proofs against the checkpoint root.

### `C2spTlogReader` constructor

```python
C2spTlogReader(lr: str, options: C2spTlogReaderOptions) -> None
```

Bind a reader to the stream addressed by *lr* and validate *options*.

**Raises:**

- `C2spTlogParseError`: If *lr* is not a valid c2sp-tlog reference.
- `C2spTlogVerificationError`: If *options* is invalid (negative clock skew, or neither/both of transport and source given).

### `canonical`

```python
C2spTlogReader.canonical(event: LogEvent) -> bytes
```

Return the canonical signed C2SP entry bytes for *event*.

In every scope only an ISSUANCE can be canonicalized here;
later events must go through the prepared-event API.

**Raises:**

- `C2spTlogParseError`: If the event cannot be encoded as a C2SP entry (for example, missing key metadata).
- `VerificationError`: With ``VerificationCode.LOG_ERROR`` if the event type is unsupported or requires the prepared-event API.

### `key_timestamp`

```python
C2spTlogReader.key_timestamp(domain: str, key_thumbprint: str) -> datetime.datetime
```

Return when *key_thumbprint* became an operational key for *domain*.

The timestamp comes from the verified lifecycle event (ISSUANCE or
KEY_ROTATION) that introduced the key.

**Raises:**

- `VerificationError`: With ``VerificationCode.LOG_ERROR`` if the thumbprint does not appear in the verified history or the history itself cannot be loaded and verified.

### `preload_history`

```python
C2spTlogReader.preload_history(domain: str, entity_key: JWK) -> None
```

Fetch and verify the complete history for *domain* under *entity_key*.

Warms the same cache `verify_bilateral_binding` reads, so callers
can overlap the log fetch with other independent network work. Raises
exactly what the later binding check would have raised.

### `verify_bilateral_binding`

```python
C2spTlogReader.verify_bilateral_binding(record: object, entity_key: JWK, operational_key: JWK) -> BilateralBindingResult
```

Verify the record's ek/ku anchors against the logged lifecycle.

Loads the complete verified history anchored on *entity_key* (which
becomes this reader's trusted entity key for later calls), and checks
that the ISSUANCE matches the record's domain and governance ID, its
entity key matches the current ek anchor, and the current operational
key is recorded in the lifecycle (initial or via rotation).

### `verify_operational_continuity`

```python
C2spTlogReader.verify_operational_continuity(domain: str, initial_operational_thumbprint: str, current_operational_thumbprint: str) -> None
```

Verify the active operational key follows from the initial one.

### `verify_non_revocation`

```python
C2spTlogReader.verify_non_revocation(domain: str, at: datetime.datetime) -> LoggedStateEvidence
```

Verify complete, fresh logged history for *domain* as of *at*.

Requires ``checkpoint_freshness_ms`` to be configured and the
checkpoint's witness time to be within that bound.

**Returns:**

- `LoggedStateEvidence` — The accepted completeness, checkpoint, and freshness boundary.

**Raises:**

- `VerificationError`: With ``VerificationCode.LOG_ERROR`` if the domain was revoked or retired at or before *at*, the checkpoint is too stale, or the history cannot be loaded and verified.

### `read_event`

```python
C2spTlogReader.read_event(ref: LogRef) -> AnyLogEvent
```

Read and verify the single logged event addressed by *ref*.

The reference must belong to this reader's stream and carry an
``@index``; a matching entry in ``options.proofs`` supplies the
tlog-proof.  The entry is checked for inclusion under a
policy-accepted checkpoint and must be authorized by the verified
lifecycle history of its domain.

**Returns:**

- `AnyLogEvent` — The parsed, lifecycle-authorized event.

**Raises:**

- `C2spTlogParseError`: If *ref* or the entry bytes are malformed.
- `VerificationError`: With ``VerificationCode.LOG_ERROR`` if the proof, checkpoint policy, timestamp, or lifecycle authorization checks fail.

### `rebuild_history`

```python
C2spTlogReader.rebuild_history(domain: str) -> list[AnyLogEvent]
```

Return the verified lifecycle events for *domain* in log order.

**Raises:**

- `VerificationError`: With ``VerificationCode.LOG_ERROR`` if the stream cannot be completely loaded, checked against the checkpoint, and verified under the trusted entity key.

### `rebuild_history_through`

```python
C2spTlogReader.rebuild_history_through(domain: str, final_entry_ref: str, entity_key: JWK, max_depth: int, max_events: int, max_response_bytes: int, seen_log_references: frozenset[str]) -> VerifiedCutoffHistory
```

Verify this stream through exactly *final_entry_ref*.

## `C2spTlogReaderOptions`

```python
from dnsid.c2sp_tlog import C2spTlogReaderOptions
```

Configuration for `C2spTlogReader`.

*policy* is the local checkpoint trust policy (per-origin log keys,
witness keys, quorum).  *transport* fetches URLs and must raise on HTTP
errors (a testnet deployment typically routes it through the testnet DNS
and CA).  *proofs* pre-supplies TlogProofV1 inclusion proofs keyed by
entry index (as a string).  *entity_key* is the trusted entity key that
anchors lifecycle verification (identity pinning).  *max_clock_skew_ms*
is the tolerated clock skew for checkpoint/cosignature timestamps.
*checkpoint_freshness_ms* bounds checkpoint staleness for non-revocation.
*max_tree_size* is an upper bound on the accepted tree size (resource
guard). *scan_limits* configures all resource bounds of the built-in
complete scanner; when both are set, *max_tree_size* takes precedence.
*migration_limits* bounds recursive depth, cumulative stitched events, and
cumulative response bytes. *migration_reader_factory* is the advanced
low-level hook used to construct fully verifying predecessor readers; the
standard registries configure it automatically. *checkpoint_store* records
the highest trusted checkpoint per origin so a later verification cannot
accept a forked or rolled-back tree; share one options instance across
readers so the state accumulates.
For ``public`` scope, an injected source or transport must expose
``security_guarantees()`` and demonstrate the complete public bounded-read
capability contract, including DNS-rebinding and redirect protections.
A scan transport must also implement ``fetch_bounded(url, maximum)``.
Supplying independently trusted ``bundle_keys`` and the exact
``bundle_policy_document`` prefers bounded per-domain stream bundles;
the scanner remains the availability and consistency fallback.

## `C2spTlogSource`

```python
from dnsid.c2sp_tlog import C2spTlogSource
```

*Bases:* `Protocol`

Source-neutral interface returning untrusted C2SP evidence.

### `fetch_checkpoint`

```python
C2spTlogSource.fetch_checkpoint(reference: ParsedC2spTlogLr) -> bytes
```

Fetch the raw signed checkpoint bytes for *reference*.

### `read_entry`

```python
C2spTlogSource.read_entry(reference: ParsedC2spTlogLr, index: int) -> C2spProvenEntry
```

Return entry *index* with an inclusion proof and its checkpoint.

### `load_stream`

```python
C2spTlogSource.load_stream(reference: ParsedC2spTlogLr, fqdn: str) -> C2spStreamEvidence
```

Return checkpoint-plus-entries evidence covering *fqdn*'s stream.

## `C2spTlogTransport`

```python
from dnsid.c2sp_tlog import C2spTlogTransport
```

*Value:* `Callable[[str], 'bytes | str'] | C2spBoundedResourceFetcher`

Lower-level callable transport or bounded standard-resource fetcher.

## `C2spTlogTransportError`

```python
from dnsid.c2sp_tlog import C2spTlogTransportError
```

*Bases:* `C2spTlogError`

Raised when fetching C2SP verification resources fails.

``transient`` is true only when retrying the same read may succeed.  TLS,
redirect, authentication, and configured resource-policy failures are
non-transient; network reachability and server-unavailable failures are
transient.

### `C2spTlogTransportError` constructor

```python
C2spTlogTransportError(message: str, transient: bool, cause: BaseException | None = None, status_code: int | None = None) -> None
```

Initialize a classified transport failure.

**Arguments:**

- `message` (`str`): Human-readable transport failure.
- `transient` (`bool`): Whether retrying the same read may succeed.
- `cause` (`BaseException | None`): Underlying transport exception, when available. — default `None`
- `status_code` (`int | None`): HTTP response status, when the server responded. — default `None`

## `C2spTlogTrustProfile`

```python
from dnsid.c2sp_tlog import C2spTlogTrustProfile
```

Trusted policy and bundle signers bound to one exact log.

## `C2spTlogVerificationError`

```python
from dnsid.c2sp_tlog import C2spTlogVerificationError
```

*Bases:* `C2spTlogError`

Raised when C2SP evidence fails cryptographic or policy verification.

### `C2spTlogVerificationError` constructor

```python
C2spTlogVerificationError(message: str, category: C2spLifecycleErrorCategory | None = None, failing_candidate_index: int | None = None) -> None
```

Initialize with a message and optional failure classification.

**Arguments:**

- `message` (`str`): Human-readable description of the verification failure.
- `category` (`C2spLifecycleErrorCategory | None`): Stable lifecycle failure category, when the failure maps to one. — default `None`
- `failing_candidate_index` (`int | None`): Zero-based index of the candidate entry that failed, when identifiable. — default `None`

## `C2spTlogVerificationOptions`

```python
from dnsid.c2sp_tlog import C2spTlogVerificationOptions
```

Configure `create_c2sp_tlog_verification_registry`.

Exactly one of `trust_profile`, `policy_document`, and
`policy_url` is required. A policy URL is independently trusted caller
configuration and is never inferred from an identity record or log prefix.

``resource_fetcher`` is shared by policy and standard C2SP reads. Custom
fetchers must implement the bounded-fetch and explicit security-capability
contract. The built-in fetcher requires HTTPS and HTTP 200, rejects
redirects and unsafe destinations, pins connections to validated DNS
results, bounds decoded bytes during reads, and uses finite deadlines.

A trust profile or direct ``bundle_verifier_keys`` enables verified
per-domain stream bundles. Unavailable endpoints fall back to the bounded
complete scanner. A valid newer bundle without a separate consistency proof
uses a complete scan to verify both checkpoint roots.
``require_stream_bundle`` disables both fallbacks. A positive
``max_bundle_lifetime_ms`` is required whenever bundle keys are configured;
bundle byte and event limits retain finite defaults.

``migration_limits`` has finite defaults for recursive depth, cumulative
history events, and cumulative response bytes. Predecessor references are
dispatched through the returned registry; additional registered methods
must implement the method-neutral verified-cutoff contract.
``checkpoint_freshness_ms``
intentionally has no default. Non-revocation therefore fails closed unless
the application chooses a positive maximum age. The default checkpoint
store is process-lifetime only; inject durable storage when rollback
protection must survive restarts.

## `C2spVerificationContext`

```python
from dnsid.c2sp_tlog import C2spVerificationContext
```

Expected identity and trusted keys for validating a prepared envelope.

A process that countersigns a prepared event (notably the operational side
of a split ISSUANCE) supplies what it expects the envelope to authorize —
its own ``fqdn``/``gi``/``operational_key`` and, when known, the trusted
``entity_key`` — so a malicious issuer cannot obtain a countersignature for
an unexpected identity.  Fields left ``None`` are not checked.

## `Checkpoint`

```python
from dnsid.c2sp_tlog import Checkpoint
```

A parsed C2SP checkpoint (origin, tree size, root hash, signatures).

## `CheckpointPolicyResult`

```python
from dnsid.c2sp_tlog import CheckpointPolicyResult
```

Outcome of checkpoint policy enforcement.

## `CheckpointStore`

```python
from dnsid.c2sp_tlog import CheckpointStore
```

*Bases:* `ABC`

Durable record of the highest trusted checkpoint per origin.

Implementations MUST be safe for concurrent use.  Consistency enforcement
and advancement MUST be atomic per origin (see `verify_and_advance`):
checking a new checkpoint against the trusted one and recording it cannot
be split, or two concurrent verifications could each accept a different
forked extension of the same trusted checkpoint.

### `get`

```python
CheckpointStore.get(origin: str) -> TrustedCheckpoint | None
```

Return the trusted checkpoint for *origin*, or None if unseen.

### `put`

```python
CheckpointStore.put(checkpoint: TrustedCheckpoint) -> None
```

Unconditionally record *checkpoint* if it advances *origin*.

Bypasses consistency checking; intended for seeding trusted state, not
for the verification path (use `verify_and_advance`).

### `verify_and_advance`

```python
CheckpointStore.verify_and_advance(candidate: TrustedCheckpoint, verify: Callable[[TrustedCheckpoint | None], None]) -> None
```

Atomically check consistency and advance the trusted checkpoint.

Under the per-origin lock: load the trusted checkpoint, call *verify*
with it (which MUST raise if *candidate* is a rollback or fork of that
trusted state), then record *candidate* if it advances the tree.
Holding the lock across verify and advance serializes concurrent
verifications of one origin, so an equivocating log cannot get two
forked extensions accepted against the same trusted checkpoint.

## `DNSID_C2SP_ENVELOPE_VERSION`

```python
from dnsid.c2sp_tlog import DNSID_C2SP_ENVELOPE_VERSION
```

*Type:* `int`

*Value:* `1`

## `DnsidManagedVerificationOptions`

```python
from dnsid.c2sp_tlog import DnsidManagedVerificationOptions
```

Shared infrastructure for managed DNSid log verification.

Trust roots, freshness, resource limits, and bundle preference are fixed by
the embedded managed catalog. Callers needing different trust use
`create_c2sp_tlog_verification_registry`.

## `InMemoryCheckpointStore`

```python
from dnsid.c2sp_tlog import InMemoryCheckpointStore
```

*Bases:* `CheckpointStore`

Process-lifetime trusted-checkpoint store (the default).

Resists rollback and fork *within a process*.  It does NOT survive a
restart: afterward the first checkpoint for an origin is trusted on first
contact, so a rollback served post-restart would be accepted.  A verifier
that must resist cross-restart rollback MUST inject a durable
``CheckpointStore`` such as `SQLiteCheckpointStore`. The SDK does not
emit a runtime warning when this in-memory default is selected; production
deployments must explicitly configure and monitor persistent trust storage.

### `InMemoryCheckpointStore` constructor

```python
InMemoryCheckpointStore() -> None
```

Create an empty store with no trusted checkpoints.

### `get`

```python
InMemoryCheckpointStore.get(origin: str) -> TrustedCheckpoint | None
```

Return the trusted checkpoint for *origin*, or None if unseen.

### `put`

```python
InMemoryCheckpointStore.put(checkpoint: TrustedCheckpoint) -> None
```

Record *checkpoint* if it advances its origin, without verifying.

### `verify_and_advance`

```python
InMemoryCheckpointStore.verify_and_advance(candidate: TrustedCheckpoint, verify: Callable[[TrustedCheckpoint | None], None]) -> None
```

Run *verify* and record *candidate* under the per-origin lock.

Exceptions raised by *verify* propagate and leave the trusted
checkpoint for the origin unchanged.

## `IndexedEntry`

```python
from dnsid.c2sp_tlog import IndexedEntry
```

One raw log entry paired with its zero-based leaf index.

## `MigrationVerificationResult`

```python
from dnsid.c2sp_tlog import MigrationVerificationResult
```

Prior state for the advanced low-level lifecycle-selection callback.

Standard readers do not accept caller-constructed migration results; they
recover this state through bounded recursive log verification.

## `NoteSignature`

```python
from dnsid.c2sp_tlog import NoteSignature
```

One signature line from a signed note.

## `ParsedC2spTlogLr`

```python
from dnsid.c2sp_tlog import ParsedC2spTlogLr
```

Structured form of a c2sp-tlog lr reference.

## `PreparedC2spTlogEvent`

```python
from dnsid.c2sp_tlog import PreparedC2spTlogEvent
```

An envelope prepared for split signing.

Treated as immutable apart from adding a role signature (via
`sign_prepared_event`, which returns a new instance).  ``envelope``
preserves unknown signed fields; ``signed_bytes`` is the canonical JCS of
the envelope with the top-level ``sigs`` member removed.

### `missing_signatures`

```python
PreparedC2spTlogEvent.missing_signatures() -> list[C2spSignerRole]
```

Roles still absent from the envelope's sigs object.

## `SQLiteCheckpointStore`

```python
from dnsid.c2sp_tlog import SQLiteCheckpointStore
```

*Bases:* `CheckpointStore`

Durable checkpoint store shared by threads and processes.

SQLite transactions serialize verification and advancement and commit before
success. Uses rollback journaling with ``synchronous=EXTRA`` and enables
``fullfsync`` where SQLite supports it. Use a local persistent filesystem
with working SQLite locks and sync semantics, not a network filesystem.

Open an existing store by default; ``create=True`` exclusively initializes a
NEW file. Never automatically recreate a missing/corrupt store on startup:
losing the database loses the trust history. An empty store still uses first
contact trust; seed an independently authenticated checkpoint with ``put``
if that is unsuitable. ``put`` does not authorize lowering a trusted size.

Transactions lock the whole database, including during the verification
callback. Callbacks must not re-enter this store. Operations wait up to five
seconds for contention, then fail closed. No connection is retained between
calls and no explicit close is needed.

### `SQLiteCheckpointStore` constructor

```python
SQLiteCheckpointStore(path: Path | str, create: bool = False) -> None
```

Open or explicitly initialize persistent trust state.

**Arguments:**

- `path` (`Path | str`): Database path in an existing, access-controlled directory.
- `create` (`bool`): Exclusively create a new database; fails if it exists. — default `False`

**Raises:**

- `C2spCheckpointStoreError`: Creation/opening or schema validation fails.

### `get`

```python
SQLiteCheckpointStore.get(origin: str) -> TrustedCheckpoint | None
```

Read the trusted checkpoint; storage failures never become first contact.

### `put`

```python
SQLiteCheckpointStore.put(checkpoint: TrustedCheckpoint) -> None
```

Seed externally authenticated state if its size advances (or equals) trust.

Bypasses proof verification. A smaller size is ignored; an equal-size
conflicting root is rejected. Use ``rebaseline`` to explicitly reset trust.

### `verify_and_advance`

```python
SQLiteCheckpointStore.verify_and_advance(candidate: TrustedCheckpoint, verify: Callable[[TrustedCheckpoint | None], None]) -> None
```

Verify and durably advance in one transaction, rolling back on failure.

### `rebaseline`

```python
SQLiteCheckpointStore.rebaseline(checkpoint: TrustedCheckpoint, expected: TrustedCheckpoint, authorized_by: str, evidence: str) -> None
```

Explicitly replace trust after independently authorized operator recovery.

NEVER call automatically on verification failure. This method records the
operator's assertion of authorization; it cannot authenticate a person or
recovery evidence. The caller must do that independently beforehand.

**Arguments:**

- `checkpoint` (`TrustedCheckpoint`): Independently authenticated replacement checkpoint.
- `expected` (`TrustedCheckpoint`): Exact previous checkpoint reviewed by the operator. A concurrent change aborts the reset rather than overwriting it.
- `authorized_by` (`str`): Nonempty identity of the authorizing incident/security owner.
- `evidence` (`str`): Nonempty incident/evidence reference justifying this trust change.

**Raises:**

- `ValueError`: Invalid checkpoint, origin mismatch, or missing audit fields.
- `C2spCheckpointStoreError`: Stored state changed or persistence failed.

The previous and replacement checkpoints, authorization, evidence reference,
and UTC time are appended to the ``rebaselines`` SQL table in the SAME
transaction as the replacement. Preserve an external incident archive too:
someone with filesystem write access can alter this database and its audit.

## `SafeC2spResourceFetcher`

```python
from dnsid.c2sp_tlog import SafeC2spResourceFetcher
```

WebPKI fetcher with fixed deadlines, no redirects, and SSRF protection.

### `SafeC2spResourceFetcher` constructor

```python
SafeC2spResourceFetcher(timeout_seconds: float = 10.0, transport_config: TransportConfig | None = None, allow_loopback_host: str | None = None) -> None
```

Create a fetcher with a finite timeout and optional DNS/TLS configuration.

**Arguments:**

- `timeout_seconds` (`float`): Finite timeout for each resource request. — default `10.0`
- `transport_config` (`TransportConfig | None`): Optional custom DNS server and additional CA bundle. Its private-host allowlist is ignored; this safe fetcher only permits loopback for the exact *allow_loopback_host*. — default `None`
- `allow_loopback_host` (`str | None`): Exact hostname allowed to resolve to loopback for an explicitly configured local testnet. — default `None`

### `fetch_bounded`

```python
SafeC2spResourceFetcher.fetch_bounded(url: str, max_bytes: int) -> bytes
```

Fetch one HTTPS resource, requiring HTTP 200 and an exact byte bound.

### `security_guarantees`

```python
SafeC2spResourceFetcher.security_guarantees() -> C2spResourceFetchGuarantees
```

Return the capabilities enforced by this implementation.

### `close`

```python
SafeC2spResourceFetcher.close() -> None
```

Close pooled network connections.

## `ScanStreamSource`

```python
from dnsid.c2sp_tlog import ScanStreamSource
```

Fetches the checkpoint and scans every entry bundle beneath it.

*authenticate_checkpoint* runs against the parsed checkpoint before any
entries are fetched (policy enforcement lives there).

### `ScanStreamSource` constructor

```python
ScanStreamSource(transport: C2spTlogTransport, authenticate_checkpoint: Callable[[Checkpoint], None], max_tree_size: int = _DEFAULT_MAX_TREE_SIZE, max_checkpoint_bytes: int = _DEFAULT_MAX_CHECKPOINT_BYTES, max_entry_bundle_bytes: int = _DEFAULT_MAX_ENTRY_BUNDLE_BYTES, max_total_entry_bytes: int = _DEFAULT_MAX_TOTAL_ENTRY_BYTES) -> None
```

Bind the source to *transport* and validate its resource limits.

**Raises:**

- `C2spTlogVerificationError`: If any limit is not a positive integer.

### `load`

```python
ScanStreamSource.load(prefix: str) -> StreamEvidence
```

Fetch the checkpoint under *prefix* and scan every entry beneath it.

**Returns:**

- `StreamEvidence` — Complete evidence: the authenticated checkpoint plus all entries.

**Raises:**

- `C2spTlogParseError`: If the checkpoint or an entry bundle is malformed.
- `C2spTlogVerificationError`: If checkpoint authentication fails, a configured size limit is exceeded, or a bundle width is wrong.

### `security_guarantees`

```python
ScanStreamSource.security_guarantees() -> C2spResourceFetchGuarantees | None
```

Return the injected fetcher's public-read capabilities, if declared.

### `fetch_checkpoint`

```python
ScanStreamSource.fetch_checkpoint(reference: ParsedC2spTlogLr) -> bytes
```

Fetch bounded raw checkpoint bytes for *reference*.

### `load_stream`

```python
ScanStreamSource.load_stream(reference: ParsedC2spTlogLr, fqdn: str) -> C2spStreamEvidence
```

Load a full scan; the reader verifies *fqdn* and all evidence.

### `read_entry`

```python
ScanStreamSource.read_entry(reference: ParsedC2spTlogLr, index: int) -> C2spProvenEntry
```

Return one entry plus a proof derived from a complete scan.

## `SignedNoteKey`

```python
from dnsid.c2sp_tlog import SignedNoteKey
```

A signed-note verifier key (name + Ed25519 public key bytes).

## `StreamEvidence`

```python
from dnsid.c2sp_tlog import StreamEvidence
```

A checkpoint and the entries fetched under it.

## `StreamVerifierOptions`

```python
from dnsid.c2sp_tlog import StreamVerifierOptions
```

Options for advanced lifecycle selection over already proven entries.

## `TlogProofV1`

```python
from dnsid.c2sp_tlog import TlogProofV1
```

A parsed c2sp.org/tlog-proof@v1 document.

## `TrustedCheckpoint`

```python
from dnsid.c2sp_tlog import TrustedCheckpoint
```

The highest checkpoint accepted for one log origin.

## `VerifiedC2spStreamBundle`

```python
from dnsid.c2sp_tlog import VerifiedC2spStreamBundle
```

A fully verified portable bundle of logged lifecycle state.

## `VerifiedLifecycleEvent`

```python
from dnsid.c2sp_tlog import VerifiedLifecycleEvent
```

One accepted lifecycle entry with its log position and hashes.

**Attributes:**

- `event_id` (`str`): Signature-independent identity of this applied payload.

## `assert_canonical_json_bytes`

```python
from dnsid.c2sp_tlog import assert_canonical_json_bytes
```

```python
assert_canonical_json_bytes(data: bytes, value: object | None = None) -> None
```

Raise unless *data* is exactly the canonical serialization of its content.

## `c2sp_envelope_to_event`

```python
from dnsid.c2sp_tlog import c2sp_envelope_to_event
```

```python
c2sp_envelope_to_event(obj: object) -> AnyLogEvent
```

Parse a C2SP JSON envelope into the corresponding DNSid event.

## `c2sp_event_id`

```python
from dnsid.c2sp_tlog import c2sp_event_id
```

```python
c2sp_event_id(data: bytes) -> str
```

Derive logical identity without altering exact-entry inclusion evidence.

## `canonical_bytes`

```python
from dnsid.c2sp_tlog import canonical_bytes
```

```python
canonical_bytes(value: object) -> bytes
```

Serialize *value* to canonical JSON as UTF-8 bytes.

**Raises:**

- `C2spTlogParseError`: If *value* cannot be canonically serialized (see `canonical_json`).

## `canonical_json`

```python
from dnsid.c2sp_tlog import canonical_json
```

```python
canonical_json(value: object) -> str
```

Serialize *value* to canonical JSON text.

## `canonical_log_prefix`

```python
from dnsid.c2sp_tlog import canonical_log_prefix
```

```python
canonical_log_prefix(raw: str) -> str
```

Validate and canonicalize a log-prefix URL.

Canonical form has a lowercase scheme and host, no default port,
normalized percent-encoding, and no trailing slash.

**Raises:**

- `C2spTlogParseError`: If *raw* is not a valid http(s) URL or contains userinfo, a query, a fragment, dot segments, encoded slashes, or characters that must be percent-encoded.

## `canonicalize_c2sp_event`

```python
from dnsid.c2sp_tlog import canonicalize_c2sp_event
```

```python
canonicalize_c2sp_event(event: AnyLogEvent, context: C2spEventContext | None = None) -> bytes
```

Canonical stored form of *event* including signatures.

## `checkpoint_origin`

```python
from dnsid.c2sp_tlog import checkpoint_origin
```

```python
checkpoint_origin(log_prefix: str) -> str
```

Derive the signed-note origin (host + path) from a canonical log prefix.

## `checkpoint_path`

```python
from dnsid.c2sp_tlog import checkpoint_path
```

```python
checkpoint_path(prefix: str) -> str
```

Return the fetch path of the log's checkpoint under *prefix*.

## `create_c2sp_tlog_verification_registry`

```python
from dnsid.c2sp_tlog import create_c2sp_tlog_verification_registry
```

```python
create_c2sp_tlog_verification_registry(options: C2spTlogVerificationOptions) -> LogRegistry
```

Create a ready-to-inject registry for standard c2sp-tlog verification.

## `create_dnsid_managed_verification_registry`

```python
from dnsid.c2sp_tlog import create_dnsid_managed_verification_registry
```

```python
create_dnsid_managed_verification_registry(options: DnsidManagedVerificationOptions | None = None) -> LogRegistry
```

Create a registry for reviewed DNSid-managed trust roots.

Calling this separately named factory is an explicit application trust
decision; the generic factory never selects these roots implicitly. Trust
snapshots are bundled with the SDK and selected only for an exact canonical
``(scope, log_prefix)`` pair. Development and production prefer signed
stream bundles with safe raw-scan fallback.

## `encode_entry_bundle`

```python
from dnsid.c2sp_tlog import encode_entry_bundle
```

```python
encode_entry_bundle(entries: list[bytes]) -> bytes
```

Encode entries into the big-endian uint16-length-prefixed bundle form.

**Raises:**

- `C2spTlogParseError`: If any entry exceeds 65535 bytes.

## `enforce_checkpoint_policy`

```python
from dnsid.c2sp_tlog import enforce_checkpoint_policy
```

```python
enforce_checkpoint_policy(checkpoint: Checkpoint, origin: str, policy: C2spTlogPolicy, scope: str, now_ms: float, max_clock_skew_ms: int = 0) -> CheckpointPolicyResult
```

Verify the checkpoint against the local trust policy for *origin*.

Checks the log signature and evaluates the witness quorum; returns the
accepted witness timestamps and the earliest one as the checkpoint's
integration time.

## `entry_bundle_path`

```python
from dnsid.c2sp_tlog import entry_bundle_path
```

```python
entry_bundle_path(prefix: str, n: int, width: int | None = None) -> str
```

Return the C2SP tlog-tiles fetch path for entry bundle *n*.

A partial bundle is addressed by passing its *width*, which appends the
``.p/<width>`` suffix defined by the tlog-tiles spec.

## `entry_bytes`

```python
from dnsid.c2sp_tlog import entry_bytes
```

```python
entry_bytes(prepared: PreparedC2spTlogEvent, context: C2spVerificationContext | None = None) -> bytes
```

Return the complete canonical entry bytes.

Requires every role in ``required_signatures`` to be present, verifies
all of them cryptographically, and re-validates the complete entry.
Does not append.

## `event_to_c2sp_envelope`

```python
from dnsid.c2sp_tlog import event_to_c2sp_envelope
```

```python
event_to_c2sp_envelope(event: AnyLogEvent, context: C2spEventContext | None = None, include_sigs: bool = True) -> dict[str, Any]
```

Build the C2SP JSON envelope for *event*.

## `generate_c2sp_tlog_stream_id`

```python
from dnsid.c2sp_tlog import generate_c2sp_tlog_stream_id
```

```python
generate_c2sp_tlog_stream_id() -> str
```

Generate a fresh version-1 identity-instance stream ID.

**Returns:**

- `str` — The unpadded base64url encoding of 128 cryptographically random bits.

## `inclusion_root`

```python
from dnsid.c2sp_tlog import inclusion_root
```

```python
inclusion_root(leaf: bytes, index: int, tree_size: int, proof: list[bytes]) -> bytes
```

Recompute the tree root from a leaf hash and its inclusion proof.

## `leaf_hash`

```python
from dnsid.c2sp_tlog import leaf_hash
```

```python
leaf_hash(entry_bytes: bytes) -> bytes
```

RFC 6962 leaf hash: SHA-256(0x00 || entry).

## `merkle_root_from_entries`

```python
from dnsid.c2sp_tlog import merkle_root_from_entries
```

```python
merkle_root_from_entries(entries: list[bytes]) -> bytes
```

Compute the RFC 6962 root over a complete, ordered entry list.

## `node_hash`

```python
from dnsid.c2sp_tlog import node_hash
```

```python
node_hash(left: bytes, right: bytes) -> bytes
```

RFC 6962 interior node hash: SHA-256(0x01 || left || right).

## `normalized_origin_policy`

```python
from dnsid.c2sp_tlog import normalized_origin_policy
```

```python
normalized_origin_policy(policy: C2spTlogPolicy, origin: str) -> NormalizedOriginPolicy
```

Resolve, validate, and normalize the policy for *origin*.

## `parse_c2sp_event_entry`

```python
from dnsid.c2sp_tlog import parse_c2sp_event_entry
```

```python
parse_c2sp_event_entry(data: bytes, context: C2spEventContext | None = None, candidate: bool = False) -> AnyLogEvent
```

Parse an entry; scans defer signed chain errors until after authentication.

## `parse_c2sp_policy_file`

```python
from dnsid.c2sp_tlog import parse_c2sp_policy_file
```

```python
parse_c2sp_policy_file(text: str) -> C2spTlogPolicy
```

Parse the C2SP text policy format (log/witness/group/quorum directives).

## `parse_c2sp_signatures`

```python
from dnsid.c2sp_tlog import parse_c2sp_signatures
```

```python
parse_c2sp_signatures(value: object, type_: str, require_complete: bool = True) -> dict[str, C2spSignatureValue]
```

Parse an entry's sigs object into signature values keyed by role.

Partial signature sets are allowed when *require_complete* is False
(prepared events mid-collection).

**Raises:**

- `C2spTlogParseError`: If *type_* is unsupported, the object is missing or malformed, a role is unexpected, or (when *require_complete* is True) a required signature is absent.

## `parse_c2sp_tlog_lr`

```python
from dnsid.c2sp_tlog import parse_c2sp_tlog_lr
```

```python
parse_c2sp_tlog_lr(lr: str) -> ParsedC2spTlogLr
```

Parse and validate a full c2sp-tlog lr string.

The reference form is
``c2sp-tlog:<scope>:<log-prefix>#<stream-id>[@<entry-index>]`` where
*scope* is ``public``, ``testnet``, or ``private-<label>``, and
*log-prefix* is the log's canonical HTTPS base URL.

**Returns:**

- `ParsedC2spTlogLr` — The structured reference, with the log prefix required to already be
- `ParsedC2spTlogLr` — canonical and ``lr`` set to the canonical bound reference (no index).

**Raises:**

- `C2spTlogParseError`: If any component of *lr* is missing or invalid.

## `parse_c2sp_tlog_trust_profile`

```python
from dnsid.c2sp_tlog import parse_c2sp_tlog_trust_profile
```

```python
parse_c2sp_tlog_trust_profile(data: bytes) -> C2spTlogTrustProfile
```

Parse and validate a ``dnsid-c2sp-tlog-trust-profile@v1`` document.

## `parse_checkpoint`

```python
from dnsid.c2sp_tlog import parse_checkpoint
```

```python
parse_checkpoint(text: str) -> Checkpoint
```

Parse a signed-note checkpoint into its body and signature lines.

## `parse_entry_bundle`

```python
from dnsid.c2sp_tlog import parse_entry_bundle
```

```python
parse_entry_bundle(data: bytes) -> list[bytes]
```

Decode a bundle of big-endian uint16-length-prefixed entries.

**Returns:**

- `list[bytes]` — The entry byte strings in bundle order.

**Raises:**

- `C2spTlogParseError`: If a length prefix or entry is truncated.

## `parse_json_no_duplicate_members`

```python
from dnsid.c2sp_tlog import parse_json_no_duplicate_members
```

```python
parse_json_no_duplicate_members(data: bytes) -> Any
```

Parse JSON, rejecting duplicate object member names.

## `parse_note_signature`

```python
from dnsid.c2sp_tlog import parse_note_signature
```

```python
parse_note_signature(line: str) -> NoteSignature
```

Parse one "— name base64" signed-note signature line.

## `parse_prepared_event`

```python
from dnsid.c2sp_tlog import parse_prepared_event
```

```python
parse_prepared_event(data: bytes, lr: str, context: C2spVerificationContext | None = None) -> PreparedC2spTlogEvent
```

Parse prepared bytes received from another process as untrusted input.

Requires canonical JCS with no duplicate members, validates the envelope
and its signed context against *lr*, preserves unknown signed fields, and
validates every signature already present before the result may be given
another signature.  For roles whose key is not embedded in the envelope,
the corresponding trusted key must be supplied via *context*; a signature
whose key cannot be resolved fails closed.

## `parse_signed_note_verifier_key`

```python
from dnsid.c2sp_tlog import parse_signed_note_verifier_key
```

```python
parse_signed_note_verifier_key(text: str) -> SignedNoteKey
```

Parse a signed-note verifier key from its text form.

Accepts the C2SP ``name+hexid+base64`` form as well as the ``name base64``
and ``name ed25519 base64`` forms.  The base64 key material is either a
bare 32-byte Ed25519 key or a signature-type byte followed by the key.

**Raises:**

- `C2spTlogParseError`: If the text matches none of the supported forms, the key ID is not four bytes, or the key material is invalid.

## `parse_tlog_proof_v1`

```python
from dnsid.c2sp_tlog import parse_tlog_proof_v1
```

```python
parse_tlog_proof_v1(text: str) -> TlogProofV1
```

Parse the tlog-proof@v1 text format (header + inclusion hashes + checkpoint).

## `prepare_event`

```python
from dnsid.c2sp_tlog import prepare_event
```

```python
prepare_event(event: AnyLogEvent, lr: str, chain: C2spChain | None = None) -> PreparedC2spTlogEvent
```

Build the unsigned prepared form of *event* bound to *lr*.

Any signatures already on *event* are discarded: they cannot be proven to
cover the resulting envelope.  Preparation requires no private key.  For
every scope, ISSUANCE (and inbound MIGRATION) genesis derives ``seq=0``
and rejects prior-chain fields; every later event requires *chain*.

## `register_c2sp_tlog`

```python
from dnsid.c2sp_tlog import register_c2sp_tlog
```

```python
register_c2sp_tlog(registry: LogRegistry, options: C2spTlogReaderOptions) -> None
```

Register the c2sp-tlog reader factory on *registry*.

## `required_c2sp_signature_names`

```python
from dnsid.c2sp_tlog import required_c2sp_signature_names
```

```python
required_c2sp_signature_names(type_: str) -> list[str]
```

Return the sigs member names a complete entry of *type_* must carry.

## `required_signer_roles`

```python
from dnsid.c2sp_tlog import required_signer_roles
```

```python
required_signer_roles(event_type: str) -> list[C2spSignerRole]
```

Return the signer roles a complete entry of *event_type* must carry.

## `sign_prepared_event`

```python
from dnsid.c2sp_tlog import sign_prepared_event
```

```python
sign_prepared_event(prepared: PreparedC2spTlogEvent, role: C2spSignerRole, key_provider: KeyProvider, context: C2spVerificationContext | None = None, replace_existing: bool = False) -> PreparedC2spTlogEvent
```

Sign *prepared* for *role* and return a new prepared event.

The provider's key for the role's kid must match the key the envelope (or
trusted *context*) requires for *role* by kid, alg, and RFC 7638
thumbprint.  Only the requested signature is added; an existing signature
for the role is never replaced unless *replace_existing* is set.

## `signed_c2sp_entry_bytes`

```python
from dnsid.c2sp_tlog import signed_c2sp_entry_bytes
```

```python
signed_c2sp_entry_bytes(data: bytes) -> bytes
```

Return the signed byte form of a stored entry: the envelope minus sigs.

## `signed_c2sp_event_bytes`

```python
from dnsid.c2sp_tlog import signed_c2sp_event_bytes
```

```python
signed_c2sp_event_bytes(event: AnyLogEvent, context: C2spEventContext | None = None) -> bytes
```

Canonical byte form of *event* that signatures cover (no sigs member).

## `state_hash`

```python
from dnsid.c2sp_tlog import state_hash
```

```python
state_hash(state: object) -> str
```

Hash of the post-event lifecycle state, used by prev_state_hash chaining.

## `tile_path`

```python
from dnsid.c2sp_tlog import tile_path
```

```python
tile_path(prefix: str, level: int, n: int, width: int | None = None) -> str
```

Return the C2SP tlog-tiles fetch path for hash tile *n* at *level*.

A partial tile (one not yet full) is addressed by passing its *width*,
which appends the ``.p/<width>`` suffix defined by the tlog-tiles spec.

## `verified_cosignature_timestamp`

```python
from dnsid.c2sp_tlog import verified_cosignature_timestamp
```

```python
verified_cosignature_timestamp(checkpoint: Checkpoint, key: SignedNoteKey) -> int | None
```

Return the verified cosignature/v1 timestamp (epoch seconds) under *key*.

Returns None if *key* is not a cosignature/v1 key (signature type 0x04) or
the checkpoint carries no valid timestamped cosignature from it.

## `verify_c2sp_stream_bundle`

```python
from dnsid.c2sp_tlog import verify_c2sp_stream_bundle
```

```python
verify_c2sp_stream_bundle(data: bytes, options: C2spStreamBundleVerifierOptions) -> VerifiedC2spStreamBundle
```

Parse and verify one canonical ``dnsid-c2sp-stream-bundle@v1``.

Successful return establishes logged lifecycle state through the accepted
checkpoint. It does not establish current protocol status. Migrated bundles
require reader-managed recursive predecessor resolution and are rejected by
this standalone verifier. Invalid, expired, incomplete, or incorrectly
bound evidence fails closed.

## `verify_c2sp_tlog_proof`

```python
from dnsid.c2sp_tlog import verify_c2sp_tlog_proof
```

```python
verify_c2sp_tlog_proof(entry_bytes: bytes, proof: TlogProofV1 | str, policy: C2spTlogPolicy, origin: str | None = None, scope: str = 'testnet', now_ms: float = 0, max_clock_skew_ms: int = 0) -> TlogProofV1
```

Verify an inclusion proof against a policy-authenticated checkpoint.

## `verify_checkpoint_signature`

```python
from dnsid.c2sp_tlog import verify_checkpoint_signature
```

```python
verify_checkpoint_signature(checkpoint: Checkpoint, key: SignedNoteKey) -> bool
```

True if any of the checkpoint's signature lines verifies under *key*.

## `verify_consistency`

```python
from dnsid.c2sp_tlog import verify_consistency
```

```python
verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool
```

Verify an RFC 6962 consistency proof between two checkpoints.

## `verify_inclusion`

```python
from dnsid.c2sp_tlog import verify_inclusion
```

```python
verify_inclusion(entry_bytes: bytes, index: int, tree_size: int, root_hash: bytes, proof: list[bytes]) -> bool
```

True if *entry_bytes* is provably included at *index* under *root_hash*.

## `verify_lifecycle`

```python
from dnsid.c2sp_tlog import verify_lifecycle
```

```python
verify_lifecycle(events: list[VerifiedLifecycleEvent], options: StreamVerifierOptions | None = None) -> None
```

Verify that *events* forms one valid, fully signed lifecycle.

## `verify_logged_event_signature`

```python
from dnsid.c2sp_tlog import verify_logged_event_signature
```

```python
verify_logged_event_signature(item: VerifiedLifecycleEvent, signer_key: JWK) -> None
```

Verify one logged event's primary signature against *signer_key*.

## `verify_note_signature`

```python
from dnsid.c2sp_tlog import verify_note_signature
```

```python
verify_note_signature(message: str, sig: NoteSignature, key: SignedNoteKey) -> bool
```

Verify one signed-note signature line against *key*.

Type 0x01 is a plain Ed25519 signature over the note body.  Type 0x04 is a
cosignature/v1: an 8-byte big-endian timestamp followed by an Ed25519
signature over "cosignature/v1\ntime <t>\n" + body.

## `verify_stream_lifecycle`

```python
from dnsid.c2sp_tlog import verify_stream_lifecycle
```

```python
verify_stream_lifecycle(entries: list[IndexedEntry], domain: str, options: StreamVerifierOptions | None = None) -> list[VerifiedLifecycleEvent]
```

Select and verify the lifecycle entries for *domain* from a full scan.

New payloads require every signer role under their verified predecessor's
historical state. Applied logical IDs deduplicate regardless of signatures
or physical position. Authenticated forks or invalid transitions are fatal.

## `write_prepared_event`

```python
from dnsid.c2sp_tlog import write_prepared_event
```

```python
write_prepared_event(prepared: PreparedC2spTlogEvent, submit: Callable[[bytes, str], int], idempotency_key: str, validate_chain: Callable[[PreparedC2spTlogEvent], None] | None = None, context: C2spVerificationContext | None = None) -> LogRef
```

Validate the complete entry and append it via *submit*.

``submit(entry_bytes, idempotency_key)`` appends the exact bytes and
returns the assigned entry index. Non-genesis events in every scope require a
``validate_chain(prepared)`` callback that checks the chain fields against
authoritative prior stream state.  Returns the final event reference
``{lr}@{index}``.
