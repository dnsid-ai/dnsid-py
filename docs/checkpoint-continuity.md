# Checkpoint continuity implementation checks

## Storage scope

The SDK supplies only `InMemoryCheckpointStore`, matching the Go and TypeScript
SDKs. The `CheckpointStore` interface remains available for deployment-provided
storage. There is no built-in durable adapter or administrative recovery API.

Remembered trust lasts only as long as the same store instance. Restarting or
recreating a registry/store loses that trust, even within the same process.
Independent signature, witness, and freshness checks still apply, but they do
not restore the lost continuity baseline.

## Verification behavior

- Reader scans and bundle fallback share one candidate-prefix validator. Missing,
  duplicate, non-integer or negative indexes and candidate-root mismatches are
  `INVALID_EVIDENCE`, before checking the trusted prefix. A valid contradictory
  prefix remains `LOG_INCONSISTENT`.
- Malformed supplied consistency proofs reject as inconsistent evidence rather
  than leaking a type error. Empty-tree proofs are checked explicitly. Missing
  capability has the machine-readable `condition="consistency_unavailable"`.
  Only lower-level custom readers without a proof source or tile capability may
  scan for missing consistency evidence, in preferred-bundle mode only.
- Standard network readers use candidate-authenticated C2SP hash tiles for growing
  checkpoints in both preferred- and required-bundle modes. Already verified scans
  take precedence over explicit proof sources, which take precedence over tiles.
  Neither proof-source nor tile failures permit a scan or another evidence source.
- Tile reads use at most two tiles per level of the candidate tree. Missing partial
  tiles (HTTP 404 or 403) get one full-tile retry, with no checkpoint refresh. Exact
  lengths and candidate authentication precede trusted-root comparison: bad tiles
  are `INVALID_EVIDENCE`; authenticated contradictory prefixes are `LOG_INCONSISTENT`.
  Tile reads share cancellation and the overall budget, not the entry-byte cap.
- Size-zero checkpoints must use SHA-256 of the empty string. Invalid candidates
  are `INVALID_EVIDENCE`; invalid stored roots are `CHECKPOINT_STORE_ERROR`.
- The memory store validates inputs and retains immutable UTC snapshots. Seeding
  cannot overwrite an equal-size conflicting root. Diagnostic roots are immutable
  byte strings.
- Verification and advancement run under the same per-origin lock against the
  exact current tuple. Conflicting extensions cannot both replace the same state.
- Lock waits and publication check the shared verification budget. Pre-publication
  cancellation does not leave a background write queued.
- Typed rollback, fork, inconsistency, and storage errors cross reader wrappers
  through `VerificationError.category` and its typed `__cause__`. Storage failure
  never authorizes substituting empty trust.
- Generic and managed factories share code-injected stores. Configuration loaders
  preserve injected registries, reject checkpoint-storage file members, and ignore
  unknown environment variables rather than treating them as persistence settings.

## Native regression coverage

Tests exercise signed public readers and portable-bundle verification,
IdentityManager rollback/fork propagation with injected discovery transports,
conflicting concurrent readers, input validation, immutable snapshots,
cancellation, budget expiry, and canceled lock waits. Injected storage failures
exercise both pre-publication failure and failure after publication; later
verification reloads actual state instead of assuming a failed acknowledgment
restored the previous checkpoint. Generic and managed registry/store injection
and loader rejection remain tested.

The shared signed checkpoint vectors use in-memory stores. They do not establish
durable-storage, crash, cross-process locking, or administrative-recovery guarantees.

## Validation

After implementing hash-tile checkpoint consistency:

- `.venv/bin/pytest -q`: **2,640 passed**, eight expected local-key safety warnings.
- `.venv/bin/pytest -q tests/test_c2sp_hash_tiles.py tests/test_c2sp_tile_continuity.py`:
  **94 passed**, covering tile geometry, authentication, retries, source selection,
  bundle modes, empty roots, exact-state race checks, cancellation, and deadlines.
- `.venv/bin/ruff check .`: passed.
- `.venv/bin/mypy dnsid`: passed, 51 source files.
- `.venv/bin/python scripts/gen_docs.py`: regenerated API reference.

The cross-SDK compliance harness and live interoperability were not rerun.

## Deployment-owned persistence and recovery

Applications requiring cross-restart rollback protection implement and inject a
durable `CheckpointStore`. Such adapters must preserve the same validation,
snapshot isolation, atomic verification/advancement, and cancellation contract,
explicitly initialize new namespaces, fail closed on lost or corrupt existing
state, and acknowledge success only after durable commit. Deployment-specific
crash, contention, corruption, and uncertain-commit tests are required.

Recovery authorization, fencing across deployments, signed-evidence archival,
backup rollback detection, cache invalidation, and fresh lifecycle verification
remain deployment responsibilities. A storage write failure may occur after
publication; reconcile actual state before recovery. Never delete trust or
replace it with an empty store to bypass a continuity failure. See
[security operations](security.md#authorized-re-baseline-procedure) for the
deployment-owned recovery procedure.
