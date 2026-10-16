# Checkpoint continuity implementation checks

## Revisions and authority

- SDK baseline: `ccf3d1b889b464b7259d6d1dfccc3992f160afb2`.
- Compliance checkout: `cc4605597442f6177c05c3083ef73418ef170bba`.
- Implementation and checks include the uncommitted SDK changes on that baseline.
- Authority: the checked-out compliance design documents
  `docs/sdk-design/11-c2sp-tlog-binding.md`, `12-configuration-loading.md`, and
  `conformance/README.md`. No default-branch documents or shared expectations were substituted.

## Existing behavior retained

Typed rollback, equal-size fork, inconsistency and storage errors already crossed
reader wrappers through `VerificationError.category` and its typed `__cause__`.
Verification callbacks already serialized continuity and advancement against the
exact current tuple, without a split load/write. Bundle fallback caught only the
missing-consistency condition, not invalid supplied proofs or retrieval failures.
Generic and managed factories already shared code-injected stores; configuration
loaders already rejected unknown file members and ignored unknown environment variables.

## Corrections

- Reader scans and bundle fallback share one candidate-prefix validator. Missing,
  duplicate, non-integer or negative indexes and candidate-root mismatches are
  `INVALID_EVIDENCE`, before checking the trusted prefix. A valid contradictory
  prefix remains `LOG_INCONSISTENT`.
- Malformed supplied consistency proofs reject as inconsistent evidence rather
  than leaking a type error. Empty-tree proofs are checked explicitly. Missing
  capability has the machine-readable `condition="consistency_unavailable"`.
- Memory and SQLite stores share validation and immutable UTC snapshots. Memory
  seeding no longer overwrites an equal-size conflicting root. Diagnostic roots
  are immutable byte strings.
- Both stores check the verification budget while waiting and before publication.
  SQLite also checks after staging writes. No background write is abandoned.
- SQLite schema 2 retains a separate origin inventory, validates existing records
  and database integrity, and rejects missing components instead of treating them
  as first contact. Opening schema 1 fails without modifying it; no automatic
  upgrade or empty-store replacement is provided.
- SQLite commit-acknowledgment errors report an indeterminate outcome and attempt
  read-back. Both the original cause and a failed reconciliation remain inspectable.
- Administrative replacement retains exact-state preconditions and transactional
  audit records, now requires read-back before success, and documents external
  authorization/evidence requirements. It never reloads and retries stale approval.

## Executed checks

- `.venv/bin/pytest -q`: **1,915 passed**, eight expected local-key safety warnings.
- `.venv/bin/ruff check .`: passed.
- `.venv/bin/mypy dnsid`: passed, 48 source files.
- `.venv/bin/python scripts/gen_docs.py`: regenerated API reference.
- Single-SDK compliance entrypoint with exported `SDK_ID=py` and
  `SDK_DIR=/Users/benjamin.guidarelli/dnsid-py`:
  `ci/run-one.sh "$SDK_ID" "$SDK_DIR" /tmp/checkpoint-compliance.md`.
  Report inspected: **347 PASS, 11 REJ, no FAIL, XFAIL or MISSING** across 358 cases.
  Checkpoint continuity: **15/15**, including one XPASS.
  The entrypoint also checked fixture reproducibility and 33 event-identity checks;
  its unit phase ran 40 tests with four skips (three all-SDK checkpoint-adapter
  self-checks and the Go-only core-refresh test).

Native regressions exercise signed public readers and portable-bundle verification,
IdentityManager rollback/fork propagation with injected discovery transports,
conflicting concurrent readers, memory/SQLite validation, cancellation and budget
expiry, staged-write rollback, uncertain commit/read-back failures, thread/process
contention, process death before and after commit, corruption, missing trust,
explicit initialization, stale witnessed-time recovery approval and audit retention.
Race tests use barriers/events rather than sleeps to schedule competing verifiers.
Generic/managed durable-store injection and loader rejection are also tested.

## Coordination and limits

The Python marker for `checkpoint-scan-missing-leaf` is stale. Remove its entry
from `harness/generate_c2sp_fixtures.py` (`bugs["scan-missing-leaf"]["py"]`), then
regenerate `fixtures/c2sp-checkpoint-continuity.yaml` in a coordinated compliance
change. Neither shared file was changed here.

Use a protected local filesystem with working SQLite locks and sync semantics.
Native fault injection and process termination are not physical power-loss or
filesystem certification. SQLite commits cannot be interrupted cooperatively:
late cancellation can report failure after a known successful publication. Read
back trust before resuming; never assume failure restored the old checkpoint.
If reconciliation also fails, leave consumers fenced until storage can be read.

Recovery authorization, fencing across deployments, signed-evidence archival,
backup rollback detection, cache invalidation and fresh lifecycle verification
remain deployment responsibilities, not authenticated by SDK audit arguments.
Schema-1 stores need a fenced, reviewed transition to a separately initialized
namespace; retain the old namespace and evidence. Never delete trust to obtain
first-contact behavior. New in-memory store instances also lose remembered trust,
even within the same process.

No live interoperability, hardware durability, all-SDK matrix or complete
IdentityManager failure-matrix claim is made. Shared checkpoint vectors alone do
not establish cancellation, durable-storage, concurrency or recovery coverage.
