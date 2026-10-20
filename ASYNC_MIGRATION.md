# Async migration

Branch: `migration/async-verification`.

Core identity verification and refresh, HTTP-signature verification, and
registry HTTP operations have native async entry points. Synchronous APIs remain available.
No runtime dependencies were added.

## Completed

### Verification

- [x] Add `IdentityManager.async_verify_domain()` and
      `HttpSignatureProfile.async_verify_signed_http_request()`.
- [x] Await native TXT, A/AAAA, JWKS, status, and SSRF-safe HTTPS reads.
- [x] Await C2SP scans, stream bundles, tiles, and recursive predecessor reads
      through the shared lifecycle verifier.
- [x] Share evidence futures across sync and async callers without a worker
      per waiter. Preserve independent caller deadlines, cancellation isolation,
      deterministic error precedence, zero-TTL behavior, and per-caller policy.
- [x] Keep fresh cache hits and default stale-status refreshes on the event loop.
- [x] Add `IdentityManager.async_refresh_domain()` with full HTTP revalidation,
      sync/async refresh coordination, zero-TTL isolation, per-caller policy,
      independent cancellation, and shutdown draining.
- [x] Support optional async DNS, HTTPS, and log capabilities while retaining
      worker fallback for synchronous injected dependencies.
- [x] Drain background verification and tracked workers through manager
      `aclose()` / `async with`.
- [x] Preserve main's DNS absence/error classification, HTTP revalidation rules,
      refresh coordination, and checkpoint continuity contracts.

### Registry I/O

- [x] Add `async_` variants for all registry HTTP operations: registration,
      verification, challenge/proof submission, lifecycle transitions, status
      and management reads, publication, and prepared-event operations.
- [x] Share request validation, response parsing, credential redaction,
      idempotency metadata, and indeterminate submission handling with sync APIs.
- [x] Make `async_wait_for_status()` await native HTTP rather than fetch status
      synchronously on the event loop.
- [x] Pool native async registry connections with SSRF protection, effective
      DNS/TLS settings, no redirects, and bounded decoded response bodies.
- [x] Add registry `aclose()` / `async with`; retain synchronous cleanup.
- [x] Migrate A2A's direct registry calls and registry context cleanup.
      Its manager-level publication workflow still uses a worker.

### Applications and checks

- [x] Migrate A2A middleware, peer verification, and startup self-verification.
- [x] Offload synchronous signing, including KMS, in signed async HTTP clients
      and the A2A example. Support caller-selected outbound transports.
- [x] Add bounded A2A reads, retry-aware responses, and failure-path cleanup.
- [x] Add an async verification example and update usage/API references.
- [x] Cover sync/async parity, local DNS/TLS and registry HTTP, authentication,
      response limits, cancellation, deadlines, pool ownership, and shutdown.

## Remaining, in dependency order

- [ ] Add async JOSE JWT/JWS verification, legacy bot bearer authentication,
      and OIDC entry points. OIDC discovery and token exchange need async HTTP.
      Files: `dnsid/jose.py`, `web_bot_auth.py`, `oidc.py`.
- [ ] Add native async `WBAHttpVerifier` verification, including directory
      discovery, timing checks, and rotation refresh. This is separate from
      the legacy JWT bearer profile in `web_bot_auth.py`.
- [ ] Migrate manager-level publication, managed-publication waits, rotation,
      and log read/write workflows. Registry HTTP primitives are now ready;
      A2A publication still offloads `publish_to_registry()` as one operation.
- [ ] Add async key-provider signing where remote providers support it.
      Keep worker fallback for synchronous KMS/HSM providers; local cryptographic
      calculations do not need an async rewrite.
- [ ] Benchmark warm/cold throughput, loop latency, and worker usage with real
      DNS, HTTPS, KMS, cancellation, and shutdown under load. Use the results to
      decide whether verification HTTP reads also need connection pooling.

## Current limits

- Async-led verification uses native adapters. Sync-only adapters and atomic
  checkpoint-store operations use tracked workers. Atomic checkpoint work and
  C2SP fallback adapters share a process-owned bounded pool; managers drain
  their own tracked futures without closing that shared pool. The SDK supplies
  only an in-memory checkpoint store; durable stores are deployment-provided.
- Explicit refreshes revalidate key-set and status HTTP resources and wait for
  older cold lookups before acquiring their own evidence. Concurrent explicit
  refreshes share work; ordinary lookups join an ongoing refresh. DNS caches
  may return answers with their remaining TTL. Async C2SP reads require HTTP
  revalidation, matching synchronous reads.
- Mixed sync/async verification shares whichever evidence leader starts first.
  Sync-led evidence still uses synchronous adapters in workers. Shared evidence
  has an independent 30-second budget; caller cancellation stops only its wait.
- Injected verification adapters still need synchronous methods. Their async
  resources remain caller-owned and must support the application's event loops.
  Injected identity caches must be nonblocking and dependencies thread-safe.
- Default verification HTTP reads own a client per read; registry async calls
  reuse a separate connection pool on one event loop. Reuse registry clients,
  finish outstanding requests, then use `async with` or `await client.aclose()`.
  In mixed use, `aclose()` also offloads closing the synchronous registry pool.
- Registry cancellation stops the local request, not an operation already
  accepted by the server. No automatic mutation retries are added. Reconcile
  the result and retain the same request and idempotency key for safe retries.
- Other profile and manager lifecycle APIs remain synchronous. Use workers
  where needed until those workflows are migrated.

External registry/KMS integration, a running A2A server, and load benchmarks have
not been checked. Automated tests cover local transports and mocked registry
workflows, not production service behavior.
