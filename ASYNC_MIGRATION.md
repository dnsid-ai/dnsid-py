# Async migration

Branch: `migration/async-verification`.

This is a staged migration. The HTTP verification hot path and default stale-status
refreshes support async callers without worker threads. Cold identity evidence
fetching still uses workers.

## Completed

- [x] Add `IdentityManager.async_verify_domain()`.
- [x] Keep fresh cache hits and per-caller mTLS/acceptance checks on the event loop.
- [x] Await shared evidence futures instead of occupying a worker per waiter.
- [x] Share evidence work across synchronous and asynchronous callers.
- [x] Preserve caller deadlines, cancellation isolation, error codes and zero-TTL behavior.
- [x] Add `AsyncIdentityResolver` and async HTTP signature verification.
- [x] Share HTTP parsing, digest, freshness and signature validation with the sync API.
- [x] Migrate A2A middleware, peer verification and startup self-verification.
- [x] Offload synchronous signing in the signed async HTTP client, including KMS calls.
- [x] Add regression tests and update README usage.
- [x] Run regression tests, Ruff, mypy and diff checks.
- [x] Add native async A/AAAA resolution and SSRF-safe HTTP transport.
- [x] Use native async status reads for shared stale-status refreshes.
- [x] Preserve injected synchronous HTTPS fetchers through the worker fallback.
- [x] Use native async custom DNS routing in signed async HTTP clients.
- [x] Isolate shared evidence budgets from sync and async callers; expose DEADLINE_EXCEEDED.
- [x] Add async manager cleanup that drains shared work and unfinished worker branches.
- [x] Allow custom outbound transports in signed async clients, with explicit ownership.
- [x] Add bounded A2A reads, retry-aware responses, KMS offload, and failure-path cleanup.
- [x] Add a runnable async verification example and async quickstart.
- [x] Define optional async DNS, HTTPS and log adapter contracts while retaining sync injection.
- [x] Await async-capable injected HTTPS fetchers for stale-status refreshes.
- [x] Implement native async TXT lookup (system DNS, configured DNS and JSON DoH).
- [x] Implement native async key-set reads with shared parsing, TLS identity,
      redirect rules, SSRF protection, byte limits and verification deadlines.

## Remaining, in dependency order

- [ ] Implement async C2SP resource fetching and log verification.
      Files: `dnsid/c2sp_tlog/resource_fetcher.py`, `reader.py`,
      `stream_bundle.py`. Preserve checkpoint atomicity and rollback protection;
      SQLite and custom stores must not block the event loop.
- [ ] Replace the evidence leader worker with native async orchestration.
      File: `dnsid/manager.py`. Preserve post-signature fanout, deterministic
      failure precedence, shared futures and per-caller policy checks.
- [ ] Add async JOSE, WebBotAuth and OIDC entry points.
      Files: `dnsid/jose.py`, `web_bot_auth.py`, `oidc.py`.
      Preserve synchronous APIs and all claim/signature validation.
- [ ] Add async registry HTTP operations and remove synchronous status fetches
      from `RegistryClient.async_wait_for_status()`.
      File: `dnsid/registry_client.py`; then migrate remaining A2A startup calls.
- [ ] Define async signing support for key providers where available.
      Keep worker fallback for synchronous KMS/HSM providers.
- [ ] Update API reference documentation and examples for native async adapters.
- [ ] Benchmark warm/cold middleware throughput, loop latency and worker usage.
      Exercise real DNS, HTTPS, KMS, cancellation and shutdown under load.

## Current limits

Cold verification and injected synchronous HTTPS fetchers still use shared workers.
Async-capable injected HTTPS fetchers are awaited for stale-status refreshes.
Native async TXT and JWKS helpers are implemented but not yet used by cold
verification. Async log capabilities are defined; their implementations remain
synchronous.
Injected adapters must retain their synchronous methods; async-only injection is
not supported. Injected async resources remain caller-owned and must support
concurrent calls on the application's event loops.
Default stale-status refreshes use native async DNS and HTTPS. Each shared refresh
owns and closes one async HTTP client; connections are not pooled across refreshes.
Shared evidence has a separate 30-second budget. Caller deadlines or cancellation
stop only that caller's wait. Use `async with manager` or `await manager.aclose()`
to drain work before closing resources. Synchronous `close()` also drains work,
but rejects blocking an event loop. Injected blocking adapters must honor budgets;
identity caches must be nonblocking and all injected dependencies thread-safe.

Other profile and registry APIs remain synchronous. No runtime dependencies were added.
Local UDP DNS and TLS are covered by automated tests. External network/KMS
integration, the A2A server and load benchmarks were not run.
