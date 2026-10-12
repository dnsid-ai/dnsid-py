# Async migration

Branch: `migration/async-verification`.

This is a staged migration. The HTTP verification hot path supports async
callers. Native async evidence fetching is not yet implemented.

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
- [x] Run tests (1,506 passed), Ruff, mypy and diff checks.

## Remaining, in dependency order

- [ ] Define async DNS, HTTPS and log adapter contracts while retaining sync injection.
      Files: `dnsid/interfaces.py`, `dnsid/manager.py`.
- [ ] Implement native async TXT lookup and SSRF-safe HTTP reads.
      Files: `dnsid/_default_resolver.py`, `dnsid/_https_client.py`,
      `dnsid/safe_transport.py`. Preserve DNSSEC state, address pinning,
      redirect rules, response byte limits, TLS identity and verification deadlines.
- [ ] Use native async custom DNS routing in `dnsid/manager.py`.
      The existing async HTTP transport still calls synchronous `_resolve_a()`.
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

Cold verification and stale-status refreshes run synchronous evidence adapters
in a shared worker. Cancellation stops the caller's wait, not that worker.
Do not close the manager until active evidence work has finished. Injected
identity caches must be nonblocking to keep cache hits off workers.

Other profile and registry APIs remain synchronous. No dependencies were added.
Live network/KMS integration, the A2A server and load benchmarks were not run.
