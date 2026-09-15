# Security Operations

Operational security details for this repository. For vulnerability reporting, see [SECURITY.md](../SECURITY.md).

## SDK Verification Hardening

Security properties enforced by the SDK's verification path (not configurable off):

- **SSRF guard** — JWKS (`ku`/`ek`) and status (`su`) fetches reject hosts that
  resolve to non-public addresses (loopback, private, link-local ranges); a
  blocked resolution raises a non-transient `VerificationError`. `ku` redirects stay on the pinned host, `ek` redirects stay within the pinned `gi` DNS-label boundary, and `su` may follow host-changing HTTPS redirects.
- **Host pinning** — JWKS fetches are pinned to the host implied by the record
  (`ku` on the agent's domain, `ek` on the governance domain); registry-hosted
  `su` URLs are permitted with the same fetch-time bounds.
- **Draft 01 fail-safe** — `v=dnsid-draft-01` and pre-RFC `v=DNSid1` records require log-binding lifecycle
  verification (bilateral ISSUANCE binding, operational-key continuity).
  Verification without a capable registered log reader fails closed rather
  than skipping the checks. Current non-revocation is operation policy:
  callers gating high-value operations invoke
  `manager.verify_log_evidence(result)`; day-to-day liveness comes from the
  `su` status check.
- **Strict TLS** — all fetches are HTTPS-only with bounded response sizes, and
  the SDK does not relax Python's default certificate validation (including
  `ssl.VERIFY_X509_STRICT` where the runtime enables it) even when a custom CA
  bundle is configured. For `fl=mtls`, the current peer certificate's dNSName
  SAN is checked on every verification call, including identity-cache hits;
  Common Name fallback and partial-label wildcards are not accepted.

## Key Rotation and JWT Overlap

DNSid has two key planes with different rotation behavior:

- **Operational keys (`ku`)** sign application-layer artifacts such as JOSE JWTs,
  JWS payloads, HTTP Message Signatures, and Web Bot Auth tokens. The live
  draft-01 `ku` JWKS published by `IdentityManager.get_key_set()` contains only
  the current operational key.
- **Accountable-entity keys (`ek`)** sign the DNSid TXT record and lifecycle
  events. The live `ek` JWKS published by `IdentityManager.get_entity_key_set()`
  likewise contains only the current entity key.

A JWT or JWS issued before operational-key rotation keeps its original `kid` and
signature. Because the live draft-01 `ku` JWKS exposes one current operational
key, verifiers that fetch identity data after the rotation will no longer find
that old `kid` in the verified JWKS. Treat this as intentional fail-closed
behavior: old application tokens are not guaranteed to verify after the new key
is published, even when their `exp` time has not arrived.

Operator guidance:

1. Keep application-token lifetimes short. The JOSE profile defaults to a
   15-minute maximum token lifetime and 60 seconds of clock skew. Set a shorter
   `JoseConfig.max_lifetime` where the relying-party path can tolerate it.
2. Before a planned operational-key rotation, stop minting long-lived tokens and
   wait at least the maximum issued-token lifetime plus expected clock skew and
   DNS/status cache windows before publishing the new `ku` key.
3. Use `IdentityManager.rotate_operational_key()` for managed rotations when the
   registry/log integration is available. It pauses application signing before
   submission, persists the exact prepared entry bytes and idempotency key,
   activates only after accepted submission, and resumes signing after durable
   local state is written.
4. For emergency key compromise, rotate immediately and revoke or retire the
   identity in the status/lifecycle plane. Do not wait for token overlap to
   drain; preserving compromised tokens is worse than breaking them.

Recommended overlap periods are policy choices, not SDK constants. A reasonable
starting point for production is:

- **Normal rotation:** maximum application-token lifetime + clock skew + maximum
  verifier status freshness window + `_dnsid` DNS TTL/cache-expiry window.
- **Emergency rotation:** no overlap; publish the new key and revoke affected
  status/log state as quickly as the operator can safely do so.

The `ka` TXT-record tag (`IdentityConfig.max_key_age`) lets publishers declare a
maximum operational-key age of `24h`, `7d`, `30d`, or `90d`. Verifiers reject a
key whose lifecycle-log binding timestamp is older than that value. Use this as
an upper bound, then choose an internal rotation interval shorter than the bound
based on token lifetime, incident-response objectives, and the risk of the key
backend. For example, a `ka=30d` deployment should rotate before day 30, not at
or after it.

Retained keys are local provider state, not live protocol publication:

- `LocalKeyProvider` stores `active`, `pending`, and `retained` keys in its JSON
  key store. `activate(kid)` moves the prior active key to retained;
  `supersede(kid)` removes a retained key from the store.
- `AwsKmsKeyProvider` keeps the same lifecycle state in `AwsKmsKeyState`.
  Call `state_snapshot()` and persist it after `generate_key()`, `activate()`,
  or `supersede()`. When `schedule_key_deletion_on_supersede=True`, superseding
  can also schedule KMS deletion using AWS's 7-30 day deletion window.
- Custom KMS/HSM providers should implement the same `KeyProvider` contract:
  `signing_key()` is current, `jwk(kid)` can resolve active/pending/retained
  keys needed by lifecycle operations, and `supersede(kid)` removes a retained
  key only after operator policy says it is no longer needed.

Clean up retained keys only after they are no longer needed for crash recovery,
lifecycle proof verification, audit, rollback, and any out-of-band verifier that
may still be checking artifacts minted before the rotation. The SDK cannot infer
that retention period for an operator.

Revocation and cache behavior:

- `verify_domain()` caches successful verifications in the configured
  `IdentityCache`. Cache expiry is bounded by DNS TXT TTL, the observed `ku`
  and `ek` TLS certificate expiries, and any `ka` key-age limit.
  `VerificationConfig.status_check_interval` is
  a separate status freshness window; with the default zero interval, the SDK
  re-fetches the `su` status endpoint on every call.
- When a cached entry is still fresh, the SDK does not re-fetch DNS, JWKS, or
  status. When the status interval has elapsed, it re-fetches only `su`; a
  non-`ACTIVE` status evicts the cached identity and fails verification.
- Status endpoint revocation is therefore the fastest revocation signal for
  default verifiers. DNS record and JWKS changes are observed when the cached
  identity expires or when callers explicitly call `IdentityManager.evict_domain()`.
- Draft-01 lifecycle-log non-revocation is operation policy. Callers gating
  high-value or irreversible operations should call
  `manager.verify_log_evidence(result)` in addition to the ordinary status
  check and retain the returned evidence.

Cross-references:

- Local key lifecycle: [`LocalKeyProvider`](https://docs.dnsid.ai/reference/py/key-providers/#localkeyprovider)
- AWS KMS-backed lifecycle: [`AwsKmsKeyProvider`](https://docs.dnsid.ai/reference/py/key-providers/#awskmskeyprovider)
- JOSE token lifetime settings: [`JoseConfig`](https://docs.dnsid.ai/reference/py/profile-jose/#joseconfig)
- Managed rotation methods: [`IdentityManager.rotate_operational_key`](https://docs.dnsid.ai/reference/py/core/#rotate_operational_key)

## Production Operational Behavior

### Compatibility and versioning

The SDK currently publishes `dnsid-draft-01` records by default and verifies both
`dnsid-draft-01` and the pre-RFC `DNSid1` selector through the same draft-01
verification path. `SDK_CONFORMANCE` exposes the supported publication and
verification profiles for the installed release. Treat DNSid as an
internet-draft protocol: pin compatible SDK and server/registry versions in
production, check [COMPATIBILITY.md](https://github.com/dnsid-ai/dnsid-py/blob/main/COMPATIBILITY.md) before upgrades, and
run an end-to-end verification against the target registry/log environment
before rolling forward.

### Sync lifecycle and resource ownership

The public API is synchronous. `IdentityManager`, profile verifiers, and
`RegistryClient` methods block the calling thread while they perform DNS, HTTPS,
registry, and log work. The narrow exceptions are helpers that wrap sync work for
convenience: `RegistryClient.async_wait_for_status()` sleeps asynchronously
between synchronous status polls, HTTP Message Signatures can produce an
`httpx.AsyncClient` for outbound signing, and `async_retry_transient()` retries
awaitables.

Reuse `IdentityManager` and profile objects for a process or request pool when
their configuration and dependencies are stable. The default identity cache is
thread-safe and in memory; it is per manager instance and is lost on process
restart. `IdentityManager` clones cached status results before refreshing them,
but key-provider lifecycle mutations such as `generate_key()`, `activate()`, and
`supersede()` are not documented as generally thread-safe. Serialize rotations
and avoid concurrent application signing while the rotation pause hook is active.
If multiple processes need shared cache semantics, inject an `IdentityCache`
implementation that enforces the same expiration rules.

SDK-managed one-shot fetches create and close their own `httpx.Client` objects.
`IdentityManager.create_dnsid_http_client()` and profile methods that return an
`httpx.Client` or `httpx.AsyncClient` transfer lifecycle ownership to the caller;
close them with `close()` / `aclose()` or a context manager.

### HTTP timeouts, retries, and limits

SDK-managed JWKS and status fetches use HTTPS, a 10-second timeout, at most five
redirects, and a 1 MiB response-body cap. DNS-over-HTTPS lookups use a 10-second
timeout and a 64 KiB body cap. Registry client HTTP calls use a 10-second request
timeout unless a polling method's separate `timeout` and `interval` parameters
apply.

The SDK does not automatically retry `verify_domain()`. Transport failures are
reported as `VerificationError` with `transient=True` when retrying may succeed.
Use `retry_transient(lambda: manager.verify_domain(domain))` or your own retry
policy around idempotent verification paths. Defaults are three attempts,
exponential backoff starting at 1 second, a 30-second delay cap, and up to one
second of jitter. Non-transient verification errors propagate immediately.

### DNS lookup and cache behavior

The default resolver uses the system resolver when `TransportConfig.dns_server`
is empty. It uses a specific DNS server for `"host:port"` values and a
provider-style JSON DNS-over-HTTPS query for `http(s)://` values. DoH is limited
to DNSid TXT lookups; SDK-created sync, async, and signed HTTP clients use custom
DNS for `"host:port"` values but use the system resolver when `dns_server` is a
DoH URL. System and standard-DNS paths return `DNSSECState.UNKNOWN`; HTTPS DoH
returns `VALID` only when the response AD bit is set. The SDK does not perform
its own negative DNS cache. NXDOMAIN and NoAnswer return an empty record list
for that call; resolver or OS-level caches may still apply outside the SDK.

Successful identity verifications are cached by domain. The `VerifiedDomain`
expiry is the earliest protocol validity bound: DNS TXT TTL, observed `ku` and
`ek` TLS certificate expiries, and any `ka` key-age limit. With `status_check_interval=0`
(the default), cached identities still expire on those bounds but `verify_domain()`
re-checks `su` each time before returning a cached identity. Call
`IdentityManager.evict_domain(domain)` after operator-driven DNS/JWKS/status
changes when a process must observe the new state before cache expiry.

### Persistent transparency-log trust and recovery

**The default checkpoint store is in memory.** It rejects rollback/forks only
within the lifetime of that store. Restarting loses continuity, even though
signature, witness, and freshness checks still apply. There is no runtime warning
for this default; configure persistent storage explicitly in production.

`SQLiteCheckpointStore` uses Python's standard-library SQLite transactions rather
than a custom file-replacement/locking implementation. It commits trusted state
before returning success, serializing read/verify/advance across threads and
processes. The lock covers the **whole database**, including consistency-proof
fetches in a verification callback, not just one origin. Contention beyond five
seconds fails closed; shard independent origins into separate stores if needed.
Do not re-enter the same store from its verification callback.

Provision a private directory on a persistent **local** filesystem with reliable
SQLite locking and sync behavior. Initialize a new store once, deliberately:

```python
from dnsid.c2sp_tlog import SQLiteCheckpointStore

SQLiteCheckpointStore("/var/lib/my-agent/checkpoints.sqlite3", create=True)
```

`create=True` fails if the file already exists. On every ordinary startup, open
without `create=True`; missing, corrupt, or unsupported state is an error, never
an automatic reset to first contact:

```python
from dnsid.c2sp_tlog import (
    DnsidManagedVerificationOptions,
    SQLiteCheckpointStore,
    create_dnsid_managed_verification_registry,
)

store = SQLiteCheckpointStore("/var/lib/my-agent/checkpoints.sqlite3")
registry = create_dnsid_managed_verification_registry(
    DnsidManagedVerificationOptions(trusted_checkpoint_store=store)
)
# Inject registry into IdentityManagerDependencies(log_registry=registry).
```

Generic verification options also accept `trusted_checkpoint_store=store`; raw
reader and portable bundle options accept `checkpoint_store=store`. No open
connection is retained between operations. Protect the database directory and
SQLite journal files; do not delete journals or copy a live database without
SQLite's backup API. Storage durability depends on the filesystem/hardware
honoring sync. An empty store uses first-contact trust: if that is inappropriate,
seed `put()` with an independently authenticated checkpoint during provisioning.
Do not routinely seed on startup or automatically recreate a lost database.

#### Checkpoint failures

At a reader/`verify_domain` boundary, these are non-transient
`VerificationError(code=VerificationCode.LOG_ERROR)` failures:

| `category` | Observed condition | Action |
| --- | --- | --- |
| `LOG_ROLLBACK` | Smaller tree than previously trusted | Stop acceptance; investigate with operations **and** security |
| `LOG_FORK` | Same size, different root | Stop acceptance; page security |
| `LOG_INCONSISTENT` | Growing tree fails prefix/consistency verification | Stop acceptance; page security |
| `CHECKPOINT_STORE_ERROR` | Missing/corrupt/unavailable storage, failed commit, or stale recovery state | Restore/investigate storage; never fall back to an empty store |

Consistency failures carry a `C2spCheckpointConsistencyError` as `__cause__`, with
`origin`, `trusted_tree_size`, `observed_tree_size`, `trusted_root_hash`, and
`observed_root_hash` (raw bytes; use `.hex()` in incident records). Direct portable
bundle verification raises that typed error itself. Missing consistency evidence
is not proof of a fork: it remains a separate evidence failure and may use the
existing authenticated raw-scan fallback. Neither a rollback category nor a valid
signature proves that a database restore was authorized. A storage commit error
can have an uncertain outcome: reopen and inspect state before retrying.

#### Authorized re-baseline procedure

1. Stop affected verification/signing workflows and coordinate all processes
   sharing the store. Preserve old checkpoints, signed evidence, and a consistent
   database backup in an external incident archive. Restoring an old database
   backup also weakens continuity; do not do that casually.
2. Have the deployment's incident/security owner independently confirm recovery
   through an authenticated operator channel. Demand the affected origin, old/new
   sizes and roots, recovery reason, and an explicit authorization/evidence
   reference. Verify replacement log signatures, witness quorum, and freshness
   against approved trust roots. Do **not** use the failed response alone as
   authorization, and do not invent an SDK-verifiable recovery statement: no such
   platform protocol is implemented here.
3. Review the exact current `TrustedCheckpoint` and construct the independently
   authenticated replacement. Call
   `store.rebaseline(replacement, expected=reviewed_checkpoint,
   authorized_by="incident/security owner", evidence="incident/evidence reference")`
   from a separately authorized operator action, never a verification exception
   handler. `expected` must match the stored checkpoint; concurrent advancement
   aborts the reset and requires review again. Origins must match. `put()` cannot
   lower a tree size and is **not** the recovery operation.
4. The replacement and audit record commit together. The `rebaselines` SQL table
   retains origin, previous/new sizes, roots and witness times, authorizer,
   evidence reference, and UTC recording time. This is an audit trail, not a
   tamper-proof authorization mechanism; keep the independent incident archive.
5. Recreate managers/readers (clearing cached verified identities/history), verify
   the recovered environment end to end, and only then resume service. A reset
   explicitly abandons continuity across the recovery boundary; future forks and
   rollback must still fail closed. Prefer restoring the original append-only
   history over re-baselining whenever possible.

### Proxy, TLS, and trust-store posture

Core SDK-managed DNSid verification uses a custom httpcore transport so it can
resolve the target, apply the SSRF guard, and connect to the checked address.
That transport does not document or expose HTTP proxy configuration and should
not be assumed to honor `HTTP_PROXY`, `HTTPS_PROXY`, SOCKS, or authenticated
proxy settings for JWKS/status verification. Registry and OIDC code paths that
call `httpx` directly use httpx's normal transport behavior unless the caller
supplies a client. SOCKS proxy support depends on installing/configuring httpx's
SOCKS support; it is not included by the base `dnsid` dependency set. If core
verification must traverse a proxy, inject an `HTTPSFetcher` or use caller-owned
`httpx` clients where the profile API accepts them, and preserve the SDK's
host-pinning, HTTPS-only, response-size, and certificate-validation requirements.

TLS verification is enabled for SDK-managed HTTPS. `TransportConfig.ca_bundle_path`
loads an additional CA bundle through Python's default SSL context. The SDK does
not provide first-class client certificate, certificate pinning, FIPS-mode, or
enterprise trust-store switches beyond what the caller can implement by
injecting a transport/fetcher or configuring the underlying Python/OpenSSL
runtime. Do not disable certificate validation for production DNSid verification.

### Logging and error surfaces

The package defines module loggers such as `dnsid.manager`, but the core SDK does
not install handlers or emit routine operational logs. Applications control
logging through Python's standard `logging` configuration; attach handlers to
`dnsid` or its child loggers if you need SDK diagnostics, or leave them unset to
stay quiet.

Common failure mapping:

| Failure | Exception/code |
|---|---|
| DNS timeout, SERVFAIL, DoH transport failure | `VerificationError(DNS_RESOLUTION, transient=True)` |
| NXDOMAIN, NoAnswer, missing or multiple TXT records | `VerificationError(RECORD_INVALID)` after record-count validation |
| DNSSEC validation failure or required validation unavailable | `VerificationError(DNSSEC_FAILED)` |
| Malformed TXT record or invalid tag semantics | `VerificationError(RECORD_INVALID)`; direct parsing helpers may raise `ParseError` or `ValidationError` |
| JWKS TLS/connect/fetch failure | `VerificationError(TLS_ERROR)` or `DNS_RESOLUTION`; transient flag depends on transport cause |
| Status endpoint DNS/connect/TLS/5xx failure | `VerificationError(STATUS_UNAVAILABLE, transient=True)` from `verify_domain()` |
| Status endpoint non-`ACTIVE`, including revoked/retired identities | `VerificationError(STATUS_NOT_ACTIVE)` with `agent_state` when known |
| Invalid JWT/JWS claims, unknown `kid`, bad alg, or bad signature | `VerificationError(RECORD_INVALID)` or `VerificationError(SIGNATURE_INVALID)` |
| Expired JWT | `VerificationError(RECORD_INVALID)` |
| Registry transport or server failure | `VerificationError(LOG_ERROR)`, usually transient for 5xx/transport failures |

### Operational limits

- Draft-01 live `ek` and `ku` JWKS documents must each expose exactly one current
  signing key with a `kid` and supported algorithm binding.
- SDK-managed JWKS/status responses larger than 1 MiB fail closed.
- DNS-over-HTTPS JSON responses larger than 64 KiB fail closed.
- Default verification state is process-local. Multi-instance deployments should
  assume each process has its own cache unless an explicit shared cache is
  injected.
- `TransportConfig.private_address_hosts` permits non-public resolution only
  for configured hostnames: exact entries, or leading-dot entries
  (`".dnsid.test"`) that cover one domain and every name beneath it. Keep it
  empty unless an intended private service or testnet zone requires access.

## Static Analysis (SAST) & Code Scanning

CodeQL scans this repository using GitHub's [code scanning default setup](https://docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning),
covering Python and GitHub Actions on every push and pull request to `main` plus a
weekly scheduled scan. Results appear under the repository's **Security → Code scanning** tab.

Triage expectations:

- **Critical / High** findings block release and are remediated (fix or documented,
  justified dismissal) before the next tagged version.
- **Medium / Low** findings are tracked as issues and addressed on a best-effort basis.

## Secret Scanning

GitHub [secret scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
and push protection are enabled for this repository. If a secret is detected or leaked:

1. **Rotate immediately** — revoke and reissue the affected credential at its source.
2. **Revoke** the exposed value so it can no longer be used, even after removal from history.
3. **Audit** access logs for the affected system for signs of misuse.

Removing a secret from git history does **not** count as remediation — assume any
committed secret is compromised and rotate it.

## Software Bill of Materials (SBOM)

Dependencies are tracked via the GitHub [Dependency Graph](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph)
and kept current by [Dependabot](.github/dependabot.yml) (pip + GitHub Actions).

An SBOM can be generated on demand:

- **GitHub UI/API**: export from the repository's dependency graph
  (`GET /repos/{owner}/{repo}/dependency-graph/sbom`, SPDX JSON).
- **Syft** (source or built artifact): `syft dir:. -o spdx-json` or `syft <package>`.

## Monitoring

- `main` is protected: direct pushes are blocked and merges require a passing CI run
  (lint, type check, tests) and CodeQL.
- Pull requests require review approval before merge.
- Dependabot and CodeQL alerts are reviewed as they arrive; Critical/High are actioned
  promptly (see above).
- The organization audit log is reviewed periodically for anomalous activity
  (permission changes, new deploy keys/tokens, force pushes).
