# Python Runtime and Dependency Compatibility Matrix

This document describes the supported Python versions, dependency version ranges,
and platform support for the `dnsid` Python SDK.

## Python Version Support

| Python Version | Status |
|---|---|
| 3.11 | ✅ Supported, tested in CI |
| 3.12 | ✅ Supported, tested in CI |
| 3.13 | ✅ Supported, tested in CI |
| < 3.11 | ❌ Not supported |

**Minimum required:** Python ≥ 3.11 (declared in `pyproject.toml` via `requires-python = ">=3.11"`).

The CI matrix currently validates against **Python 3.11, 3.12, and 3.13** on **Ubuntu (latest)**.

## Core Runtime Dependencies

These are installed automatically with `pip install dnsid`:

| Package | Required Version | Purpose |
|---|---|---|
| [idna](https://pypi.org/project/idna/) | ≥ 3.6 | IDNA A-label normalisation (`normalize_fqdn`) |
| [httpx](https://pypi.org/project/httpx/) | ≥ 0.27 | HTTP client for JWKS, status endpoint fetches, and DoH queries |
| [dnspython](https://pypi.org/project/dnspython/) | ≥ 2.6 | System DNS resolver (TXT record lookup with DNSSEC awareness) |
| [cryptography](https://pypi.org/project/cryptography/) | ≥ 42.0 | JWK thumbprint, ECDSA/EdDSA signature verification and signing |

## Optional Dependencies

### `aws` extra (`pip install "dnsid[aws]"`)

| Package | Required Version | Purpose |
|---|---|---|
| [boto3](https://pypi.org/project/boto3/) | ≥ 1.34 | AWS KMS-backed signing key provider |

### `dev` extra (`pip install "dnsid[dev]"`)

| Package | Required Version | Purpose |
|---|---|---|
| [pytest](https://pypi.org/project/pytest/) | ≥ 8.0 | Test framework |
| [pytest-asyncio](https://pypi.org/project/pytest-asyncio/) | ≥ 0.23 | Async test support |
| [ruff](https://pypi.org/project/ruff/) | ≥ 0.4 | Linter and formatter |
| [mypy](https://pypi.org/project/mypy/) | ≥ 1.10 | Static type checker |

## Platform Support

| Platform | Architecture | Status |
|---|---|---|
| Linux (Ubuntu) | x86_64 | ✅ Tested in CI |
| macOS | x86_64 / arm64 | ✅ Supported (not currently in CI matrix) |
| Windows | x86_64 | ⚠️ Expected to work but not tested in CI |

The SDK is pure Python with no platform-specific native code. Platform compatibility
is primarily determined by the `cryptography` package's binary wheel availability.
See [cryptography's installation docs](https://cryptography.io/en/latest/installation/)
for platform-specific details.

## Compliance update: `5e5c783`

Reviewed the committed `astra-review` changes in `dnsid-sdk-compliance`.
This SDK update covers absolute DNS expiry, zero-TTL non-reuse, return-time
TLS/key-age/DNS checks, manager-private injected cache namespaces, snapshotted
protocol/transport configuration, strict JOSE/OIDC decoding and NumericDates,
expiration rechecks, and explicit JWT audiences without local identity setup.
HTTP, JOSE and OIDC already forward current-peer certificates and retain
caller-owned `logchk` policy.

Injected resolver, fetcher, and log-registry trust configuration must remain
immutable for the manager's lifetime. Construct a new manager when changing
trust or policy; mutating returned configuration copies does not reconfigure it.
Shared cache backends receive opaque manager-prefixed keys, not bare domains.

Standalone JOSE/OIDC verification rejects compact tokens over 1 MiB and encoded
protected headers over 16 KiB before JSON parsing. HTTP signature verification
rejects combined Signature/Signature-Input values over 64 KiB, Content-Digest
over 16 KiB, more than 16 labels per dictionary, more than 64 components per
label, or bodies over 8 MiB. HTTP hosts must enforce body/header limits while
reading, before constructing the already-buffered `HttpRequest`; the SDK rejects
oversized buffered inputs before hashing or discovery. These are rejection
limits, never candidate truncation.

### Breaking C2SP wire correction

All scopes now require signed method/origin/stream/reference context and logical
chains. `C2spChain.previous_event_id` replaces physical predecessor index and leaf
hash fields. Genesis uses `seq=0`; successors require `prev_event_id` and
`prev_state_hash`. Top-level `event_id`, `prev_index`, and `prev_leaf_hash` are
prohibited. Use `dnsid.c2sp_tlog.c2sp_event_id(entry_bytes)` to derive the logical
ID; it excludes signatures but preserves unknown signed fields. Leaf hashes
still cover the exact complete entry bytes.

Readers reject bare-FQDN stream IDs and unchained verification. Old unbound or
physical-chain entries cannot be silently upgraded: use newly signed,
identity-instance streams. Generic canonicalization supports ISSUANCE only;
later events require the prepared API and authoritative chain validation in
all scopes. Re-signed copies apply once, invalid signatures cannot reserve an
ID, and authenticated historical-key forks/duplicate genesis/post-terminal
transitions fail closed. Direct reads and migration cutoffs authenticate the
exact occurrence, including every required signature. All supplied bundle
proofs are checked even for ignored candidates. Signed bundle fixtures have
been regenerated; primitive hashes match the committed compliance vectors.

Lifecycle selection defaults to at most 100,000 supplied entries and 64 MiB of
entry bytes, including ignored copies. Advanced `StreamVerifierOptions` callers
can configure those limits. Existing scan and recursive migration limits still
apply independently.

### Overall verification budget

Verification entry points share a default **30-second monotonic budget** across
DNS, HTTPS, candidate processing, recursive C2SP verification, and coalescing
waits. Override it around the outer call:

```python
import threading
from dnsid import verification_budget

cancelled = threading.Event()  # another thread may call cancelled.set()
with verification_budget(15.0, cancelled=cancelled):
    identity = manager.verify_domain("agent.example")
```

Nested calls cannot extend the deadline. A timed-out waiter does not cancel
another caller's shared verification. No background worker is spawned to leave
abandoned network work running. SDK-managed DNS and socket/TLS operations use
the remaining time; streamed responses and lifecycle loops check cancellation.
Safe HTTPS hostname resolution now uses dnspython with system DNS configuration
rather than uninterruptible libc/NSS resolution (`localhost` remains supported;
NSS aliases and hosts-file overrides are not consulted).

Cancellation is cooperative: it is checked between blocking operations, not by
forcibly terminating Python threads. Injected resolvers, fetchers, HTTP clients,
and log readers **must honor `dnsid.remaining_seconds()`**, bound their reads,
and propagate the budget when handing work to another thread. A noncooperating
callback cannot be forcibly interrupted; its late result is rejected, but the
SDK cannot guarantee prompt return from arbitrary caller code.

Standalone bundle migration rejection remains an API limitation rather than a
design deviation: configured readers recursively verify predecessor histories.
Durable initial-issuance coordinator recovery remains deployment-owned and is
not established by these verification tests.

## Consistency Reference

The following project files are the sources of truth and must remain consistent:

- **`pyproject.toml`** — `requires-python`, `dependencies`, `[project.optional-dependencies]`, and trove classifiers
- **`.github/workflows/lint-test.yml`** — CI Python version matrix and OS runners
- **`README.md`** — Installation section and compatibility statements
