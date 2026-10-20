---
title: "Python: SDK overview"
description: "Import surface, async verification, and layout of the dnsid Python SDK reference."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

The `dnsid` package is the Python SDK for the DNSid Protocol — agent
identity management and verification. Install with `pip install dnsid`
(Python 3.11+). The package ships a `py.typed` marker, so type checkers
see the SDK's full mypy-strict annotations.

See the [quickstart](https://docs.dnsid.ai/quickstart/) and the
[SDK overview](https://docs.dnsid.ai/sdk-overview/) for guided introductions;
these pages are the generated API reference.

## Import surface

Everything documented here is importable from the package root
(`from dnsid import IdentityManager, JoseProfile`), mirroring the
TypeScript SDK's umbrella package. The application-profile classes are
also importable from their home submodules — both paths are supported
and refer to the same classes:

```python
from dnsid.jose import JoseProfile
from dnsid.http_signatures import HttpSignatureProfile
```

The transparency-log integration is the exception: import it from
`dnsid.c2sp_tlog`.

## Async verification

Use `await manager.async_verify_domain(domain)` and
`await http_signer.async_verify_signed_http_request(request)` in async code.
Fresh cache hits, shared waits, and default stale-status refreshes need no worker
threads. Async-led cold verification awaits native TXT, JWKS, status and C2SP
reads, including bundles, tiles and recursive predecessors. Injected adapters
may implement `AsyncDNSResolver`, `AsyncHTTPSFetcher` and `AsyncLogReader`
alongside their synchronous methods. Sync-only adapters and atomic checkpoint
stores use tracked workers. Sync-led work retains synchronous adapters in
workers; both APIs share whichever evidence leader starts first. Injected
resources remain caller-owned.
Shared evidence has an independent 30-second budget. Cancellation or a request
deadline stops only that caller's wait. Use `async with manager` or
`await manager.aclose()` at shutdown to drain owned work and close resources.
Use `with verification_budget(5):` around a request to set its deadline; expiry
raises `VerificationError` with `DEADLINE_EXCEEDED` and `transient=True`.
Injected identity caches must be nonblocking.

Use `await manager.async_refresh_domain(domain)` to bypass the identity cache
and revalidate HTTP evidence. Concurrent explicit refreshes share work, but do
not reuse ordinary lookups. Each caller enforces its current peer, acceptance,
and freshness; cancellation stops only that caller's wait.

Signed `httpx.AsyncClient` requests offload synchronous signing, including KMS.
`create_signed_async_http_client(transport=...)` accepts an outbound transport;
the returned client owns and closes it. Synchronous APIs remain available.
RegistryClient exposes native `async_` variants for every registry HTTP
operation, including `async_wait_for_status()`. Use `async with client` or
`await client.aclose()` after async use. Requests share a protected async pool
on one event loop; finish outstanding requests before closing. Cancellation
does not undo server-side mutations. Preserve the same request and idempotency
key when reconciling and retrying an uncertain operation.
Manager-level publication, rotation and other blocking SDK operations still
need workers.

## Application profiles

The JOSE, HTTP Message Signatures, Web Bot Auth, and OIDC profiles are
**not part of the core DNSid protocol** — they
are optional application-layer integrations built on top of it.

## `SDKConformance`

```python
from dnsid import SDKConformance
```

Immutable protocol-facing conformance metadata for this SDK release.

## `SDK_CONFORMANCE`

```python
from dnsid import SDK_CONFORMANCE
```

*Value:* `SDKConformance(publish_profile=_DRAFT_01, verification_profiles=MappingProxyType({_DRAFT_01: _DRAFT_01, 'DNSid1': _DRAFT_01}), specification_status='internet-draft', log_bindings=MappingProxyType({'c2sp-tlog': _C2SP_TLOG_BINDING}), known_deviations=('JOSE, HTTP Message Signatures, and OIDC profiles retain mutable caller configuration.', 'The JWT bearer profile is exported as WebBotAuthProfile; Web Bot Auth naming is reserved for RFC 9421.'))`
