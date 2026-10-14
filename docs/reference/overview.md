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
threads. Status refreshes use native async DNS and SSRF-safe HTTPS. Cold
verification and injected synchronous HTTPS fetchers still use workers.
Shared evidence has an independent 30-second budget. Cancellation or a request
deadline stops only that caller's wait. Use `async with manager` or
`await manager.aclose()` at shutdown to drain owned work and close resources.
Use `with verification_budget(5):` around a request to set its deadline; expiry
raises `VerificationError` with `DEADLINE_EXCEEDED` and `transient=True`.
Injected identity caches must be nonblocking.

Signed `httpx.AsyncClient` requests offload synchronous signing, including KMS.
`create_signed_async_http_client(transport=...)` accepts an outbound transport;
the returned client owns and closes it. Synchronous APIs remain available.
Other blocking SDK operations, including the status reads in
`RegistryClient.async_wait_for_status()`, still need workers.

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
