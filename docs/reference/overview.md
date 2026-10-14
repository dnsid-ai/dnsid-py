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
Fresh cache hits and shared waits need no worker threads. Cold verification and
status refreshes use workers for synchronous DNS, HTTPS, and log adapters.
Cancellation stops the caller's wait, not shared evidence work; keep the manager
open until that work finishes. Injected identity caches must be nonblocking.

Signed `httpx.AsyncClient` requests offload synchronous signing, including KMS.
Synchronous APIs remain available. Other blocking SDK operations, including the
status reads in `RegistryClient.async_wait_for_status()`, still need workers.

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

*Value:* `SDKConformance(publish_profile=_DRAFT_01, verification_profiles=MappingProxyType({_DRAFT_01: _DRAFT_01, 'DNSid1': _DRAFT_01}), specification_status='internet-draft', log_bindings=MappingProxyType({'c2sp-tlog': _C2SP_TLOG_BINDING}), known_deviations=())`
