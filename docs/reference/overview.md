---
title: "Python: SDK overview"
description: "Import surface, sync-only design, and layout of the dnsid Python SDK reference."
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

## Synchronous by design

The public API is synchronous: every `IdentityManager`, profile, and
registry method blocks. Async support is limited to the httpx transport
plumbing (custom transports may implement `handle_async_request`) and
the `async_retry_transient` helper. Call the SDK from async code via
`asyncio.to_thread` or an executor.

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
