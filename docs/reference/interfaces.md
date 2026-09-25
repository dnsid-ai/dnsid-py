---
title: "Python: Interfaces"
description: "Extension-point protocols: key providers, logs, caches, DNS resolvers, and identity resolution."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

Implement these interfaces to integrate your own backends. `IdentityResolver` is the minimal protocol satisfied by `IdentityManager` and accepted by the application profiles.

## `IdentityResolver`

```python
from dnsid import IdentityResolver
```

*Bases:* `Protocol`

Minimal interface required by application-layer profiles.

Any object exposing verify_domain with this signature satisfies the protocol
structurally — no inheritance needed.  IdentityManager satisfies it.
Profiles (JoseProfile, HttpSignatureProfile, WebBotAuthProfile, OIDCProfile)
accept IdentityResolver so they can be tested with lightweight doubles instead
of a full IdentityManager.

### `verify_domain`

```python
IdentityResolver.verify_domain(domain: str, peer_cert: TLSCertificate | None = None) -> VerifiedDomain
```

Verify the DNSid identity record for *domain*.

**Arguments:**

- `domain` (`str`): Agent FQDN to verify.
- `peer_cert` (`TLSCertificate | None`): TLS certificate of the live peer connection, when the caller wants channel binding against the identity record. — default `None`

**Returns:**

- `VerifiedDomain` — A VerifiedDomain describing the verified identity.

**Raises:**

- `VerificationError`: If any verification step fails.

## `KeyProvider`

```python
from dnsid import KeyProvider
```

*Bases:* `ABC`

Standardized interface for Key Management Systems.

Implementations may wrap local key files, cloud KMS (AWS KMS, GCP Cloud KMS,
Azure Key Vault), or HSMs. LocalKeyProvider handles private key material
locally; external KMS/HSM providers can keep it out of the SDK process.

> **Key lifecycle states:** Pending — generated but not yet promoted; excluded from JWKS. Active — current signing key; the single key in the live JWKS. Superseded — rotated out; retained only in log/archive/KMS for audit. Not in the live JWKS and never used for signing; historical verification uses key material recorded in the lifecycle log.

Driving generate_key/activate/supersede directly does not record the
KEY_ROTATION lifecycle event; for a registry-managed draft 01 rotation use
IdentityManager.rotate_operational_key, which appends the event before
activating the new key.

### `signing_key`

```python
KeyProvider.signing_key() -> JWK
```

Return the JWK of the current active signing key (public side only).

The returned kid MUST NOT contain '#' because application-layer helpers
encode key IDs as '{domain}#{kid}'.

### `jwk`

```python
KeyProvider.jwk(kid: str) -> JWK
```

Return the JWK for the given kid (active or retained).

**Raises:**

- `ArgumentError`: If *kid* is not found.

### `list_key_ids`

```python
KeyProvider.list_key_ids() -> list[str]
```

Return IDs of all active and retained keys (pending excluded).

The active key ID MUST appear first; retained keys follow in any order.

### `sign`

```python
KeyProvider.sign(payload: bytes) -> bytes
```

Sign *payload* with the current active key.

**Returns:**

- `bytes` — Raw signature bytes.

### `sign_key`

```python
KeyProvider.sign_key(kid: str, payload: bytes) -> bytes
```

Sign *payload* with a specified active or pending key.

Used for rotation authorization and proof of possession, where the
signing key is not (yet) the active key.  Providers that cannot
address keys by kid may leave this unimplemented.

### `generate_key`

```python
KeyProvider.generate_key() -> str
```

Generate a new key pair in the pending state.

**Returns:**

- `str` — The kid of the newly generated key.

### `activate`

```python
KeyProvider.activate(kid: str) -> None
```

Promote *kid* from pending to active; previous active transitions to retained.

**Raises:**

- `ArgumentError`: If *kid* is unknown or already active/retained.

### `supersede`

```python
KeyProvider.supersede(kid: str) -> None
```

Rotate *kid* out of live use after a completed key rotation.

The key leaves the live JWKS and is never used for signing again;
implementations may retain the material in a log/archive/KMS for audit.

**Raises:**

- `ArgumentError`: If *kid* is the current active key (activate a replacement first).

## `Log`

```python
from dnsid import Log
```

*Bases:* `ABC`

Write interface for the agent's own immutable ledger.

Implementations may wrap a blockchain, CT-style transparency log,
SCITT transparency service, or any append-only verifiable log.
Canonical serialization is log-method-specific; Log.canonical and
LogReader.canonical MUST produce identical bytes for the same event.

### `canonical`

```python
Log.canonical(event: LogEvent) -> bytes
```

Return the canonical byte representation of *event* for this log method.

Used by IdentityManager.sign_and_write_event to produce bytes that are signed.

### `write_event`

```python
Log.write_event(event: LogEvent) -> LogRef
```

Append a signed event to the log.

*event* MUST already carry sig; implementations MUST reject unsigned
events or events with invalid signatures.

**Returns:**

- `LogRef` — A LogRef identifying the recorded entry.

## `LogReader`

```python
from dnsid import LogReader
```

*Bases:* `ABC`

Read and verify interface for a specific ledger entry.

Bound at construction to a full lr value (e.g.
``c2sp-tlog:public:https://log.dnsid.ai#<stream-id>``).
The implementation stores the entry reference internally; callers do not pass
it per-method.  All methods MUST verify cryptographic inclusion proofs,
verifiable timestamps, and append-only consistency before returning.

### `canonical`

```python
LogReader.canonical(event: LogEvent) -> bytes
```

Return the canonical byte representation of *event* for this log method.

MUST produce identical output to Log.canonical for the same event.

### `key_timestamp`

```python
LogReader.key_timestamp(domain: str, key_thumbprint: str) -> datetime.datetime
```

Return the timestamp when *key_thumbprint* was bound to *domain*.

Matches ISSUANCE or KEY_ROTATION events.  Used for ka validation.
MUST verify inclusion proof, timestamp proof, and append-only consistency.

### `verify_non_revocation`

```python
LogReader.verify_non_revocation(domain: str, at: datetime.datetime) -> LoggedStateEvidence
```

Verify complete, fresh, non-terminal history for *domain* through *at*.

MUST verify the cryptographic evidence required by the log binding and
return the accepted proof boundary.

**Raises:**

- `VerificationError`: With LOG_ERROR if a terminal entry is found or complete, fresh log evidence cannot be established.

### `read_event`

```python
LogReader.read_event(ref: LogRef) -> AnyLogEvent
```

Read a single event by log reference.

MUST verify inclusion proof and timestamp proof before returning.

### `rebuild_history`

```python
LogReader.rebuild_history(domain: str) -> list[AnyLogEvent]
```

Rebuild the full event history for *domain* in chronological order.

MUST verify inclusion proofs, timestamp proofs, and append-only consistency.

### `rebuild_history_through`

```python
LogReader.rebuild_history_through(domain: str, final_entry_ref: str, entity_key: JWK, *, max_depth: int, max_events: int, max_response_bytes: int, seen_log_references: frozenset[str]) -> VerifiedCutoffHistory
```

Verify history through exactly *final_entry_ref* within cumulative bounds.

Bindings supporting migration predecessors override this method. The
returned event references MUST parallel ``events`` and end at the exact
signed cutoff; ``response_bytes`` reports bytes consumed by this read.

### `verify_bilateral_binding`

```python
LogReader.verify_bilateral_binding(record: DnsIdTxtRecord, entity_key: JWK, operational_key: JWK) -> Any
```

Verify the draft 01 bilateral ISSUANCE binding for *record*.

Confirms the logged ISSUANCE (or verified MIGRATION genesis) binds the
record's identity to *entity_key* (ek) and an initial operational key,
with both authorizing signatures verified.

**Returns:**

- `Any` — A binding object exposing at least ``initial_operational_thumbprint``.

**Raises:**

- `VerificationError`: With LOG_ERROR when the binding does not support this operation.

### `verify_operational_continuity`

```python
LogReader.verify_operational_continuity(domain: str, initial_operational_thumbprint: str, current_operational_thumbprint: str) -> None
```

Verify the logged KEY_ROTATION chain between two operational keys.

Confirms the chain of logged KEY_ROTATION events connects the initial
operational key from the ISSUANCE binding to the currently published
operational key for *domain*.

**Raises:**

- `VerificationError`: With LOG_ERROR when unsupported or when the chain does not connect the two thumbprints.

## `NoopLogReader`

```python
from dnsid import NoopLogReader
```

*Bases:* `LogReader`

Placeholder LogReader for ledger methods with no registered factory.

Every method raises VerificationError(LOG_ERROR) with a descriptive message.
Draft 01 verification requires lifecycle-log checks, so verify_domain fails
closed when no capable reader is registered.

### `NoopLogReader` constructor

```python
NoopLogReader(method: str) -> None
```

Record the unregistered log method for error messages.

**Arguments:**

- `method` (`str`): Log method name that has no registered LogReader factory.

### `canonical`

```python
NoopLogReader.canonical(event: LogEvent) -> bytes
```

Raise VerificationError(LOG_ERROR); no LogReader is registered for this method.

### `key_timestamp`

```python
NoopLogReader.key_timestamp(domain: str, key_thumbprint: str) -> datetime.datetime
```

Raise VerificationError(LOG_ERROR); no LogReader is registered for this method.

### `verify_non_revocation`

```python
NoopLogReader.verify_non_revocation(domain: str, at: datetime.datetime) -> LoggedStateEvidence
```

Raise VerificationError(LOG_ERROR); no LogReader is registered for this method.

### `read_event`

```python
NoopLogReader.read_event(ref: LogRef) -> AnyLogEvent
```

Raise VerificationError(LOG_ERROR); no LogReader is registered for this method.

### `rebuild_history`

```python
NoopLogReader.rebuild_history(domain: str) -> list[AnyLogEvent]
```

Raise VerificationError(LOG_ERROR); no LogReader is registered for this method.

## `IdentityCache`

```python
from dnsid import IdentityCache
```

*Bases:* `ABC`

Cache for verified domain results.

Implementations MUST be safe for concurrent use.
Get MUST return None for entries whose VerifiedDomain.expiry() has passed.
Put MUST derive the entry TTL from result.expiry() and evict automatically.

### `get`

```python
IdentityCache.get(domain: str) -> VerifiedDomain | None
```

Return the cached VerifiedDomain, or None if absent or expired.

### `put`

```python
IdentityCache.put(domain: str, result: VerifiedDomain) -> None
```

Store *result*. Entry expires at result.expiry().

### `evict`

```python
IdentityCache.evict(domain: str) -> None
```

Remove *domain* from the cache immediately.

## `DNSResolver`

```python
from dnsid import DNSResolver
```

*Bases:* `ABC`

Pluggable DNS resolver.

Decouples VerifyDomain from the system resolver so deployments can substitute
a DNSSEC-validating library, a trusted DoT/DoH upstream, or a test double.

### `fetch_txt`

```python
DNSResolver.fetch_txt(name: str) -> tuple[list[TXTRecord], DNSSECState]
```

Fetch TXT records for *name* (normalized FQDN, no trailing dot).

Implementations MUST treat *name* as an absolute name — no search-domain
expansion.  Returns the record set and the DNSSEC validation state.

## `HTTPSFetcher`

```python
from dnsid import HTTPSFetcher
```

*Bases:* `ABC`

Pluggable HTTPS JSON fetch dependency.

Decouples VerifyDomain from any particular runtime HTTP stack while preserving
DNSid TLS and redirect semantics.  Language bindings may expose this dependency
as a configured HTTP client, transport, session, or other idiomatic abstraction.

Injected via IdentityManagerDependencies.https_fetcher.  When omitted,
IdentityManager uses a default implementation backed by TransportConfig.

Implementations MUST be safe for concurrent use: after the record
signature is authenticated, verify_domain fetches the status endpoint on
a helper thread while the runtime JWKS and lifecycle-log work proceed.

The built-in fetcher enforces strict HTTPS and rejects su/JWKS hosts that
resolve to non-public addresses. The only exception is a hostname matching
an exact or leading-dot suffix entry in
TransportConfig.private_address_hosts (empty by default, no built-in
exemption), which may resolve to loopback or private-use addresses only.
A blocked resolution raises a non-transient VerificationError with
TLS_ERROR.

### `fetch_strict_json`

```python
HTTPSFetcher.fetch_strict_json(url: str, allowed_host: str | None = None, domain_boundary: bool = False) -> tuple[dict[str, Any], TLSCertificate]
```

Fetch and parse a JSON document from an HTTPS URL.

Must perform full TLS certificate validation, reject credentials,
fragments, non-HTTPS URLs, and non-HTTPS redirects, and return the
peer TLS certificate.
When *allowed_host* is supplied, any redirect that changes the host away
from *allowed_host* MUST be rejected (used for JWKS fetches).  When
*domain_boundary* is additionally true, hosts equal to *allowed_host*
or within its DNS domain (subdomains) are permitted. Draft 01 uses this
for `ek`; `ku` remains pinned to the exact identity FQDN.
Without *allowed_host*, host-changing HTTPS redirects are permitted
(used for status endpoint fetches).

**Raises:**

- `VerificationError`: With TLS_ERROR on certificate failures or disallowed redirects; transient MUST be True for retryable transport conditions (e.g. handshake timeouts) and False for policy failures (e.g. a redirect to a non-HTTPS URL). With DNS_RESOLUTION and transient=True on network errors (DNS, connect, request timeouts) — callers use the transient flag to classify status-endpoint availability.

## `AbstractRegistryClient`

```python
from dnsid import AbstractRegistryClient
```

*Bases:* `ABC`

Abstract interface for operator-side DNSid registry workflows.

Defines the core methods specified by the DNSid registry transport design.
The bundled `RegistryClient` is the default
concrete implementation; inject a custom subclass via
`IdentityManager` workflows when needed.

``AbstractRegistryClient`` is NOT used by ``VerifyDomain`` — protocol
verification always fetches the ``su`` endpoint asserted in the signed TXT
record and never contacts the registry operator API.

### `get_registration`

```python
AbstractRegistryClient.get_registration(domain: str) -> AgentRegistration | None
```

Return the operator workflow record, or ``None`` if unregistered.

### `wait_for_status`

```python
AbstractRegistryClient.wait_for_status(domain: str, *, timeout: float = 120.0, interval: float = 5.0, target_state: str | None = None) -> RegistryAgentStatus
```

Wait for publication or an explicitly requested workflow state.

### `canonical_record_content`

```python
AbstractRegistryClient.canonical_record_content(domain: str, signing_kid: str) -> CanonicalRecordContentResponse
```

Fetch the registry's canonical TXT record content for signing.

POST ``{baseUrl}/api/v1/agent/{domain}/record``.
The SDK MUST validate the response before signing; it is not trusted input.

### `publish_signature`

```python
AbstractRegistryClient.publish_signature(domain: str, sig: str) -> PublishedRecord
```

Submit the profile-encoded signature to complete the publish workflow.

POST ``{baseUrl}/api/v1/agent/{domain}/signature``.
Draft 01 requires bare unpadded base64url signature bytes.

### `prepare_issuance`

```python
AbstractRegistryClient.prepare_issuance(domain: str, idempotency_key: str) -> PreparedRegistryEvent
```

Fetch exact untrusted accountable-entity-signed ISSUANCE bytes.

POST ``{baseUrl}/api/v1/agent/{domain}/tlog/issuance/prepare`` with no
body and the supplied ``Idempotency-Key`` header. The returned log
reference is transport context and remains unparsed at this boundary.

### `prepare_key_rotation`

```python
AbstractRegistryClient.prepare_key_rotation(domain: str, request: KeyRotationPreparationRequest, idempotency_key: str) -> PreparedRegistryEvent
```

Return an untrusted registry-prepared KEY_ROTATION response.

The caller independently parses and verifies the exact returned bytes
against the returned log reference before adding any signature.

### `submit_prepared_event`

```python
AbstractRegistryClient.submit_prepared_event(domain: str, entry_bytes: bytes, idempotency_key: str) -> SubmissionResult
```

Submit exact prepared-event bytes under a durable idempotency key.

## `retry_transient`

```python
from dnsid import retry_transient
```

```python
retry_transient(fn: Callable[[], T], *, max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 30.0) -> T
```

Call *fn* and retry on transient VerificationError with exponential backoff.

Only retries when the raised `VerificationError` has
``transient=True``; any other exception — including non-transient
``VerificationError`` — propagates immediately.

**Arguments:**

- `fn` (`Callable[[], T]`): Zero-argument callable to call (use ``functools.partial`` or a lambda to bind arguments).
- `max_attempts` (`int`): Total number of attempts before re-raising the last error. — default `3`
- `base_delay` (`float`): Initial delay in seconds; doubles each retry. — default `1.0`
- `max_delay` (`float`): Upper cap on the per-retry delay before jitter. — default `30.0`

Example::

    result = retry_transient(lambda: idm.verify_domain("example.com"))

## `async_retry_transient`

```python
from dnsid import async_retry_transient
```

```python
async async_retry_transient(fn: Callable[[], object], *, max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 30.0) -> object
```

Async variant of `retry_transient`.

*fn* must return an awaitable (e.g. a coroutine function call).
Sleeps with ``asyncio.sleep`` between retries so the event loop is not blocked.

Example::

    result = await async_retry_transient(lambda: some_async_fn("example.com"))
