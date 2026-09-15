---
title: "Python: IdentityManager"
description: "Primary entry point of the dnsid Python SDK: IdentityManager and its dependency bundle."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

`IdentityManager` is the primary entry point of the SDK; all protocol operations flow through it. The public API is **synchronous** — see the [package overview](https://docs.dnsid.ai/reference/py/overview/) for the async story.

## `IdentityManager`

```python
from dnsid import IdentityManager
```

Primary SDK object.  All DNSid protocol operations flow through it.

Log-writing methods — including sign_and_write_event, setup flows, key
rotation, and revocation flows — require a write-capable Log to be
derivable from deps.log_registry.  If this manager was constructed for
verification-only use, these methods raise ArgumentError.

**Attributes:**

- `config` (`DnsidConfig`): Return an independent copy of the manager's validated configuration.
- `local_domain` (`str`): Return the local identity FQDN, or ``""`` for a verification-only manager.

### `IdentityManager` constructor

```python
IdentityManager(config: DnsidConfig | None = None, key_provider: KeyProvider | None = None, deps: IdentityManagerDependencies | None = None) -> None
```

Initialize the manager with configuration, keys, and dependencies.

**Arguments:**

- `config` (`DnsidConfig | None`): Core configuration. Omit ``config.identity`` (or *config* entirely) for a verification-only manager; ``verification`` and ``transport`` apply identically in either mode. *domain* and *governance_id* are normalised with normalize_fqdn. The configuration is validated and snapshotted before any network work; create a new manager to change policy or trust. — default `None`
- `key_provider` (`KeyProvider | None`): Operational key provider for the local identity. Required with ``config.identity``; rejected without it. — default `None`
- `deps` (`IdentityManagerDependencies | None`): Optional dependency bundle. Omit to use built-in defaults (in-memory cache, system/configured DNS resolver). — default `None`

**Raises:**

- `ArgumentError`: On invalid configuration, a key provider supplied to a verification-only manager, a missing operational key provider for a local identity, or a transport setting whose only SDK-managed consumer is an injected dependency.

### `for_verification`

```python
IdentityManager.for_verification(deps: IdentityManagerDependencies | None = None, verification: VerificationConfig | None = None, transport: TransportConfig | None = None) -> IdentityManager
```

Construct a verifier without a local identity or keys.

Alias for ``IdentityManager(DnsidConfig(verification=..., transport=...), deps=deps)``.

### `canonicalize_log_event`

```python
IdentityManager.canonicalize_log_event(event: LogEvent) -> bytes
```

Return the log-method-specific canonical bytes all signatures cover.

Requires a local log binding for config.identity.log_ref (Log or
LogReader), but not write access.  Canonicalization excludes signature
fields, so adding one signature never changes the bytes another covers.

**Arguments:**

- `event` (`LogEvent`): The lifecycle log event to canonicalize.

**Returns:**

- `bytes` — The canonical bytes that every signature over the event covers.

**Raises:**

- `ArgumentError`: If no LogRegistry binding is available for config.identity.log_ref.

### `required_log_signatures`

```python
IdentityManager.required_log_signatures(event: LogEvent) -> list[LogSignerRole]
```

Return the profile-owned signer roles required before writing *event*.

Signer roles are event-type-owned:

* ISSUANCE — Entity and OperationalCountersignature
* KEY_ROTATION — PreviousOperational (signs by kid via
  KeyProvider.sign_key)
* all other lifecycle events — Entity

Entity signatures require deps.entity_key_provider; the other roles
use the agent key_provider.  Concrete bindings enforce any
method-owned additions without weakening these profile requirements.

**Arguments:**

- `event` (`LogEvent`): The lifecycle log event to inspect.

**Returns:**

- `list[LogSignerRole]` — The signer roles whose signatures must be present before the event
- `list[LogSignerRole]` — may be written.

### `sign_event`

```python
IdentityManager.sign_event(event: LogEvent, role: LogSignerRole) -> LogEvent
```

Add the signature for one role using this manager's matching provider.

Entity signatures come from deps.entity_key_provider; Operational,
OperationalCountersignature, and PreviousOperational signatures come
from the agent key_provider.  Does not write to the log.

**Arguments:**

- `event` (`LogEvent`): The lifecycle log event to sign; mutated in place.
- `role` (`LogSignerRole`): The signer role whose signature to add.

**Returns:**

- `LogEvent` — The same event with the role's signature added.

**Raises:**

- `ArgumentError`: If the Entity role is requested without deps.entity_key_provider, or no LogRegistry binding is available for config.identity.log_ref.

### `write_signed_event`

```python
IdentityManager.write_signed_event(event: LogEvent) -> LogRef
```

Append an already-signed lifecycle event to the local log.

Rejects events missing any required_log_signatures field.

**Arguments:**

- `event` (`LogEvent`): The fully signed lifecycle event to append.

**Returns:**

- `LogRef` — The LogRef of the appended event.

**Raises:**

- `ArgumentError`: If no write-capable local log is configured, or the event is missing a required signature.

### `sign_and_write_event`

```python
IdentityManager.sign_and_write_event(event: LogEvent) -> LogRef
```

Sign and append a lifecycle event to the identity's local log.

Single-process convenience: the input may already carry some required
signatures; only missing signatures for roles this manager is
configured to produce are added, then the event is written.  If a
required signature is still missing (e.g. an Entity role with no
deps.entity_key_provider), this fails before writing.  Distributed
flows call sign_event on each signing machine and write_signed_event
once all required signatures are present.

**Arguments:**

- `event` (`LogEvent`): The lifecycle event to sign and append; mutated in place.

**Returns:**

- `LogRef` — The LogRef of the appended event.

**Raises:**

- `ArgumentError`: If no write-capable local log is configured, or a required signature is missing and this manager is not configured to produce it.

### `get_key_set`

```python
IdentityManager.get_key_set() -> JWKS
```

Return the agent public key set for publication at the ku endpoint.

Draft 01 live endpoints expose exactly one current operational key
(retained keys are not published); the endpoint MUST be served over
HTTPS with a valid TLS certificate whose host matches the identity
FQDN.

**Returns:**

- `JWKS` — A JWKS containing exactly the current operational key.

### `get_entity_key_set`

```python
IdentityManager.get_entity_key_set() -> JWKS
```

Return the accountable-entity public key set for publication at the ek endpoint.

Draft 01 live endpoints expose exactly one current key. The endpoint
MUST be served over HTTPS with a valid TLS certificate whose host
equals or is beneath gi.

**Returns:**

- `JWKS` — A JWKS containing exactly the current entity key.

**Raises:**

- `ArgumentError`: If no entity key provider is configured.

### `create_txt_record`

```python
IdentityManager.create_txt_record() -> str
```

Build and sign the _dnsid TXT record for publication at _dnsid.{domain}.

The wire profile comes from IdentityConfig.publish_profile; draft 01 is
the only publishable profile.  Draft 01 records require explicit
IdentityConfig.ek_url and ku_url (the protocol defines no default
endpoint paths), are signed by the accountable-entity key
(deps.entity_key_provider), and carry a bare base64url sg value.

The signature is computed over DnsIdTxtRecord.canonical(), not the
serialized wire form: draft 01 sorts all tags (including the exact
``v=`` selector) alphabetically for signing, while the serialized wire
form always puts ``v=`` first.

**Returns:**

- `str` — The serialized, signed identity record TXT string including all
- `str` — required tags (v, gi, ek, ku, lr, su, sg).

**Raises:**

- `ArgumentError`: If no entity key provider is configured, the entity and agent keys are not distinct, the configured publish profile is unsupported, or the record configuration is invalid.

### `publish_client_controlled_record`

```python
IdentityManager.publish_client_controlled_record(registry_client: AbstractRegistryClient) -> PublishedRecord
```

Publish through a registry when this SDK controls the entity key.

Two-step workflow per the design spec:
1. Fetch the registry's canonical content and validate it exactly
   matches the unsigned record this identity would produce locally
   (same publish profile, same known tags, same active signing kid).
   Unknown registry-managed tags (e.g. expiry) are signed as-is.
2. Sign the canonical bytes with the accountable-entity key and
   submit the bare base64url signature.

**Arguments:**

- `registry_client` (`AbstractRegistryClient`): Client for the registry publication API.

**Returns:**

- `PublishedRecord` — The PublishedRecord reported by the registry.

**Raises:**

- `ValidationError`: If the identity is not registered, the registry controls accountable-entity publication, or the registry canonical content does not match the local unsigned identity record.
- `ArgumentError`: If no entity key provider is configured or the entity and agent keys are not distinct.

### `publish_to_registry`

```python
IdentityManager.publish_to_registry(registry_client: AbstractRegistryClient) -> PublishedRecord
```

Deprecated alias for `publish_client_controlled_record`.

### `await_registry_managed_publication`

```python
IdentityManager.await_registry_managed_publication(registry_client: AbstractRegistryClient, timeout: float = 120.0, interval: float = 5.0) -> PublishedRecord
```

Wait for registry-owned publication, then verify the observed DNS record.

Polls the registry until it reports the identity record published,
then verifies the observed DNS record with the same protocol checks as
verify_domain (but without counterparty acceptance; this confirms
publication, it does not approve a counterparty) and checks the
published record's version against the configured publish profile.

**Arguments:**

- `registry_client` (`AbstractRegistryClient`): Client for the registry publication API.
- `timeout` (`float`): Maximum seconds to wait for the registry to report publication. — default `120.0`
- `interval` (`float`): Seconds between registry status polls. — default `5.0`

**Returns:**

- `PublishedRecord` — A PublishedRecord describing the verified published record.

**Raises:**

- `ValidationError`: If the identity is not registered, the client controls publication, the registry fails or never confirms DNS publication, or the published record uses an unexpected version.
- `VerificationError`: If verification of the published identity fails; carries a VerificationCode.

### `rotate_operational_key`

```python
IdentityManager.rotate_operational_key(registry_client: AbstractRegistryClient, idempotency_key: str, persist_rotation: KeyRotationPersistenceHook, set_application_signing_paused: ApplicationSigningPauseHook) -> KeyRotationResult
```

Rotate the managed operational key with mandatory recovery hooks.

Complete signed entry bytes are persisted before submission, then new
application signing is paused. Every submission and local activation
transition is persisted. The exact bytes and idempotency key are
reused by `resume_key_rotation` after a crash or indeterminate
result. Signing resumes only after accepted submission, idempotent key
activation/supersession, and durable activation state.

**Arguments:**

- `registry_client` (`AbstractRegistryClient`): Client implementing the registry rotation API.
- `idempotency_key` (`str`): Caller-chosen key making preparation and submission retry-safe; reuse it for every retry of this rotation.
- `persist_rotation` (`KeyRotationPersistenceHook`): Mandatory durable persistence hook. It receives an isolated copy of every recoverable state transition.
- `set_application_signing_paused` (`ApplicationSigningPauseHook`): Mandatory hook that enforces the application-signing pause boundary.

**Returns:**

- `KeyRotationResult` — The latest durable recovery state.

**Raises:**

- `ArgumentError`: If a mandatory hook, key, or idempotency key is invalid.
- `ValidationError`: If registry preparation is invalid.
- `ManagedKeyRotationSubmissionError`: If pausing, submission, or submission persistence fails; carries the latest recovery state.
- `ManagedKeyRotationActivationError`: If accepted local reconciliation, persistence, or pause release fails; carries recovery state.

### `resume_key_rotation`

```python
IdentityManager.resume_key_rotation(registry_client: AbstractRegistryClient, result: KeyRotationResult, persist_rotation: KeyRotationPersistenceHook, set_application_signing_paused: ApplicationSigningPauseHook) -> KeyRotationResult
```

Resume an exact persisted managed key rotation safely.

Validates the persisted bytes, hash, identity, log, and key bindings
before any network or key mutation. Pending state reuses the exact
bytes and idempotency key. Accepted state performs only idempotent
local reconciliation; activated-but-paused state only releases the
signing pause and persists completion.

### `activate_rotated_key`

```python
IdentityManager.activate_rotated_key(result: KeyRotationResult, submission: SubmissionResult | None = None, persist_rotation: KeyRotationPersistenceHook, set_application_signing_paused: ApplicationSigningPauseHook) -> KeyRotationResult
```

Reconcile an accepted rotation using the mandatory durability hooks.

### `verify_domain`

```python
IdentityManager.verify_domain(domain: str, peer_cert: TLSCertificate | None = None) -> VerifiedDomain
```

Verify a DNSid identity, then enforce configured counterparty acceptance.

This is the core trust-establishment operation; all profile Verify*
methods call this internally.  The result is cached per
VerificationConfig.status_check_interval.

When ``VerificationConfig.trusted_entities`` is configured, the
verified record's ``gi`` (and, if pinned, the current record-signing
key's RFC 7638 thumbprint) must match one entry; otherwise a permanent
COUNTERPARTY_NOT_ACCEPTED error is raised.  Acceptance runs on every
invocation, including cache hits; verified evidence is cached before
acceptance and denials are never cached.  Without ``trusted_entities``
no acceptance decision is made.

Draft 01 verification checks the record's ek/ku anchors against the
logged lifecycle through the log binding itself — the bilateral
ISSUANCE binding and operational-key continuity.  These checks run
independently of the fl=logchk flag and fail closed: verifying a
record without a registered log reader capable of the binding-level
checks (such as the c2sp-tlog reader) raises VerificationError with
LOG_ERROR.  Draft 01 also requires distinct ek and ku keys; a record
whose entity and operational keys share an RFC 7638 thumbprint is
rejected as RECORD_INVALID.

Operation-level log policy (fl=logchk) is caller policy: this method
records the flag but does not run automatic non-revocation checks —
whether the caller's next operation is high-value or irreversible is
not the SDK's decision. Callers can inspect
``result.requires_log_check()`` and call ``verify_log_evidence()``
before such operations.

Status availability: a transport-level failure fetching the su
endpoint (DNS, connect, TLS handshake, 5xx) raises STATUS_UNAVAILABLE
with ``transient=True`` — the identity's status is indeterminate, not
failed. A reachable endpoint returning a non-ACTIVE state raises
STATUS_NOT_ACTIVE. When the record carries ``fl=mtls``, the certificate
from the current peer connection is checked on every invocation,
including identity-cache hits.

**Arguments:**

- `domain` (`str`): FQDN of the identity to verify.
- `peer_cert` (`TLSCertificate | None`): TLS peer certificate from an mTLS connection. Required when the verified record carries fl=mtls; raises VerificationError otherwise. — default `None`

**Returns:**

- `VerifiedDomain` — A VerifiedDomain carrying the verified identity record, key sets,
- `VerifiedDomain` — registry status, and a bound log reader.

**Raises:**

- `VerificationError`: If any verification step fails — DNS resolution, DNSSEC, identity record parsing or validation, signature checks, key-set fetches, lifecycle-log checks, key age, policy flags, or status. Carries a VerificationCode identifying the failing step.

### `verify_log_evidence`

```python
IdentityManager.verify_log_evidence(vd: VerifiedDomain, at: datetime.datetime | None = None) -> LoggedStateEvidence
```

Verify and return complete, fresh operation-level log evidence.

This does not refresh the identity's protocol status.

**Arguments:**

- `vd` (`VerifiedDomain`): A result previously returned by ``verify_domain``.
- `at` (`datetime.datetime | None`): Operation time; defaults to the current time. — default `None`

**Returns:**

- `LoggedStateEvidence` — The accepted log completeness, checkpoint, and freshness boundary.

### `evict_domain`

```python
IdentityManager.evict_domain(domain: str) -> None
```

Remove *domain* from the identity cache.

### `load_domain_log`

```python
IdentityManager.load_domain_log(vd: VerifiedDomain) -> DomainLog
```

Load the full verified event history for a domain from its lifecycle log.

**Arguments:**

- `vd` (`VerifiedDomain`): A VerifiedDomain previously returned by verify_domain.

**Returns:**

- `DomainLog` — A DomainLog containing the rebuilt event history.

### `close`

```python
IdentityManager.close() -> None
```

Close manager-owned HTTP resources.

Closing is idempotent. The manager must not be closed while verification
calls are active. Injected HTTPSFetcher instances remain caller-owned.

### `create_dnsid_http_client`

```python
IdentityManager.create_dnsid_http_client() -> httpx.Client
```

Return an httpx.Client scoped to this identity's transport config.

Applies ca_bundle_path for TLS trust augmentation. A ``host:port``
dns_server is used for hostname resolution; DoH URLs apply only to
DNSid TXT lookups and this client uses the system hostname resolver.

**Returns:**

- `httpx.Client` — A new httpx.Client; the caller is responsible for closing it.

### `create_dnsid_async_http_client`

```python
IdentityManager.create_dnsid_async_http_client() -> httpx.AsyncClient
```

Return an httpx.AsyncClient scoped to this identity's transport config.

Applies ca_bundle_path for TLS trust augmentation. A ``host:port``
dns_server is used for hostname resolution; DoH URLs apply only to
DNSid TXT lookups and this client uses the system hostname resolver.

**Returns:**

- `httpx.AsyncClient` — A new httpx.AsyncClient; the caller is responsible for closing it.

## `IdentityManagerDependencies`

```python
from dnsid import IdentityManagerDependencies
```

Optional dependencies for IdentityManager.

All fields default to None; the manager uses built-in defaults when omitted.

**Attributes:**

- `log_registry` (`LogRegistry | None`): Registry of log-method bindings. Used to derive the local log for config.identity.log_ref and to construct readers for counterparty logs during verification.
- `dns_resolver` (`DNSResolver | None`): DNS resolver used for _dnsid TXT lookups. Omit to use the built-in default resolver: system DNS or a ``host:port`` server (neither reports DNSSEC state), or DNS-over-HTTPS when config.transport.dns_server is an ``http(s)://`` URL (reports DNSSEC state from the AD bit). System and ``host:port`` resolution report ``UNKNOWN``, which the default ``AUTO`` policy accepts and preserves. Inject a DNSSEC-aware resolver for ``VALIDATED`` or ``REQUIRED`` policy.
- `https_fetcher` (`HTTPSFetcher | None`): HTTPS fetcher used for JWKS and status endpoint requests. Omit to use the SDK's default transport.
- `cache` (`IdentityCache | None`): Cache for verified identities. Defaults to an in-memory cache.
- `entity_key_provider` (`KeyProvider | None`): Accountable-entity key provider, used only for _dnsid identity record signing and entity lifecycle events. Keep separate from the agent key_provider; for draft 01 the current entity and agent public keys MUST be distinct.

## `verification_budget`

```python
from dnsid import verification_budget
```

```python
verification_budget(timeout: float = 30.0, cancelled: threading.Event | None = None) -> Iterator[None]
```

Set a finite overall timeout; nested budgets cannot extend their parent.

## `remaining_seconds`

```python
from dnsid import remaining_seconds
```

```python
remaining_seconds(maximum: float = 30.0) -> float
```

Return a child timeout without restarting the invocation's clock.

## `KeyRotationPersistenceHook`

```python
from dnsid import KeyRotationPersistenceHook
```

*Value:* `Callable[[KeyRotationResult], None]`

Persist a complete managed-key-rotation recovery state durably.

## `ApplicationSigningPauseHook`

```python
from dnsid import ApplicationSigningPauseHook
```

*Value:* `Callable[[bool], None]`

Pause or resume creation of new application signatures.

## `ManagedKeyRotationSubmissionError`

```python
from dnsid import ManagedKeyRotationSubmissionError
```

*Bases:* `DNSidError`

Managed rotation submission failed with recoverable exact-byte state.

### `ManagedKeyRotationSubmissionError` constructor

```python
ManagedKeyRotationSubmissionError(message: str, rotation: KeyRotationResult, state: str, transient: bool, retry_same_bytes: bool, cause: BaseException | None = None) -> None
```

Initialize a typed submission/recovery failure.

## `ManagedKeyRotationActivationError`

```python
from dnsid import ManagedKeyRotationActivationError
```

*Bases:* `DNSidError`

Accepted managed rotation has incomplete local reconciliation.

### `ManagedKeyRotationActivationError` constructor

```python
ManagedKeyRotationActivationError(message: str, rotation: KeyRotationResult, cause: BaseException | None = None) -> None
```

Initialize an activation, pause-release, or persistence failure.

## `sign_event_with_provider`

```python
from dnsid import sign_event_with_provider
```

```python
sign_event_with_provider(event: LogEvent, role: LogSignerRole, key_provider: KeyProvider, log_binding: Log | LogReader) -> LogEvent
```

Add the signature for one role to *event* using an explicit provider.

Lower-level primitive behind IdentityManager.sign_event for processes that
intentionally hold only one signer role.  The bound log binding, not
caller-supplied bytes, determines canonical content.  Does not require
providers for any other role and does not write to the log.

**Arguments:**

- `event` (`LogEvent`): The lifecycle log event to sign; mutated in place.
- `role` (`LogSignerRole`): The signer role whose signature to add.
- `key_provider` (`KeyProvider`): Provider holding the key material for the role.
- `log_binding` (`Log | LogReader`): Bound log binding that determines canonical content.

**Returns:**

- `LogEvent` — The same event with the role's signature added.

**Raises:**

- `ArgumentError`: If PreviousOperational signing is requested for an event that is not a KEY_ROTATION event with previous_kid set.
