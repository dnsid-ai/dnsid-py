---
title: "Python: Registry"
description: "Registry control-plane workflows: RegistryClient, log-method registry, and registry data models."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

## `LogRegistry`

```python
from dnsid import LogRegistry
```

Holds one factory per log method; constructs bound LogReader instances on demand.

> **Example:** registry = LogRegistry() registry.register("algorand", AlgorandLogReader) reader = registry.new_reader("algorand:AGENT_ADDR")

IdentityManager uses this at construction (to derive localLog) and during
VerifyDomain (to construct counterparty readers).

### `LogRegistry` constructor

```python
LogRegistry() -> None
```

Initialize an empty registry with no registered log method factories.

### `register`

```python
LogRegistry.register(method: str, factory: LogReaderFactory) -> None
```

Register a factory for *method* (e.g. 'algorand', 'ctlog', 'scitt').

**Arguments:**

- `method` (`str`): Log method name; must match ``[a-z][a-z0-9-]*``.
- `factory` (`LogReaderFactory`): Callable that builds a LogReader bound to a full lr string.

**Raises:**

- `ArgumentError`: If *method* does not match ``[a-z][a-z0-9-]*``.

### `new_reader`

```python
LogRegistry.new_reader(lr: str) -> LogReader
```

Construct a LogReader bound to the full log reference *lr*.

Splits *lr* on the first ':' to extract the method prefix, then calls
the registered factory.

**Arguments:**

- `lr` (`str`): Full log reference string, e.g. ``"algorand:AGENT_ADDR"``.

**Returns:**

- `LogReader` — A LogReader bound to *lr*, or a NoopLogReader when the method has no registered factory.

**Raises:**

- `ParseError`: If *lr* is malformed.

## `RegistryClient`

```python
from dnsid import RegistryClient
```

*Bases:* `AbstractRegistryClient`

Operator-side client for managing the local agent's own registration.

The primary contract is the DNSid registry API under ``/api/v1``:

* ``POST /api/v1/agent`` — register an agent
* ``POST /api/v1/agent/{fqdn}/verify`` — request verification
* ``POST /api/v1/agent/{fqdn}/challenge`` — submit the signed challenge nonce
* ``POST /api/v1/agent/{fqdn}/proof`` — submit managed Live proof
* ``POST /api/v1/agent/{fqdn}/proof/reissue`` — reissue managed Live proof
* ``GET  /api/v1/agent/{fqdn}/status`` — fetch lifecycle state
* ``POST /api/v1/agent/{fqdn}/record`` — fetch canonical record content
* ``POST /api/v1/agent/{fqdn}/signature`` — submit signature for publication
* ``POST /api/v1/agent/{fqdn}/retire`` — retire an agent
* ``DELETE /api/v1/agent/{fqdn}`` — unregister

NOT used by VerifyDomain; protocol verification always fetches the signed su endpoint.

Hosted mutation calls require owner credentials (an organization session or
API key), supplied as ``api_key`` and sent as an ``Authorization: Bearer``
header. Loopback registry calls do not require credentials. An agent bearer
token is not sufficient. Legacy status reads are public, but Live status
requires the same owner authentication because it
may expose a proof challenge. A configured credential is sent on all reads.
The credential is never included in ``repr()``/``str()``, exceptions, or logs.

Restore/reactivation operations (un-retiring or un-revoking an agent) are
deliberately not exposed: the registry treats RETIRED and REVOKED as
terminal, so recovery is an operator/registry-console action, not an SDK
call.  The signed ``_dnsid`` TXT record is authoritative in DNS, not in
the registry API — read the effective published values (e.g. ku/su) by
resolving and verifying the record with ``IdentityManager.verify_domain``.

### `RegistryClient` constructor

```python
RegistryClient(base_url: str | None = None, *, api_key: str | None = None) -> None
```

Initialize the client with a registry base URL and optional credential.

**Arguments:**

- `base_url` (`str | None`): HTTPS registry base URL, or HTTP loopback URL for the local registry; defaults to ``DEFAULT_REGISTRY_URL`` (the local registry from ``dnsid local up``). Hosted use requires an explicit URL; see `dnsid.registry_client_from_environment`. A trailing slash is stripped. — default `None`
- `api_key` (`str | None`): Owner session or organization API-key credential sent as an ``Authorization: Bearer`` header. Whitespace-only values are treated as absent; without one hosted clients can only read legacy status. The loopback registry does not require a credential. Constructors never read the environment themselves. — default `None`

**Raises:**

- `ValueError`: If *base_url* is not a safe HTTPS or loopback HTTP URL, or *api_key* contains control characters that could corrupt the Authorization header.

### `register_agent`

```python
RegistryClient.register_agent(input: AgentRegistrationInput) -> AgentRegistration
```

Register an agent with the registry.

``POST /api/v1/agent``

Pass ``domain`` to register a name you control (self-managed), or
``zone_id`` to have the registry assign a name in a delegated zone
(registry-managed). The two are mutually exclusive, and
``managed=True`` requires ``zone_id``. ``environment`` defaults to
``"production"``; ``"sandbox"`` is also accepted. For Live names use
`register_live_agent`.

### `register_live_agent`

```python
RegistryClient.register_live_agent(input: LiveAgentRegistrationInput, idempotency_key: str) -> LiveProvisioningResponse
```

Start managed Live registration and return its validated proof challenge.

``POST /api/v1/agent`` sends fixed ``tier="live"`` and ``managed=true``
discriminators. Sign the exact base64url-decoded ``challenge_message``
bytes; use the derived `LiveProvisioningResponse.domain` for the
proof route.

### `verify_agent`

```python
RegistryClient.verify_agent(domain: str) -> AgentRegistration
```

Request registry verification for a registered self-managed agent.

``POST /api/v1/agent/{domain}/verify``

### `revoke_agent`

```python
RegistryClient.revoke_agent(domain: str, agent_id: str, reason: RegistryRevocationReason) -> LifecycleResult
```

Revoke an agent through the registry-owned terminal lifecycle flow.

``POST /api/v1/agent/{domain}/revoke``

The registry owns persistence and the transparency-log append; this
convenience method does not prepare or append a second local event.

**Arguments:**

- `domain` (`str`): Agent FQDN to revoke.
- `agent_id` (`str`): Immutable registry agent ID for safe retries after domain re-registration.
- `reason` (`RegistryRevocationReason`): Typed owner-authorized registry revocation reason.

**Returns:**

- `LifecycleResult` — The registry lifecycle transition result.

**Raises:**

- `ArgumentError`: If *reason* is not a ``RegistryRevocationReason``.

### `retire_agent`

```python
RegistryClient.retire_agent(domain: str, agent_id: str) -> LifecycleResult
```

Retire an agent while retaining its key for historical verification.

``POST /api/v1/agent/{domain}/retire`` with the immutable *agent_id*.

### `cancel_agent`

```python
RegistryClient.cancel_agent(domain: str) -> LifecycleResult
```

Cancel an agent that is still inside the registration workflow.

``POST /api/v1/agent/{domain}/cancel``. A PENDING agent cannot be
revoked (the registry answers 409 ``INVALID_TRANSITION``); cancelling
is the transition that removes it. Mirrors ``cancelAgent`` in the
TypeScript SDK and ``CancelAgent`` in Go.

### `submit_challenge_signature`

```python
RegistryClient.submit_challenge_signature(domain: str, nonce: str, signature: bytes | str) -> LifecycleResult
```

Submit the signed verification challenge to prove key possession.

``POST /api/v1/agent/{domain}/challenge``

During the ``VERIFICATION`` lifecycle state the registry exposes a
challenge nonce on the status document (``raw["challenge"]``).  The
agent signs the base64url-decoded nonce bytes with its active signing
key and submits the signature here.  The registry accepts the
challenge and completes verification asynchronously; use
`wait_for_status` with ``target_state="VERIFIED"`` afterwards.
The nonce is single-use — a fresh one must be fetched before retrying.

**Arguments:**

- `domain` (`str`): Agent FQDN.
- `nonce` (`str`): Challenge nonce exactly as returned by the status endpoint.
- `signature` (`bytes | str`): Raw signature bytes (base64url-encoded automatically), or an already base64url-encoded signature string.

### `submit_live_proof`

```python
RegistryClient.submit_live_proof(domain: str, request: LiveProofRequest) -> LiveProofResponse
```

Submit signed proof for managed Live provisioning.

``POST /api/v1/agent/{domain}/proof`` requires owner/session/API-key
credentials, not an agent bearer token. ``request.request_id`` is sent
as the required ``Idempotency-Key`` header.

### `reissue_live_proof`

```python
RegistryClient.reissue_live_proof(domain: str, request: LiveProofReissueRequest) -> LiveProofReissueResponse
```

Request a replacement challenge for an expired managed Live proof.

``POST /api/v1/agent/{domain}/proof/reissue`` requires owner/session/API-key
credentials, not an agent bearer token. ``request.request_id`` is sent
as the required ``Idempotency-Key`` header. The original public key is
validated locally and binds the replacement transcript, but is not sent.
The replacement challenge supersedes every earlier challenge; only the
latest message may be signed.

### `get_status`

```python
RegistryClient.get_status(domain: str) -> str | None
```

Fetch the raw lifecycle status string from the registry.

``GET /api/v1/agent/{domain}/status``

Returns the uppercased status string (e.g. ``"ACTIVE"``, ``"VERIFIED"``),
or ``None`` if the agent is not registered (HTTP 404). Live status
requires owner/session/API-key authentication; legacy status is public.

### `get_agent_status`

```python
RegistryClient.get_agent_status(domain: str) -> RegistryAgentStatus | None
```

Fetch registry lifecycle state.

``GET /api/v1/agent/{domain}/status``

Returns ``None`` if the agent is not registered (HTTP 404). Live status
requires owner/session/API-key authentication; legacy status is public.
Returns a `RegistryAgentStatus` with computed boolean flags that
mirror the TypeScript ``RegistryAgentStatus`` interface.

### `get_registration`

```python
RegistryClient.get_registration(domain: str) -> AgentRegistration | None
```

Return the current registry registration without conflating status namespaces.

### `wait_for_status`

```python
RegistryClient.wait_for_status(domain: str, *, timeout: float = 120.0, interval: float = 5.0, target_state: str | None = None) -> RegistryAgentStatus
```

Poll the registry until the agent reaches a settled or target state.

Returns when the agent is published, failed, or terminal — or when
*target_state* (a raw registry status string such as ``"VERIFIED"``) is
reached.  Raises `VerificationError(LOG_ERROR)` on timeout or if a
failed/terminal state is reached before *target_state*.

**Arguments:**

- `domain` (`str`): Agent FQDN.
- `timeout` (`float`): Maximum seconds to wait before raising. — default `120.0`
- `interval` (`float`): Seconds between status polls. — default `5.0`
- `target_state` (`str | None`): Raw registry status string to wait for specifically. — default `None`

### `async_wait_for_status`

```python
RegistryClient.async async_wait_for_status(domain: str, *, timeout: float = 120.0, interval: float = 5.0, target_state: str | None = None) -> RegistryAgentStatus
```

Async variant of `wait_for_status`.

Sleeps with ``asyncio.sleep`` between polls so the event loop is not
blocked.  The status fetch itself is synchronous (httpx).

### `unregister_agent`

```python
RegistryClient.unregister_agent(domain: str) -> None
```

Best-effort unregister. Silently ignores 404 and 405.

``DELETE /api/v1/agent/{domain}``

### `canonical_record_content`

```python
RegistryClient.canonical_record_content(domain: str, signing_kid: str) -> CanonicalRecordContentResponse
```

Fetch the registry's canonical TXT record content for signing.

``POST /api/v1/agent/{domain}/record``

Returns a `CanonicalRecordContentResponse` with the canonical
byte string and the registry's view of the active signing key ID.
The SDK MUST validate both before signing; this response is not trusted input.

### `publish_signature`

```python
RegistryClient.publish_signature(domain: str, sig: str) -> PublishedRecord
```

Submit the record signature to complete the publish workflow.

``POST /api/v1/agent/{domain}/signature``

*sig* MUST be the profile-owned sg value.  For draft 01 this is the bare
unpadded base64url signature bytes.

### `prepare_issuance`

```python
RegistryClient.prepare_issuance(domain: str, idempotency_key: str) -> PreparedRegistryEvent
```

Fetch exact raw ISSUANCE bytes for operational countersigning.

``POST /api/v1/agent/{domain}/tlog/issuance/prepare`` has no request
body. Both the response bytes and ``DNSID-Log-Reference`` header are
untrusted and must be validated by the C2SP prepared-event binding.

### `prepare_key_rotation`

```python
RegistryClient.prepare_key_rotation(domain: str, request: KeyRotationPreparationRequest, idempotency_key: str) -> PreparedRegistryEvent
```

Request a registry-prepared KEY_ROTATION envelope.

``POST /api/v1/agent/{domain}/tlog/key-rotation/prepare``

This operation requires owner/session/API-key credentials, not an
agent bearer token. The idempotency key travels as transport metadata
(``Idempotency-Key`` header); reusing it with different key material fails server-side, as
does a second preparation against the same previous key.  Only public
JWK members are sent — a *request.public_key* carrying private
material is rejected locally before any request.

Returns the exact canonical prepared-envelope bytes and bound log
reference as UNTRUSTED input: the caller must parse both with the bound log implementation
(``dnsid.c2sp_tlog.parse_prepared_event``), independently reproduce
the signed bytes, and verify domain, previous key, new key, log
context, and stream-chain fields before adding any signature.

### `submit_prepared_event`

```python
RegistryClient.submit_prepared_event(domain: str, entry_bytes: bytes, idempotency_key: str) -> SubmissionResult
```

Submit exact complete canonical entry bytes for append.

``POST /api/v1/agent/{domain}/tlog/events``

The bytes are sent unchanged as the application/json request body;
a timeout or indeterminate result is retried with the same bytes and
the same idempotency key.  The registry's durable idempotency mapping
returns the original pending/accepted result for the same
(identity, key, byte-hash) triple and rejects key reuse with
different bytes.

## `AgentRegistrationInput`

```python
from dnsid import AgentRegistrationInput
```

Input for registering an agent with the registry.

## `AgentRegistration`

```python
from dnsid import AgentRegistration
```

Agent registration record returned by the registry.

## `LiveAgentRegistrationInput`

```python
from dnsid import LiveAgentRegistrationInput
```

Input for the dedicated managed Live registration operation.

## `LiveChallengeTranscript`

```python
from dnsid import LiveChallengeTranscript
```

Validated transcript encoded by a managed Live proof challenge.

## `LiveProvisioningResponse`

```python
from dnsid import LiveProvisioningResponse
```

Proof challenge returned when managed Live provisioning starts.

## `LiveProofRequest`

```python
from dnsid import LiveProofRequest
```

Signed proof submitted after managed Live registration.

## `LiveProofResponse`

```python
from dnsid import LiveProofResponse
```

Durable handoff status returned after managed Live proof.

## `LiveProofReissueRequest`

```python
from dnsid import LiveProofReissueRequest
```

Request for a replacement managed Live proof challenge.

The original public key is local validation context and is not sent to the
registry.

## `LiveProofReissueResponse`

```python
from dnsid import LiveProofReissueResponse
```

Replacement challenge returned for an expired managed Live proof.

## `LifecycleResult`

```python
from dnsid import LifecycleResult
```

Lifecycle transition result.

Returned by registry mutation endpoints such as ``submit_challenge_signature``.

## `RegistryAgentStatus`

```python
from dnsid import RegistryAgentStatus
```

Registry workflow status, kept separate from protocol ``AgentStatus``.

## `CanonicalRecordContentResponse`

```python
from dnsid import CanonicalRecordContentResponse
```

Registry-prepared canonical TXT record content for a local identity signing workflow.

## `PublishedRecord`

```python
from dnsid import PublishedRecord
```

Record returned after a successful publish_to_registry call.

## `PreparedRegistryEvent`

```python
from dnsid import PreparedRegistryEvent
```

Raw untrusted bytes and log context returned by a prepare endpoint.

## `KeyRotationPreparationRequest`

```python
from dnsid import KeyRotationPreparationRequest
```

Input for RegistryClient.prepare_key_rotation.

*previous_key_id* is the RFC 7638 thumbprint of the current operational
key — the registry rejects a stale or concurrent rotation.  *public_key*
is one pending public signing key including kid and alg; private JWK
members are forbidden and never leave the SDK.

## `KeyRotationResult`

```python
from dnsid import KeyRotationResult
```

Durable recovery state for a managed operational-key rotation.

Entry bytes, their hash, key bindings, and the idempotency key are fixed
once first persisted. When *activated* is False, call
``IdentityManager.resume_key_rotation(registry_client, result)`` to retry
the exact same bytes under the same idempotency key. Application signing
remains paused until accepted submission, local activation/supersession,
and durable state reconciliation all complete.

## `SubmissionResult`

```python
from dnsid import SubmissionResult
```

Typed result of RegistryClient.submit_prepared_event.

*state* is one of "pending", "accepted", or "rejected".  A pending or
otherwise indeterminate submission is retried with the exact same entry
bytes and idempotency key; the entry is never regenerated.

**Attributes:**

- `accepted` (`bool`): Return True when the registry reported the appended entry as accepted.
