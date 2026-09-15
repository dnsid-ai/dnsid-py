---
title: "Python: Errors and enumerations"
description: "Exception hierarchy and enumerations of the dnsid package."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

## `DNSidError`

```python
from dnsid import DNSidError
```

*Bases:* `Exception`

Base for all DNSid SDK errors.

## `ParseError`

```python
from dnsid import ParseError
```

*Bases:* `DNSidError`

TXT record RDATA is structurally malformed (syntax, missing/duplicate tags).

Never transient; retry will not help.

## `ValidationError`

```python
from dnsid import ValidationError
```

*Bases:* `DNSidError`

Data parses correctly but violates semantic constraints.

Examples: malformed gi; ku host mismatch; bad ka value.
Never transient.

## `VerificationError`

```python
from dnsid import VerificationError
```

*Bases:* `DNSidError`

A live verification step failed.

Carries a structured code and transient flag so callers can decide whether to
retry and what to surface to users or logs.

### `VerificationError` constructor

```python
VerificationError(code: VerificationCode, message: str, transient: bool = False, agent_state: str | None = None, category: str | None = None, cause: BaseException | None = None, verified_governance_id: str | None = None, verified_entity_key_thumbprint: str | None = None) -> None
```

Initialize the error with a structured code and message.

**Arguments:**

- `code` (`VerificationCode`): Failure category from `VerificationCode`.
- `message` (`str`): Human-readable description of the failure.
- `transient` (`bool`): True when retrying the operation may succeed. — default `False`
- `agent_state` (`str | None`): Agent lifecycle state reported by the status endpoint, when known. — default `None`
- `category` (`str | None`): Stable lifecycle failure-category string, when the failure maps to one (see LifecycleErrorCategory). — default `None`
- `cause` (`BaseException | None`): Underlying exception to chain as ``__cause__``. — default `None`
- `verified_governance_id` (`str | None`): For ``COUNTERPARTY_NOT_ACCEPTED`` only, the observed verified governance ID. — default `None`
- `verified_entity_key_thumbprint` (`str | None`): For ``COUNTERPARTY_NOT_ACCEPTED`` only, the observed record-signing key's RFC 7638 thumbprint. — default `None`

## `RegistryRequestError`

```python
from dnsid import RegistryRequestError
```

*Bases:* `VerificationError`

The registry answered a request with a non-2xx status.

A `VerificationError` (code ``LOG_ERROR``) so existing handlers keep
working, plus the two facts a caller can act on: the HTTP status and the
registry's short ``error`` code (``INVALID_TRANSITION``, ``NOT_FOUND`` …).
The response body is never echoed into the message: an authenticated
request's error body may repeat request metadata.

### `RegistryRequestError` constructor

```python
RegistryRequestError(path: str, status_code: int, error_code: str = '') -> None
```

Build the error for *path* from the status and the registry's error code.

## `LifecycleVerificationError`

```python
from dnsid import LifecycleVerificationError
```

*Bases:* `VerificationError`

A verified lifecycle history violates the shared reducer contract.

### `LifecycleVerificationError` constructor

```python
LifecycleVerificationError(category: LifecycleErrorCategory, message: str, failing_event_index: int | None = None) -> None
```

Initialize with a lifecycle failure category and message.

**Arguments:**

- `category` (`LifecycleErrorCategory`): Stable failure category from LifecycleErrorCategory; also exposed as the string ``category`` on the base class.
- `message` (`str`): Human-readable description of the violation.
- `failing_event_index` (`int | None`): Zero-based index of the offending event in the verified history, when identifiable. — default `None`

## `LifecycleErrorCategory`

```python
from dnsid import LifecycleErrorCategory
```

Stable failure categories for the shared lifecycle reducer.

**Members:**

- `GENESIS_REQUIRED` = `'GENESIS_REQUIRED'`
- `DUPLICATE_ISSUANCE` = `'DUPLICATE_ISSUANCE'`
- `INVALID_ISSUANCE` = `'INVALID_ISSUANCE'`
- `TERMINAL_STATE` = `'TERMINAL_STATE'`
- `DOMAIN_MISMATCH` = `'DOMAIN_MISMATCH'`
- `KEY_CONTINUITY` = `'KEY_CONTINUITY'`
- `INVALID_REVOCATION_REASON` = `'INVALID_REVOCATION_REASON'`
- `INVALID_MIGRATION` = `'INVALID_MIGRATION'`
- `SNAPSHOT_EMPTY` = `'SNAPSHOT_EMPTY'`
- `SNAPSHOT_NON_PREFIX` = `'SNAPSHOT_NON_PREFIX'`
- `UNSUPPORTED_EVENT` = `'UNSUPPORTED_EVENT'`

## `ArgumentError`

```python
from dnsid import ArgumentError
```

*Bases:* `DNSidError`

Caller-supplied argument is invalid (wrong format, reserved field override, etc.).

## `NetworkError`

```python
from dnsid import NetworkError
```

*Bases:* `DNSidError`

OIDC discovery, JWKS, or token endpoint transport failure.

## `OAuthError`

```python
from dnsid import OAuthError
```

*Bases:* `DNSidError`

OIDC token endpoint returned an OAuth error response.

### `OAuthError` constructor

```python
OAuthError(error: str = '', error_description: str = '') -> None
```

Initialize from an OAuth error response.

**Arguments:**

- `error` (`str`): OAuth 2.0 error code returned by the token endpoint. — default `''`
- `error_description` (`str`): Human-readable description from the response, if any. — default `''`

## `DNSSECState`

```python
from dnsid import DNSSECState
```

Outcome of DNSSEC validation for a DNS response.

Values:

* UNSIGNED — zone has no DNSSEC; proceed at lower assurance.
* VALID — chain of trust from the root validated successfully.
* FAILED — validation attempted and failed; the record MUST be rejected.
* UNKNOWN — resolver does not support DNSSEC (no AD bit).

**Members:**

- `UNSIGNED` = `auto()`
- `VALID` = `auto()`
- `FAILED` = `auto()`
- `UNKNOWN` = `auto()`

## `DNSSECMode`

```python
from dnsid import DNSSECMode
```

Controls how VerifyDomain responds to DNSSECState.

Regardless of mode, FAILED always aborts.

Values:

* AUTO — hard-fail on FAILED; permit VALID, UNSIGNED, and UNKNOWN.
* VALIDATED — permit VALID and UNSIGNED; fail on FAILED or UNKNOWN.
* REQUIRED — fail unless VALID.

**Members:**

- `AUTO` = `'auto'`
- `VALIDATED` = `'validated'`
- `REQUIRED` = `'required'`

## `VerificationCode`

```python
from dnsid import VerificationCode
```

Identifies the failure category in VerificationError.

Values:

* DNS_RESOLUTION — DNS lookup failed (network error or NXDOMAIN);
  transient.
* DNSSEC_FAILED — DNSSEC validation attempted and failed; permanent.
* RECORD_INVALID — wrong number of TXT records, or record
  parse/validation failure; permanent.
* SIGNATURE_INVALID — no JWKS key could verify the sg tag; permanent.
* TLS_ERROR — TLS certificate error or disallowed redirect; permanent.
* KEY_AGE_EXCEEDED — signing key older than the ka tag permits; permanent.
* STATUS_NOT_ACTIVE — su endpoint returned a non-ACTIVE state; permanent.
* STATUS_UNAVAILABLE — su endpoint unreachable (transport failure);
  transient.
* LOG_ERROR — log unreachable (transient) or a lifecycle-log proof or
  policy check failed (permanent).
* COUNTERPARTY_NOT_ACCEPTED — configured ``trusted_entities`` policy
  denied a protocol-valid identity; permanent.

**Members:**

- `DNS_RESOLUTION` = `auto()`
- `DNSSEC_FAILED` = `auto()`
- `RECORD_INVALID` = `auto()`
- `SIGNATURE_INVALID` = `auto()`
- `TLS_ERROR` = `auto()`
- `KEY_AGE_EXCEEDED` = `auto()`
- `STATUS_NOT_ACTIVE` = `auto()`
- `STATUS_UNAVAILABLE` = `auto()`
- `LOG_ERROR` = `auto()`
- `COUNTERPARTY_NOT_ACCEPTED` = `auto()`

## `AgentState`

```python
from dnsid import AgentState
```

Lifecycle state values returned by the status endpoint.

PENDING, PROVISIONING, and VERIFYING are pre-operational; ACTIVE is the
only state verification accepts; RETIRED is a graceful decommissioning
and REVOKED a forced termination — both terminal.

**Members:**

- `PENDING` = `'PENDING'`
- `PROVISIONING` = `'PROVISIONING'`
- `VERIFYING` = `'VERIFYING'`
- `ACTIVE` = `'ACTIVE'`
- `RETIRED` = `'RETIRED'`
- `REVOKED` = `'REVOKED'`

## `RevocationReason`

```python
from dnsid import RevocationReason
```

Reason codes for REVOKED agent state.

**Members:**

- `KEY_COMPROMISE` = `'keyCompromise'`
- `POLICY_VIOLATION` = `'policyViolation'`
- `SUPERSEDED` = `'superseded'`
- `CESSATION_OF_OPERATION` = `'cessationOfOperation'`

## `RegistryRevocationReason`

```python
from dnsid import RegistryRevocationReason
```

Owner-authorized reason codes accepted by the registry revoke API.

**Members:**

- `OWNER_REQUEST` = `'owner_request'`
- `KEY_COMPROMISE` = `'key_compromise'`

## `EventType`

```python
from dnsid import EventType
```

Ledger event type identifiers.

**Members:**

- `ISSUANCE` = `'ISSUANCE'`
- `KEY_ROTATION` = `'KEY_ROTATION'`
- `REVOCATION` = `'REVOCATION'`
- `RETIREMENT` = `'RETIREMENT'`
- `MIGRATION` = `'MIGRATION'`
- `DELEGATION` = `'DELEGATION'`
