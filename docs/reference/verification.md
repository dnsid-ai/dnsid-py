---
title: "Python: Verification results"
description: "Results of domain verification: VerifiedDomain, the domain log and snapshot models, and lifecycle log events."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

## `VerifiedDomain`

```python
from dnsid import VerifiedDomain
```

Result of a successful VerifyDomain call.

All fields are verified and immutable from the caller's perspective.

**Attributes:**

- `domain` (`str`): Normalized FQDN that was verified.
- `record` (`DnsIdTxtRecord`): The parsed and validated identity record.
- `jwks` (`JWKS`): The verified operational (ku) key set.
- `signing_key` (`JWK`): The entity (ek) key that verified the record's sg value.
- `tls_cert` (`TLSCertificate`): TLS certificate presented by the ku endpoint fetch.
- `registry_status` (`AgentStatus`): Status document from the most recent su fetch.
- `verified_at` (`datetime.datetime`): When verification was performed.
- `dns_ttl` (`int`): DNS TTL of the TXT record, in seconds.
- `key_bound_at` (`datetime.datetime`): When the operational key was bound per the lifecycle log (zero time when the record carries no ka tag).
- `last_status_check_at` (`datetime.datetime`): When the su endpoint was last fetched.
- `dnssec_state` (`DNSSECState`): DNSSEC validation result for the TXT lookup.
- `log_reader` (`LogReader`): Log reader bound to the record's lr reference and used by ``IdentityManager.verify_log_evidence``.
- `record_signing_jwks` (`JWKS | None`): The ek key set that verified the record signature (draft 01 evidence).
- `record_signing_tls_cert` (`TLSCertificate | None`): TLS certificate presented by the ek endpoint fetch; its NotAfter bounds expiry().

### `cached_state`

```python
VerifiedDomain.cached_state() -> str
```

Return the agent state from the most recent su fetch.

This reflects lastStatusCheckAt, not necessarily right now. For a live
status check before a new operation, call VerifyDomain again.

### `requires_log_check`

```python
VerifiedDomain.requires_log_check() -> bool
```

Return whether the record carries the operation-level ``logchk`` flag.

### `expiry`

```python
VerifiedDomain.expiry() -> datetime.datetime
```

Return the earliest of all cache validity bounds.

Candidates: DNS TTL, TLS cert NotAfter, key age (if ka set), JWK exp.

## `LoggedStateEvidence`

```python
from dnsid import LoggedStateEvidence
```

Verified complete lifecycle-log state retained for an operation.

``logged_state`` describes lifecycle history, not current protocol status.
``complete_through`` and ``checkpoint`` are binding-specific evidence.

**Attributes:**

- `log_reference` (`str`): Complete identity-instance log reference.
- `logged_state` (`str`): Verified lifecycle state through ``history_end``.
- `history_start` (`str`): Binding-specific genesis event reference.
- `history_end` (`str | None`): Binding-specific final applied event reference, if any.
- `complete_through` (`object`): Binding-specific completeness boundary.
- `completeness_mode` (`str`): Accepted binding-defined completeness mechanism.
- `checkpoint` (`object`): Accepted checkpoint or equivalent log-state evidence.
- `freshness_time` (`datetime.datetime`): Independently verified freshness timestamp.

## `VerifiedCutoffHistory`

```python
from dnsid import VerifiedCutoffHistory
```

Method-neutral lifecycle history verified through an exact event reference.

## `DomainLog`

```python
from dnsid import DomainLog
```

Full verified event history for a domain, loaded from the lifecycle log.

All events have inclusion proofs verified before being stored here.
snapshot_at() is pure computation — no I/O.

### `snapshot_at`

```python
DomainLog.snapshot_at(at: datetime.datetime) -> DomainSnapshot
```

Derive domain state at *at* by replaying a verified lifecycle prefix.

Preserves the verified lifecycle order supplied by the log binding —
timestamps are signed lifecycle metadata, not the log method's ordering
primitive.  Raises VerificationError if no events exist at or before
*at*, if no ISSUANCE event precedes *at*, if the requested boundary is
not a verified lifecycle prefix (an event past *at* is followed by a
later event at or before *at*), or if lifecycle ordering is invalid
(duplicate issuance, rotation/termination outside an ACTIVE issuance,
or events after a terminal state).

## `DomainSnapshot`

```python
from dnsid import DomainSnapshot
```

Materialized state of a domain at a specific point in time.

Derived from a DomainLedger — contains no live data.

## `LogRef`

```python
from dnsid import LogRef
```

Structured log reference: '{method}:{entry_ref}'.

### `parse`

```python
LogRef.parse(lr: str) -> LogRef
```

Raise ParseError if *lr* is malformed.

## `LogEvent`

```python
from dnsid import LogEvent
```

Base class for all log events.

Signature fields are populated by the IdentityManager signing facade
(sign_event / sign_and_write_event); callers fill in all other
(event-specific) fields before passing the event.  Canonicalization
excludes every signature field (*signing_kid*, *sig*,
*operational_countersig*), so adding one signature never changes the
bytes covered by another.

*sig* carries the primary role signature (Entity, Operational, or
PreviousOperational depending on the event type);
*operational_countersig* carries the ISSUANCE operational
countersignature.

## `AnyLogEvent`

```python
from dnsid import AnyLogEvent
```

*Value:* `IssuanceEvent | KeyRotationEvent | RevocationEvent | RetirementEvent | MigrationEvent | DelegationEvent`

## `IssuanceEvent`

```python
from dnsid import IssuanceEvent
```

*Bases:* `LogEvent`

Initial bilateral registration of an agent identity.

## `KeyRotationEvent`

```python
from dnsid import KeyRotationEvent
```

*Bases:* `LogEvent`

Rotation to a new signing key; establishes continuity from previous key.

## `RevocationEvent`

```python
from dnsid import RevocationEvent
```

*Bases:* `LogEvent`

Permanent, forced termination.

## `RetirementEvent`

```python
from dnsid import RetirementEvent
```

*Bases:* `LogEvent`

Graceful end-of-life.

## `MigrationEvent`

```python
from dnsid import MigrationEvent
```

*Bases:* `LogEvent`

Transfer of agent identity history to a new ledger technology.

## `DelegationEvent`

```python
from dnsid import DelegationEvent
```

*Bases:* `LogEvent`

Grants a delegatee agent permission to act within a defined scope.

## `LogSignerRole`

```python
from dnsid import LogSignerRole
```

Profile-owned signer roles for lifecycle log events.

A concrete log binding may require additional method-owned roles without
replacing or weakening these.

**Members:**

- `ENTITY` = `'Entity'`
- `OPERATIONAL` = `'Operational'`
- `OPERATIONAL_COUNTERSIGNATURE` = `'OperationalCountersignature'`
- `PREVIOUS_OPERATIONAL` = `'PreviousOperational'`
