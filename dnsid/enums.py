"""Enumerations shared across the DNSid SDK.

Covers DNSSEC handling, verification failure categories, agent lifecycle
states, revocation reasons, ledger event types, and log signer roles.
"""

from __future__ import annotations

from enum import Enum, StrEnum, auto


class DNSSECState(Enum):
    """Outcome of DNSSEC validation for a DNS response.

    Values:

    * UNSIGNED — zone has no DNSSEC; proceed at lower assurance.
    * VALID — chain of trust from the root validated successfully.
    * FAILED — validation attempted and failed; the record MUST be rejected.
    * UNKNOWN — resolver does not support DNSSEC (no AD bit).
    """

    UNSIGNED = auto()  # zone has no DNSSEC; proceed at lower assurance
    VALID = auto()  # chain of trust from root validated successfully
    FAILED = auto()  # validation attempted and failed; record MUST be rejected
    UNKNOWN = auto()  # resolver does not support DNSSEC (no AD bit)


class DNSSECMode(StrEnum):
    """Controls how VerifyDomain responds to DNSSECState.

    Regardless of mode, FAILED always aborts.

    Values:

    * AUTO — hard-fail on FAILED; permit VALID, UNSIGNED, and UNKNOWN.
    * VALIDATED — permit VALID and UNSIGNED; fail on FAILED or UNKNOWN.
    * REQUIRED — fail unless VALID.
    """

    AUTO = "auto"  # hard-fail on FAILED; permit VALID, UNSIGNED, and UNKNOWN
    VALIDATED = "validated"  # require a conclusive VALID or UNSIGNED result
    REQUIRED = "required"  # fail unless VALID


class VerificationCode(Enum):
    """Identifies the failure category in VerificationError.

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
    """

    DNS_RESOLUTION = auto()  # DNS lookup failed (network error or NXDOMAIN). Transient.
    DNSSEC_FAILED = auto()  # DNSSEC attempted and failed. Permanent.
    RECORD_INVALID = auto()  # Wrong number of TXT records or parse/validation failure. Permanent.
    SIGNATURE_INVALID = auto()  # No JWKS key could verify the sg tag. Permanent.
    TLS_ERROR = auto()  # TLS cert error or disallowed redirect. Permanent.
    KEY_AGE_EXCEEDED = auto()  # Signing key older than ka tag permits. Permanent.
    STATUS_NOT_ACTIVE = auto()  # su endpoint returned non-ACTIVE state. Permanent.
    STATUS_UNAVAILABLE = auto()  # su endpoint unreachable (transport failure). Transient.
    LOG_ERROR = auto()  # Log unreachable (Transient) or proof failed (Permanent).
    COUNTERPARTY_NOT_ACCEPTED = auto()  # Configured policy denied verified counterparty. Permanent.


class AgentState(StrEnum):
    """Lifecycle state values returned by the status endpoint.

    PENDING, PROVISIONING, and VERIFYING are pre-operational; ACTIVE is the
    only state verification accepts; RETIRED is a graceful decommissioning
    and REVOKED a forced termination — both terminal.
    """

    PENDING = "PENDING"
    PROVISIONING = "PROVISIONING"
    VERIFYING = "VERIFYING"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


class RevocationReason(StrEnum):
    """Reason codes for REVOKED agent state."""

    KEY_COMPROMISE = "keyCompromise"
    POLICY_VIOLATION = "policyViolation"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessationOfOperation"


class RegistryRevocationReason(StrEnum):
    """Owner-authorized reason codes accepted by the registry revoke API."""

    OWNER_REQUEST = "owner_request"
    KEY_COMPROMISE = "key_compromise"


class EventType(StrEnum):
    """Ledger event type identifiers."""

    ISSUANCE = "ISSUANCE"
    KEY_ROTATION = "KEY_ROTATION"
    REVOCATION = "REVOCATION"
    RETIREMENT = "RETIREMENT"
    MIGRATION = "MIGRATION"
    DELEGATION = "DELEGATION"


class LifecycleErrorCategory(StrEnum):
    """Stable failure categories for the shared lifecycle reducer."""

    GENESIS_REQUIRED = "GENESIS_REQUIRED"
    DUPLICATE_ISSUANCE = "DUPLICATE_ISSUANCE"
    INVALID_ISSUANCE = "INVALID_ISSUANCE"
    TERMINAL_STATE = "TERMINAL_STATE"
    DOMAIN_MISMATCH = "DOMAIN_MISMATCH"
    KEY_CONTINUITY = "KEY_CONTINUITY"
    INVALID_REVOCATION_REASON = "INVALID_REVOCATION_REASON"
    INVALID_MIGRATION = "INVALID_MIGRATION"
    SNAPSHOT_EMPTY = "SNAPSHOT_EMPTY"
    SNAPSHOT_NON_PREFIX = "SNAPSHOT_NON_PREFIX"
    UNSUPPORTED_EVENT = "UNSUPPORTED_EVENT"


class LogSignerRole(StrEnum):
    """Profile-owned signer roles for lifecycle log events.

    A concrete log binding may require additional method-owned roles without
    replacing or weakening these.
    """

    ENTITY = "Entity"
    OPERATIONAL = "Operational"
    OPERATIONAL_COUNTERSIGNATURE = "OperationalCountersignature"
    PREVIOUS_OPERATIONAL = "PreviousOperational"
