"""Abstract base classes and protocols for all pluggable SDK dependencies."""

from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .enums import DNSSECState, VerificationCode
from .exceptions import VerificationError
from .models import (
    JWK,
    AgentRegistration,
    AnyLogEvent,
    CanonicalRecordContentResponse,
    DnsIdTxtRecord,
    KeyRotationPreparationRequest,
    LogEvent,
    LoggedStateEvidence,
    LogRef,
    PreparedRegistryEvent,
    PublishedRecord,
    RegistryAgentStatus,
    SubmissionResult,
    TLSCertificate,
    TXTRecord,
    VerifiedCutoffHistory,
    VerifiedDomain,
)

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# IdentityResolver
# ---------------------------------------------------------------------------


@runtime_checkable
class IdentityResolver(Protocol):
    """Minimal interface required by application-layer profiles.

    Any object exposing verify_domain with this signature satisfies the protocol
    structurally — no inheritance needed.  IdentityManager satisfies it.
    Profiles (JoseProfile, HttpSignatureProfile, WebBotAuthProfile, OIDCProfile)
    accept IdentityResolver so they can be tested with lightweight doubles instead
    of a full IdentityManager.
    """

    def verify_domain(
        self,
        domain: str,
        peer_cert: TLSCertificate | None = None,
    ) -> VerifiedDomain:
        """Verify the DNSid identity record for *domain*.

        Args:
            domain: Agent FQDN to verify.
            peer_cert: TLS certificate of the live peer connection, when the
                caller wants channel binding against the identity record.

        Returns:
            A VerifiedDomain describing the verified identity.

        Raises:
            VerificationError: If any verification step fails.
        """
        ...


# ---------------------------------------------------------------------------
# KeyProvider
# ---------------------------------------------------------------------------


class KeyProvider(ABC):
    """Standardized interface for Key Management Systems.

    Implementations may wrap local key files, cloud KMS (AWS KMS, GCP Cloud KMS,
    Azure Key Vault), or HSMs.  The SDK never handles private key material directly.

    Key lifecycle states:
      Pending    — generated but not yet promoted; excluded from JWKS.
      Active     — current signing key; the single key in the live JWKS.
      Superseded — rotated out; retained only in log/archive/KMS for audit.
                   Not in the live JWKS and never used for signing; historical
                   verification uses key material recorded in the lifecycle log.

    Driving generate_key/activate/supersede directly does not record the
    KEY_ROTATION lifecycle event; for a registry-managed draft 01 rotation use
    IdentityManager.rotate_operational_key, which appends the event before
    activating the new key.
    """

    # ------------------------------------------------------------------
    # Runtime methods — called internally by the SDK
    # ------------------------------------------------------------------

    @abstractmethod
    def signing_key(self) -> JWK:
        """Return the JWK of the current active signing key (public side only).

        The returned kid MUST NOT contain '#' because application-layer helpers
        encode key IDs as '{domain}#{kid}'.
        """

    @abstractmethod
    def jwk(self, kid: str) -> JWK:
        """Return the JWK for the given kid (active or retained).

        Raises:
            ArgumentError: If *kid* is not found.
        """

    @abstractmethod
    def list_key_ids(self) -> list[str]:
        """Return IDs of all active and retained keys (pending excluded).

        The active key ID MUST appear first; retained keys follow in any order.
        """

    @abstractmethod
    def sign(self, payload: bytes) -> bytes:
        """Sign *payload* with the current active key.

        Returns:
            Raw signature bytes.
        """

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        """Sign *payload* with a specified active or pending key.

        Used for rotation authorization and proof of possession, where the
        signing key is not (yet) the active key.  Providers that cannot
        address keys by kid may leave this unimplemented.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support signing by kid")

    # ------------------------------------------------------------------
    # Management methods — called by operator code during key rotation
    # ------------------------------------------------------------------

    @abstractmethod
    def generate_key(self) -> str:
        """Generate a new key pair in the pending state.

        Returns:
            The kid of the newly generated key.
        """

    @abstractmethod
    def activate(self, kid: str) -> None:
        """Promote *kid* from pending to active; previous active transitions to retained.

        Raises:
            ArgumentError: If *kid* is unknown or already active/retained.
        """

    @abstractmethod
    def supersede(self, kid: str) -> None:
        """Rotate *kid* out of live use after a completed key rotation.

        The key leaves the live JWKS and is never used for signing again;
        implementations may retain the material in a log/archive/KMS for audit.

        Raises:
            ArgumentError: If *kid* is the current active key (activate a
                replacement first).
        """


# ---------------------------------------------------------------------------
# Log (ledger write interface)
# ---------------------------------------------------------------------------


class Log(ABC):
    """Write interface for the agent's own immutable ledger.

    Implementations may wrap a blockchain, CT-style transparency log,
    SCITT transparency service, or any append-only verifiable log.
    Canonical serialization is log-method-specific; Log.canonical and
    LogReader.canonical MUST produce identical bytes for the same event.
    """

    @abstractmethod
    def canonical(self, event: LogEvent) -> bytes:
        """Return the canonical byte representation of *event* for this log method.

        Used by IdentityManager.sign_and_write_event to produce bytes that are signed.
        """

    @abstractmethod
    def write_event(self, event: LogEvent) -> LogRef:
        """Append a signed event to the log.

        *event* MUST already carry sig; implementations MUST reject unsigned
        events or events with invalid signatures.

        Returns:
            A LogRef identifying the recorded entry.
        """


# ---------------------------------------------------------------------------
# LogReader (ledger read/verify interface)
# ---------------------------------------------------------------------------


class LogReader(ABC):
    """Read and verify interface for a specific ledger entry.

    Bound at construction to a full lr value (e.g. 'algorand:AGENT_ADDR_BASE32').
    The implementation stores the entry reference internally; callers do not pass
    it per-method.  All methods MUST verify cryptographic inclusion proofs,
    verifiable timestamps, and append-only consistency before returning.
    """

    @abstractmethod
    def canonical(self, event: LogEvent) -> bytes:
        """Return the canonical byte representation of *event* for this log method.

        MUST produce identical output to Log.canonical for the same event.
        """

    @abstractmethod
    def key_timestamp(self, domain: str, key_thumbprint: str) -> datetime.datetime:
        """Return the timestamp when *key_thumbprint* was bound to *domain*.

        Matches ISSUANCE or KEY_ROTATION events.  Used for ka validation.
        MUST verify inclusion proof, timestamp proof, and append-only consistency.
        """

    @abstractmethod
    def verify_non_revocation(
        self, domain: str, at: datetime.datetime
    ) -> LoggedStateEvidence:
        """Verify complete, fresh, non-terminal history for *domain* through *at*.

        MUST verify the cryptographic evidence required by the log binding and
        return the accepted proof boundary.

        Raises:
            VerificationError: With LOG_ERROR if a terminal entry is found or
                complete, fresh log evidence cannot be established.
        """

    @abstractmethod
    def read_event(self, ref: LogRef) -> AnyLogEvent:
        """Read a single event by log reference.

        MUST verify inclusion proof and timestamp proof before returning.
        """

    @abstractmethod
    def rebuild_history(self, domain: str) -> list[AnyLogEvent]:
        """Rebuild the full event history for *domain* in chronological order.

        MUST verify inclusion proofs, timestamp proofs, and append-only consistency.
        """

    def rebuild_history_through(
        self,
        domain: str,
        final_entry_ref: str,
        entity_key: JWK,
        *,
        max_depth: int,
        max_events: int,
        max_response_bytes: int,
        seen_log_references: frozenset[str],
    ) -> VerifiedCutoffHistory:
        """Verify history through exactly *final_entry_ref* within cumulative bounds.

        Bindings supporting migration predecessors override this method. The
        returned event references MUST parallel ``events`` and end at the exact
        signed cutoff; ``response_bytes`` reports bytes consumed by this read.
        """
        raise VerificationError(
            VerificationCode.LOG_ERROR,
            f"{type(self).__name__} does not support exact-cutoff history verification",
        )

    # ------------------------------------------------------------------
    # Draft 01 binding-level lifecycle operations
    # ------------------------------------------------------------------
    # Full draft 01 verification requires these; bindings that cannot perform
    # them keep the fail-closed defaults, and verify_domain then rejects
    # draft 01 records read through such a binding.

    def verify_bilateral_binding(
        self, record: DnsIdTxtRecord, entity_key: JWK, operational_key: JWK
    ) -> Any:
        """Verify the draft 01 bilateral ISSUANCE binding for *record*.

        Confirms the logged ISSUANCE (or verified MIGRATION genesis) binds the
        record's identity to *entity_key* (ek) and an initial operational key,
        with both authorizing signatures verified.

        Returns:
            A binding object exposing at least ``initial_operational_thumbprint``.

        Raises:
            VerificationError: With LOG_ERROR when the binding does not
                support this operation.
        """
        raise VerificationError(
            VerificationCode.LOG_ERROR,
            f"{type(self).__name__} does not support verify_bilateral_binding "
            "required by draft 01 verification",
        )

    def verify_operational_continuity(
        self,
        domain: str,
        initial_operational_thumbprint: str,
        current_operational_thumbprint: str,
    ) -> None:
        """Verify the logged KEY_ROTATION chain between two operational keys.

        Confirms the chain of logged KEY_ROTATION events connects the initial
        operational key from the ISSUANCE binding to the currently published
        operational key for *domain*.

        Raises:
            VerificationError: With LOG_ERROR when unsupported or when the
                chain does not connect the two thumbprints.
        """
        raise VerificationError(
            VerificationCode.LOG_ERROR,
            f"{type(self).__name__} does not support verify_operational_continuity "
            "required by draft 01 verification",
        )


# ---------------------------------------------------------------------------
# NoopLogReader — returned for unknown ledger methods
# ---------------------------------------------------------------------------


class NoopLogReader(LogReader):
    """Placeholder LogReader for ledger methods with no registered factory.

    Every method raises VerificationError(LedgerError) with a descriptive message.
    This lets non-log-dependent interactive verification succeed while making log
    evidence failures explicit and descriptive when actually required.
    """

    def __init__(self, method: str) -> None:
        """Record the unregistered log method for error messages.

        Args:
            method: Log method name that has no registered LogReader factory.
        """
        self._method = method

    def _raise(self) -> None:
        from .enums import VerificationCode
        from .exceptions import VerificationError

        raise VerificationError(
            VerificationCode.LOG_ERROR,
            f"no LogReader registered for log method {self._method!r}",
            transient=False,
        )

    def canonical(self, event: LogEvent) -> bytes:
        """Raise VerificationError(LOG_ERROR); no LogReader is registered for this method."""
        self._raise()
        return b""  # unreachable; satisfies type checker

    def key_timestamp(self, domain: str, key_thumbprint: str) -> datetime.datetime:
        """Raise VerificationError(LOG_ERROR); no LogReader is registered for this method."""
        self._raise()
        return datetime.datetime.min  # unreachable

    def verify_non_revocation(
        self, domain: str, at: datetime.datetime
    ) -> LoggedStateEvidence:
        """Raise VerificationError(LOG_ERROR); no LogReader is registered for this method."""
        self._raise()
        raise RuntimeError("unreachable")

    def read_event(self, ref: LogRef) -> AnyLogEvent:
        """Raise VerificationError(LOG_ERROR); no LogReader is registered for this method."""
        self._raise()
        raise RuntimeError("unreachable")

    def rebuild_history(self, domain: str) -> list[AnyLogEvent]:
        """Raise VerificationError(LOG_ERROR); no LogReader is registered for this method."""
        self._raise()
        return []  # unreachable

# ---------------------------------------------------------------------------
# IdentityCache
# ---------------------------------------------------------------------------


class IdentityCache(ABC):
    """Cache for verified domain results.

    Implementations MUST be safe for concurrent use.
    Get MUST return None for entries whose VerifiedDomain.expiry() has passed.
    Put MUST derive the entry TTL from result.expiry() and evict automatically.
    """

    @abstractmethod
    def get(self, domain: str) -> VerifiedDomain | None:
        """Return the cached VerifiedDomain, or None if absent or expired."""

    @abstractmethod
    def put(self, domain: str, result: VerifiedDomain) -> None:
        """Store *result*. Entry expires at result.expiry()."""

    @abstractmethod
    def evict(self, domain: str) -> None:
        """Remove *domain* from the cache immediately."""


# ---------------------------------------------------------------------------
# DNSResolver
# ---------------------------------------------------------------------------


class DNSResolver(ABC):
    """Pluggable DNS resolver.

    Decouples VerifyDomain from the system resolver so deployments can substitute
    a DNSSEC-validating library, a trusted DoT/DoH upstream, or a test double.
    """

    @abstractmethod
    def fetch_txt(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        """Fetch TXT records for *name* (normalized FQDN, no trailing dot).

        Implementations MUST treat *name* as an absolute name — no search-domain
        expansion.  Returns the record set and the DNSSEC validation state.
        """


# ---------------------------------------------------------------------------
# HTTPSFetcher
# ---------------------------------------------------------------------------


class HTTPSFetcher(ABC):
    """Pluggable HTTPS JSON fetch dependency.

    Decouples VerifyDomain from any particular runtime HTTP stack while preserving
    DNSid TLS and redirect semantics.  Language bindings may expose this dependency
    as a configured HTTP client, transport, session, or other idiomatic abstraction.

    Injected via IdentityManagerDependencies.https_fetcher.  When omitted,
    IdentityManager uses a default implementation backed by TransportConfig.

    Implementations MUST be safe for concurrent use: after the record
    signature is authenticated, verify_domain fetches the status endpoint on
    a helper thread while the runtime JWKS and lifecycle-log work proceed.

    The built-in fetcher enforces strict HTTPS and rejects su/JWKS hosts that
    resolve to non-public addresses unless the hostname matches an exact or
    leading-dot suffix entry in TransportConfig.private_address_hosts. A blocked
    resolution raises a
    non-transient VerificationError with TLS_ERROR.
    """

    @abstractmethod
    def fetch_strict_json(
        self,
        url: str,
        allowed_host: str | None = None,
        domain_boundary: bool = False,
    ) -> tuple[dict[str, Any], TLSCertificate]:
        """Fetch and parse a JSON document from an HTTPS URL.

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

        Raises:
            VerificationError: With TLS_ERROR on certificate failures or
                disallowed redirects; transient MUST be True for retryable
                transport conditions (e.g. handshake timeouts) and False for
                policy failures (e.g. a redirect to a non-HTTPS URL).  With
                DNS_RESOLUTION and transient=True on network errors (DNS,
                connect, request timeouts) — callers use the transient flag
                to classify status-endpoint availability.
        """


# ---------------------------------------------------------------------------
# AbstractRegistryClient
# ---------------------------------------------------------------------------


class AbstractRegistryClient(ABC):
    """Abstract interface for operator-side DNSid registry workflows.

    Defines the core methods specified by the DNSid registry transport design.
    The bundled :class:`~dnsid.registry_client.RegistryClient` is the default
    concrete implementation; inject a custom subclass via
    :class:`~dnsid.manager.IdentityManager` workflows when needed.

    ``AbstractRegistryClient`` is NOT used by ``VerifyDomain`` — protocol
    verification always fetches the ``su`` endpoint asserted in the signed TXT
    record and never contacts the registry operator API.
    """

    @abstractmethod
    def get_registration(self, domain: str) -> AgentRegistration | None:
        """Return the operator workflow record, or ``None`` if unregistered."""

    @abstractmethod
    def wait_for_status(
        self,
        domain: str,
        *,
        timeout: float = 120.0,
        interval: float = 5.0,
        target_state: str | None = None,
    ) -> RegistryAgentStatus:
        """Wait for publication or an explicitly requested workflow state."""

    @abstractmethod
    def canonical_record_content(
        self, domain: str, signing_kid: str
    ) -> CanonicalRecordContentResponse:
        """Fetch the registry's canonical TXT record content for signing.

        POST ``{baseUrl}/api/v1/agent/{domain}/record``.
        The SDK MUST validate the response before signing; it is not trusted input.
        """

    @abstractmethod
    def publish_signature(self, domain: str, sig: str) -> PublishedRecord:
        """Submit the profile-encoded signature to complete the publish workflow.

        POST ``{baseUrl}/api/v1/agent/{domain}/signature``.
        Draft 01 requires bare unpadded base64url signature bytes.
        """

    @abstractmethod
    def prepare_issuance(self, domain: str, idempotency_key: str) -> PreparedRegistryEvent:
        """Fetch exact untrusted accountable-entity-signed ISSUANCE bytes.

        POST ``{baseUrl}/api/v1/agent/{domain}/tlog/issuance/prepare`` with no
        body and the supplied ``Idempotency-Key`` header. The returned log
        reference is transport context and remains unparsed at this boundary.
        """

    @abstractmethod
    def prepare_key_rotation(
        self,
        domain: str,
        request: KeyRotationPreparationRequest,
        idempotency_key: str,
    ) -> PreparedRegistryEvent:
        """Return an untrusted registry-prepared KEY_ROTATION response.

        The caller independently parses and verifies the exact returned bytes
        against the returned log reference before adding any signature.
        """

    @abstractmethod
    def submit_prepared_event(
        self,
        domain: str,
        entry_bytes: bytes,
        idempotency_key: str,
    ) -> SubmissionResult:
        """Submit exact prepared-event bytes under a durable idempotency key."""
