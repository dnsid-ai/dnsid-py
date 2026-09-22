"""IdentityManager — DNSid protocol core.

Responsibilities (spec-defined):
  - TXT record construction and signing (create_txt_record)
  - Domain verification (verify_domain)
  - JWKS publication helper (get_key_set)
  - Lifecycle log write (sign_and_write_event)
  - Registry publication workflow (publish_to_registry)
  - Cache management (evict_domain)
  - Domain log loading (load_domain_log)

Not responsibilities (handled by separate profile classes):
  - JWT / JWS creation and verification  → JoseProfile
  - HTTP Message Signatures              → HttpSignatureProfile
"""

from __future__ import annotations

import datetime
import logging
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import Future
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from ._verification_budget import (
    remaining_seconds,
    run_concurrently,
    verification_operation,
    wait_for_verification,
)

if TYPE_CHECKING:
    import httpcore
    import httpx

    from .interfaces import AbstractRegistryClient

from ._https_client import _create_https_client
from ._utils import (
    b64url_decode_strict,
    normalize_fqdn,
)
from .enums import DNSSECMode, DNSSECState, EventType, LogSignerRole, VerificationCode
from .exceptions import ArgumentError, ValidationError, VerificationError
from .interfaces import (
    DNSResolver,
    HTTPSFetcher,
    IdentityCache,
    KeyProvider,
    Log,
    LogReader,
    NoopLogReader,
)
from .models import (
    _V_DRAFT01,
    JWKS,
    DnsidConfig,
    DnsIdTxtRecord,
    DomainLog,
    IdentityConfig,
    KeyRotationEvent,
    KeyRotationResult,
    LogEvent,
    LoggedStateEvidence,
    LogRef,
    PublishedRecord,
    SubmissionResult,
    TLSCertificate,
    TransportConfig,
    TrustedEntity,
    VerificationConfig,
    VerifiedDomain,
)
from .registry import LogRegistry
from .safe_transport import make_ssrf_safe_transport as _make_sdk_transport

_ZERO_TIME = datetime.datetime.min.replace(tzinfo=datetime.UTC)
_log = logging.getLogger(__name__)

KeyRotationPersistenceHook = Callable[[KeyRotationResult], None]
"""Persist a complete managed-key-rotation recovery state durably."""

ApplicationSigningPauseHook = Callable[[bool], None]
"""Pause or resume creation of new application signatures."""


@dataclass
class IdentityManagerDependencies:
    """Optional dependencies for IdentityManager.

    All fields default to None; the manager uses built-in defaults when omitted.

    Attributes:
        log_registry: Registry of log-method bindings.  Used to derive the
            local log for config.identity.log_ref and to construct readers for
            counterparty logs during verification.
        dns_resolver: DNS resolver used for _dnsid TXT lookups.  Omit to use
            the built-in default resolver: system DNS or a ``host:port``
            server (neither reports DNSSEC state), or DNS-over-HTTPS when
            config.transport.dns_server is an ``http(s)://`` URL (reports
            DNSSEC state from the AD bit).  System and ``host:port`` resolution
            report ``UNKNOWN``, which the default ``AUTO`` policy accepts and
            preserves.  Inject a DNSSEC-aware resolver for ``VALIDATED`` or
            ``REQUIRED`` policy.
        https_fetcher: HTTPS fetcher used for JWKS and status endpoint
            requests.  Omit to use the SDK's default transport.
        cache: Cache for verified identities.  Defaults to an in-memory cache.
        entity_key_provider: Accountable-entity key provider, used only for
            _dnsid identity record signing and entity lifecycle events.  Keep
            separate from the agent key_provider; for draft 01 the current
            entity and agent public keys MUST be distinct.
    """

    log_registry: LogRegistry | None = None
    dns_resolver: DNSResolver | None = None
    https_fetcher: HTTPSFetcher | None = None
    cache: IdentityCache | None = None
    # Accountable-entity key provider, used only for _dnsid record signing and
    # entity lifecycle events.  Keep separate from the agent key_provider; for
    # draft 01 the current entity and agent public keys MUST be distinct.
    entity_key_provider: KeyProvider | None = None


class IdentityManager:
    """Primary SDK object.  All DNSid protocol operations flow through it.

    Log-writing methods — including sign_and_write_event, setup flows, key
    rotation, and revocation flows — require a write-capable Log to be
    derivable from deps.log_registry.  If this manager was constructed for
    verification-only use, these methods raise ArgumentError.
    """

    def __init__(
        self,
        config: DnsidConfig | None = None,
        key_provider: KeyProvider | None = None,
        deps: IdentityManagerDependencies | None = None,
    ) -> None:
        """Initialize the manager with configuration, keys, and dependencies.

        Args:
            config: Core configuration.  Omit ``config.identity`` (or *config*
                entirely) for a verification-only manager; ``verification`` and
                ``transport`` apply identically in either mode.  *domain* and
                *governance_id* are normalised with normalize_fqdn.  The
                configuration is validated and snapshotted before any network
                work; create a new manager to change policy or trust.
            key_provider: Operational key provider for the local identity.
                Required with ``config.identity``; rejected without it.
            deps: Optional dependency bundle.  Omit to use built-in defaults
                (in-memory cache, system/configured DNS resolver).

        Raises:
            ArgumentError: On invalid configuration, a key provider supplied
                to a verification-only manager, a missing operational key
                provider for a local identity, or a transport setting whose
                only SDK-managed consumer is an injected dependency.
        """
        import copy

        if deps is None:
            deps = IdentityManagerDependencies()
        if config is not None and not isinstance(config, DnsidConfig):
            raise ArgumentError(
                f"config must be a DnsidConfig, got {type(config).__name__}; "
                "wrap identity settings as DnsidConfig(identity=IdentityConfig(...))"
            )
        config = copy.deepcopy(config) if config is not None else DnsidConfig()

        identity = config.identity
        if identity is None:
            if key_provider is not None or deps.entity_key_provider is not None:
                raise ArgumentError(
                    "key providers require config.identity; this manager is verification-only"
                )
        else:
            if key_provider is None:
                raise ArgumentError("config.identity requires a key_provider")
            identity.domain = normalize_fqdn(identity.domain, agent_fqdn=True)
            identity.governance_id = _maybe_normalize_fqdn(identity.governance_id)
        config.verification = _validate_verification_config(config.verification)
        _validate_transport_config(
            config.transport,
            resolver_injected=deps.dns_resolver is not None,
            fetcher_injected=deps.https_fetcher is not None,
        )

        self._config = config
        self._identity = identity
        self._key_provider = key_provider
        self._verification_only = identity is None
        self._entity_key_provider = deps.entity_key_provider
        self._log_registry = deps.log_registry
        self._transport_config = config.transport

        resolver = deps.dns_resolver or _default_dns_resolver(self._transport_config)
        self._dns_resolver: DNSResolver = resolver
        self._https_fetcher: HTTPSFetcher | None = deps.https_fetcher
        self._http_client = (
            _create_https_client(transport=_make_sdk_transport(self._transport_config))
            if self._https_fetcher is None
            else None
        )
        self._closed = False

        self._cache: IdentityCache = (
            _PrivateCache(deps.cache) if deps.cache is not None else _InMemoryCache()
        )
        self._coordination_lock = threading.Lock()
        self._verification_futures: dict[str, Future[VerifiedDomain]] = {}
        self._status_futures: dict[str, Future[VerifiedDomain]] = {}

        # Derive the local log binding when a registry is available.  The
        # binding always provides canonicalization; it doubles as the local
        # write log only when it also implements Log (write-capable methods
        # raise otherwise — a read-only binding is valid for verification).
        self._local_log: Log | None = None
        self._local_log_binding: LogReader | Log | None = None
        if deps.log_registry is not None and identity is not None:
            reader = deps.log_registry.new_reader(identity.log_ref)
            self._local_log_binding = reader
            if isinstance(reader, Log):
                self._local_log = reader

    @classmethod
    def for_verification(
        cls,
        deps: IdentityManagerDependencies | None = None,
        *,
        verification: VerificationConfig | None = None,
        transport: TransportConfig | None = None,
    ) -> IdentityManager:
        """Construct a verifier without a local identity or keys.

        Alias for ``IdentityManager(DnsidConfig(verification=..., transport=...), deps=deps)``.
        """
        return cls(
            DnsidConfig(
                verification=verification or VerificationConfig(),
                transport=transport or TransportConfig(),
            ),
            deps=deps,
        )

    @property
    def config(self) -> DnsidConfig:
        """Return an independent copy of the manager's validated configuration."""
        import copy

        return copy.deepcopy(self._config)

    @property
    def local_domain(self) -> str:
        """Return the local identity FQDN, or ``""`` for a verification-only manager."""
        return self._identity.domain if self._identity is not None else ""

    @property
    def _local_identity(self) -> IdentityConfig:
        if self._identity is None:
            raise ArgumentError(
                "operation requires a local identity; this manager is verification-only"
            )
        return self._identity

    # ------------------------------------------------------------------
    # Core protocol methods
    # ------------------------------------------------------------------

    def canonicalize_log_event(self, event: LogEvent) -> bytes:
        """Return the log-method-specific canonical bytes all signatures cover.

        Requires a local log binding for config.identity.log_ref (Log or
        LogReader), but not write access.  Canonicalization excludes signature
        fields, so adding one signature never changes the bytes another covers.

        Args:
            event: The lifecycle log event to canonicalize.

        Returns:
            The canonical bytes that every signature over the event covers.

        Raises:
            ArgumentError: If no LogRegistry binding is available for
                config.identity.log_ref.
        """
        if self._local_log_binding is None:
            raise ArgumentError(
                "canonicalize_log_event requires a LogRegistry binding for config.identity.log_ref"
            )
        return self._local_log_binding.canonical(event)

    def required_log_signatures(self, event: LogEvent) -> list[LogSignerRole]:
        """Return the profile-owned signer roles required before writing *event*.

        Signer roles are event-type-owned:

        * ISSUANCE — Entity and OperationalCountersignature
        * KEY_ROTATION — PreviousOperational (signs by kid via
          KeyProvider.sign_key)
        * all other lifecycle events — Entity

        Entity signatures require deps.entity_key_provider; the other roles
        use the agent key_provider.  Concrete bindings enforce any
        method-owned additions without weakening these profile requirements.

        Args:
            event: The lifecycle log event to inspect.

        Returns:
            The signer roles whose signatures must be present before the event
            may be written.
        """
        return _required_log_signatures(event)

    def sign_event(self, event: LogEvent, role: LogSignerRole) -> LogEvent:
        """Add the signature for one role using this manager's matching provider.

        Entity signatures come from deps.entity_key_provider; Operational,
        OperationalCountersignature, and PreviousOperational signatures come
        from the agent key_provider.  Does not write to the log.

        Args:
            event: The lifecycle log event to sign; mutated in place.
            role: The signer role whose signature to add.

        Returns:
            The same event with the role's signature added.

        Raises:
            ArgumentError: If the Entity role is requested without
                deps.entity_key_provider, or no LogRegistry binding is
                available for config.identity.log_ref.
        """
        self._require_local_identity("sign_event")
        if role is LogSignerRole.ENTITY:
            provider = self._entity_key_provider
            if provider is None:
                raise ArgumentError("signing an Entity role requires deps.entity_key_provider")
        else:
            provider = self._require_operational_key_provider("sign_event")
        binding = self._local_log_binding
        if binding is None:
            raise ArgumentError(
                "sign_event requires a LogRegistry binding for config.identity.log_ref"
            )
        return sign_event_with_provider(event, role, provider, binding)

    def write_signed_event(self, event: LogEvent) -> LogRef:
        """Append an already-signed lifecycle event to the local log.

        Rejects events missing any required_log_signatures field.

        Args:
            event: The fully signed lifecycle event to append.

        Returns:
            The LogRef of the appended event.

        Raises:
            ArgumentError: If no write-capable local log is configured, or the
                event is missing a required signature.
        """
        self._require_local_identity("write_signed_event")
        if self._local_log is None:
            raise ArgumentError(
                "write_signed_event requires a LogRegistry with a Log implementation"
            )
        for role in self.required_log_signatures(event):
            if _role_signature_missing(event, role):
                raise ArgumentError(f"event is missing the required {role.value} signature")
        return self._local_log.write_event(event)

    def sign_and_write_event(self, event: LogEvent) -> LogRef:
        """Sign and append a lifecycle event to the identity's local log.

        Single-process convenience: the input may already carry some required
        signatures; only missing signatures for roles this manager is
        configured to produce are added, then the event is written.  If a
        required signature is still missing (e.g. an Entity role with no
        deps.entity_key_provider), this fails before writing.  Distributed
        flows call sign_event on each signing machine and write_signed_event
        once all required signatures are present.

        Args:
            event: The lifecycle event to sign and append; mutated in place.

        Returns:
            The LogRef of the appended event.

        Raises:
            ArgumentError: If no write-capable local log is configured, or a
                required signature is missing and this manager is not
                configured to produce it.
        """
        self._require_local_identity("sign_and_write_event")
        if self._local_log is None:
            raise ArgumentError(
                "sign_and_write_event requires a LogRegistry with a Log implementation"
            )
        for role in self.required_log_signatures(event):
            if _role_signature_missing(event, role) and self._configured_for_role(role):
                self.sign_event(event, role)
        return self.write_signed_event(event)

    def _configured_for_role(self, role: LogSignerRole) -> bool:
        if role is LogSignerRole.ENTITY:
            return self._entity_key_provider is not None
        return self._key_provider is not None

    def _require_operational_key_provider(self, operation: str) -> KeyProvider:
        provider = self._key_provider
        if provider is None:
            raise ArgumentError(
                f"{operation} requires a key_provider; this manager is verification-only"
            )
        return provider

    def _require_local_identity(self, operation: str) -> None:
        if self._verification_only:
            raise ArgumentError(
                f"{operation} requires a local identity; this manager is verification-only"
            )

    def get_key_set(self) -> JWKS:
        """Return the agent public key set for publication at the ku endpoint.

        Draft 01 live endpoints expose exactly one current operational key
        (retained keys are not published); the endpoint MUST be served over
        HTTPS with a valid TLS certificate whose host matches the identity
        FQDN.

        Returns:
            A JWKS containing exactly the current operational key.
        """
        provider = self._require_operational_key_provider("get_key_set")
        return JWKS(keys=[provider.signing_key()])

    def get_entity_key_set(self) -> JWKS:
        """Return the accountable-entity public key set for publication at the ek endpoint.

        Draft 01 live endpoints expose exactly one current key. The endpoint
        MUST be served over HTTPS with a valid TLS certificate whose host
        equals or is beneath gi.

        Returns:
            A JWKS containing exactly the current entity key.

        Raises:
            ArgumentError: If no entity key provider is configured.
        """
        self._require_local_identity("get_entity_key_set")
        if self._entity_key_provider is None:
            raise ArgumentError("get_entity_key_set requires deps.entity_key_provider")
        return JWKS(keys=[self._entity_key_provider.signing_key()])

    def create_txt_record(self) -> str:
        """Build and sign the _dnsid TXT record for publication at _dnsid.{domain}.

        The wire profile comes from IdentityConfig.publish_profile; draft 01 is
        the only publishable profile.  Draft 01 records require explicit
        IdentityConfig.ek_url and ku_url (the protocol defines no default
        endpoint paths), are signed by the accountable-entity key
        (deps.entity_key_provider), and carry a bare base64url sg value.

        The signature is computed over DnsIdTxtRecord.canonical(), not the
        serialized wire form: draft 01 sorts all tags (including the exact
        ``v=`` selector) alphabetically for signing, while the serialized wire
        form always puts ``v=`` first.

        Returns:
            The serialized, signed identity record TXT string including all
            required tags (v, gi, ek, ku, lr, su, sg).

        Raises:
            ArgumentError: If no entity key provider is configured, the entity
                and agent keys are not distinct, the configured publish
                profile is unsupported, or the record configuration is
                invalid.
        """
        record = _build_unsigned_txt_record(self._local_identity)
        canonical_bytes = record.canonical().encode("ascii")
        from ._utils import b64url_encode

        provider = self._require_entity_provider_for_publication()
        signing_key = provider.signing_key()
        signing_key.signature_alg()  # validates required alg/key binding
        record.sg = b64url_encode(provider.sign(canonical_bytes))
        return record.serialize()

    def _require_entity_provider_for_publication(self) -> KeyProvider:
        """Entity provider with the draft 01 entity/agent key distinctness check."""
        provider = self._entity_key_provider
        if provider is None:
            raise ArgumentError(
                "draft 01 publishing requires deps.entity_key_provider "
                "(the accountable-entity record-signing key)"
            )
        entity_key = provider.signing_key()
        agent_key = self._require_operational_key_provider(
            "draft 01 publishing"
        ).signing_key()
        try:
            distinct = entity_key.thumbprint() != agent_key.thumbprint()
        except ValueError as exc:
            raise ArgumentError(f"cannot compute JWK thumbprint: {exc}") from exc
        if not distinct:
            raise ArgumentError("draft 01 entity and agent keys must be distinct")
        return provider

    def publish_client_controlled_record(
        self, registry_client: AbstractRegistryClient
    ) -> PublishedRecord:
        """Publish through a registry when this SDK controls the entity key.

        Two-step workflow per the design spec:
        1. Fetch the registry's canonical content and validate it exactly
           matches the unsigned record this identity would produce locally
           (same publish profile, same known tags, same active signing kid).
           Unknown registry-managed tags (e.g. expiry) are signed as-is.
        2. Sign the canonical bytes with the accountable-entity key and
           submit the bare base64url signature.

        Args:
            registry_client: Client for the registry publication API.

        Returns:
            The PublishedRecord reported by the registry.

        Raises:
            ValidationError: If the identity is not registered, the registry
                controls accountable-entity publication, or the registry
                canonical content does not match the local unsigned identity
                record.
            ArgumentError: If no entity key provider is configured or the
                entity and agent keys are not distinct.
        """
        self._require_local_identity("publish_client_controlled_record")
        from ._utils import b64url_encode
        from .exceptions import ValidationError
        from .models import DnsIdTxtRecord, publish_allowed_version

        registration = registry_client.get_registration(self._local_identity.domain)
        if registration is None:
            raise ValidationError("local identity is not registered")
        if registration.publication_authority != "client":
            raise ValidationError("registry controls accountable-entity publication")

        expected = _build_unsigned_txt_record(self._local_identity)
        provider = self._require_entity_provider_for_publication()
        signing_key = provider.signing_key()
        if not signing_key.kid:
            raise ValidationError("active record-signing key missing kid")

        # Step 1: fetch canonical content from registry.
        canonical_response = registry_client.canonical_record_content(
            self._local_identity.domain, signing_key.kid
        )

        # Validate the registry's signingKid matches our active key.
        if canonical_response.signing_kid != signing_key.kid:
            raise ValidationError(
                f"registry canonical content targets a different active signing kid: "
                f"{canonical_response.signing_kid!r} != {signing_key.kid!r}"
            )

        # Parse and semantically validate the registry-supplied canonical.
        try:
            registry_record = DnsIdTxtRecord.parse_unsigned_canonical(
                canonical_response.canonical,
                identity_fqdn=self._local_identity.domain,
            )
        except Exception as exc:
            raise ValidationError(f"registry canonical content is invalid: {exc}") from exc

        # The registry must echo a publishable profile and the exact version
        # this identity is configured to emit; profile IDs are never aliased
        # or normalized for comparison.
        if not publish_allowed_version(registry_record.v):
            raise ValidationError(
                f"registry canonical content uses an unsupported DNSid publish "
                f"profile: {registry_record.v!r}"
            )
        if registry_record.v != expected.v:
            raise ValidationError(
                f"registry canonical content uses an unexpected DNSid version: "
                f"{registry_record.v!r} != {expected.v!r}"
            )
        # Known tags must match; unknown registry-managed tags (e.g. exp) are
        # accepted as-is and included in the signed bytes without comparison.
        if registry_record.known_tags_canonical() != expected.known_tags_canonical():
            raise ValidationError(
                "registry canonical content does not match local unsigned DNSid record"
            )

        # Step 2: sign and submit.
        signing_key.signature_alg()  # validates required alg/key binding
        sig_bytes = provider.sign(canonical_response.canonical.encode("utf-8"))
        return registry_client.publish_signature(
            self._local_identity.domain, b64url_encode(sig_bytes)
        )

    def publish_to_registry(
        self, registry_client: AbstractRegistryClient
    ) -> PublishedRecord:
        """Deprecated alias for :meth:`publish_client_controlled_record`."""
        return self.publish_client_controlled_record(registry_client)

    def await_registry_managed_publication(
        self,
        registry_client: AbstractRegistryClient,
        *,
        timeout: float = 120.0,
        interval: float = 5.0,
    ) -> PublishedRecord:
        """Wait for registry-owned publication, then verify the observed DNS record.

        Polls the registry until it reports the identity record published,
        then verifies the observed DNS record with the same protocol checks as
        verify_domain (but without counterparty acceptance; this confirms
        publication, it does not approve a counterparty) and checks the
        published record's version against the configured publish profile.

        Args:
            registry_client: Client for the registry publication API.
            timeout: Maximum seconds to wait for the registry to report
                publication.
            interval: Seconds between registry status polls.

        Returns:
            A PublishedRecord describing the verified published record.

        Raises:
            ValidationError: If the identity is not registered, the client
                controls publication, the registry fails or never confirms
                DNS publication, or the published record uses an unexpected
                version.
            VerificationError: If verification of the published identity
                fails; carries a VerificationCode.
        """
        self._require_local_identity("await_registry_managed_publication")
        from .exceptions import ValidationError
        from .models import PublishedRecord

        domain = self._local_identity.domain
        registration = registry_client.get_registration(domain)
        if registration is None:
            raise ValidationError("local identity is not registered")
        if registration.publication_authority != "registry":
            raise ValidationError("client controls accountable-entity publication")

        status = registry_client.wait_for_status(
            domain, timeout=timeout, interval=interval
        )
        if not status.published:
            raise ValidationError("registry did not report DNS publication complete")

        registration = registry_client.get_registration(domain)
        if registration is None:
            raise ValidationError("registry registration disappeared after publication")
        if registration.publication_authority != "registry":
            raise ValidationError("registry publication authority changed while waiting")
        if registration.registry_status in {"REJECTED", "CANCELLED", "ERROR"}:
            raise ValidationError(
                f"registry publication failed: {registration.registry_status}"
            )
        if registration.dns_published is not True:
            raise ValidationError("registry did not confirm DNS publication")

        verified = self._verify_publication_evidence(domain)
        from .models import IDENTITY_RECORD_VERSION

        expected_profile = self._local_identity.publish_profile or IDENTITY_RECORD_VERSION
        if verified.record.v != expected_profile:
            raise ValidationError(
                "published DNSid record uses an unexpected version: "
                f"{verified.record.v!r} != {expected_profile!r}"
            )
        return PublishedRecord(
            domain=verified.domain,
            owner_name=f"_dnsid.{verified.domain}",
            txt_record=verified.record.serialize(),
            ttl=verified.dns_ttl,
            publication_status=registration.registry_status,
            protocol_status=verified.registry_status,
            raw=registration.raw,
        )

    def rotate_operational_key(
        self,
        registry_client: AbstractRegistryClient,
        *,
        idempotency_key: str,
        persist_rotation: KeyRotationPersistenceHook,
        set_application_signing_paused: ApplicationSigningPauseHook,
    ) -> KeyRotationResult:
        """Rotate the managed operational key with mandatory recovery hooks.

        Complete signed entry bytes are persisted before submission, then new
        application signing is paused. Every submission and local activation
        transition is persisted. The exact bytes and idempotency key are
        reused by :meth:`resume_key_rotation` after a crash or indeterminate
        result. Signing resumes only after accepted submission, idempotent key
        activation/supersession, and durable activation state.

        Args:
            registry_client: Client implementing the registry rotation API.
            idempotency_key: Caller-chosen key making preparation and
                submission retry-safe; reuse it for every retry of this
                rotation.
            persist_rotation: Mandatory durable persistence hook. It receives
                an isolated copy of every recoverable state transition.
            set_application_signing_paused: Mandatory hook that enforces the
                application-signing pause boundary.

        Returns:
            The latest durable recovery state.

        Raises:
            ArgumentError: If a mandatory hook, key, or idempotency key is invalid.
            ValidationError: If registry preparation is invalid.
            ManagedKeyRotationSubmissionError: If pausing, submission, or submission
                persistence fails; carries the latest recovery state.
            ManagedKeyRotationActivationError: If accepted local reconciliation,
                persistence, or pause release fails; carries recovery state.
        """
        from .c2sp_tlog.prepared import (
            C2spSignerRole,
            C2spVerificationContext,
            entry_bytes,
            parse_prepared_event,
            sign_prepared_event,
        )
        from .exceptions import ManagedKeyRotationSubmissionError, ValidationError
        from .models import KeyRotationPreparationRequest

        domain = self._local_identity.domain
        lr = self._local_identity.log_ref
        self._validate_rotation_hooks(
            persist_rotation, set_application_signing_paused
        )
        self._validate_rotation_idempotency_key(idempotency_key)

        key_provider = self._require_operational_key_provider(
            "rotate_operational_key"
        )
        previous_key = key_provider.signing_key()
        if not previous_key.kid:
            raise ArgumentError("active operational key missing kid")
        new_kid = key_provider.generate_key()
        new_key = key_provider.jwk(new_kid)
        new_key.signature_alg()  # validates required alg/key binding
        previous_thumbprint = previous_key.thumbprint()
        new_thumbprint = new_key.thumbprint()
        if previous_thumbprint == new_thumbprint:
            raise ValidationError("managed KEY_ROTATION requires a distinct pending key")

        request = KeyRotationPreparationRequest(
            previous_key_id=previous_thumbprint,
            public_key=new_key,
        )
        prepared_response = registry_client.prepare_key_rotation(domain, request, idempotency_key)
        if prepared_response.log_reference != lr:
            raise ValidationError(
                "registry preparation returned an unexpected log reference: "
                f"{prepared_response.log_reference!r} != {lr!r}"
            )

        context = C2spVerificationContext(
            previous_operational_key=previous_key,
            fqdn=domain,
        )
        prepared = parse_prepared_event(
            prepared_response.entry_bytes, prepared_response.log_reference, context
        )
        if prepared.envelope.get("type") != "KEY_ROTATION":
            raise ValidationError(
                "registry preparation returned a non-KEY_ROTATION envelope: "
                f"{prepared.envelope.get('type')!r}"
            )

        # Previous-key authorization, then the binding-owned proof of
        # possession.  sign_prepared_event matches the provider's key against
        # the envelope's keys by kid, alg, and RFC 7638 thumbprint, so an
        # envelope naming foreign key material fails closed here.
        prepared = sign_prepared_event(
            prepared, C2spSignerRole.PREVIOUS_OPERATIONAL, key_provider, context
        )
        prepared = sign_prepared_event(
            prepared, C2spSignerRole.NEW_OPERATIONAL, key_provider, context
        )
        final_bytes = entry_bytes(prepared, context)
        import hashlib

        result = KeyRotationResult(
            previous_kid=previous_key.kid,
            new_kid=new_kid,
            entry_bytes=final_bytes,
            domain=domain,
            log_reference=lr,
            previous_thumbprint=previous_thumbprint,
            new_thumbprint=new_thumbprint,
            previous_public_key=previous_key,
            entry_hash=hashlib.sha256(final_bytes).hexdigest(),
            idempotency_key=idempotency_key,
            application_signing_paused=True,
        )
        try:
            self._persist_rotation(persist_rotation, result)
        except Exception as exc:
            raise ManagedKeyRotationSubmissionError(
                "failed to persist prepared managed key rotation",
                self._clone_rotation(result),
                state="prepared",
                transient=True,
                retry_same_bytes=True,
                cause=exc,
            ) from exc
        try:
            set_application_signing_paused(True)
        except Exception as exc:
            raise ManagedKeyRotationSubmissionError(
                "failed to pause application signing before key-rotation submission",
                self._clone_rotation(result),
                state="prepared",
                transient=True,
                retry_same_bytes=True,
                cause=exc,
            ) from exc
        return self._submit_rotation(
            registry_client,
            result,
            persist_rotation,
            set_application_signing_paused,
        )

    def resume_key_rotation(
        self,
        registry_client: AbstractRegistryClient,
        result: KeyRotationResult,
        *,
        persist_rotation: KeyRotationPersistenceHook,
        set_application_signing_paused: ApplicationSigningPauseHook,
    ) -> KeyRotationResult:
        """Resume an exact persisted managed key rotation safely.

        Validates the persisted bytes, hash, identity, log, and key bindings
        before any network or key mutation. Pending state reuses the exact
        bytes and idempotency key. Accepted state performs only idempotent
        local reconciliation; activated-but-paused state only releases the
        signing pause and persists completion.
        """
        from .exceptions import (
            ManagedKeyRotationActivationError,
            ManagedKeyRotationSubmissionError,
        )

        self._require_local_identity("resume_key_rotation")
        self._validate_rotation_hooks(
            persist_rotation, set_application_signing_paused
        )
        rotation = self._clone_rotation(result)
        self._validate_persisted_rotation(rotation)

        if rotation.activated:
            if not rotation.application_signing_paused:
                return rotation
            try:
                set_application_signing_paused(False)
            except Exception as exc:
                raise ManagedKeyRotationActivationError(
                    "failed to resume application signing after key activation",
                    self._clone_rotation(rotation),
                    cause=exc,
                ) from exc
            completed = replace(rotation, application_signing_paused=False)
            try:
                self._persist_rotation(persist_rotation, completed)
            except Exception as exc:
                raise ManagedKeyRotationActivationError(
                    "failed to persist completed managed key rotation",
                    self._clone_rotation(rotation),
                    cause=exc,
                ) from exc
            return completed

        if rotation.submission is not None and rotation.submission.state == "rejected":
            raise ManagedKeyRotationSubmissionError(
                "registry rejected the prepared KEY_ROTATION",
                rotation,
                state="rejected",
                transient=False,
                retry_same_bytes=False,
            )
        try:
            set_application_signing_paused(True)
        except Exception as exc:
            state = rotation.submission.state if rotation.submission else "prepared"
            raise ManagedKeyRotationSubmissionError(
                "failed to enforce application-signing pause during recovery",
                rotation,
                state=state,
                transient=True,
                retry_same_bytes=True,
                cause=exc,
            ) from exc

        if rotation.submission is not None and rotation.submission.accepted:
            return self._finish_accepted_rotation(
                rotation, persist_rotation, set_application_signing_paused
            )
        return self._submit_rotation(
            registry_client,
            rotation,
            persist_rotation,
            set_application_signing_paused,
        )

    def activate_rotated_key(
        self,
        result: KeyRotationResult,
        submission: SubmissionResult | None = None,
        *,
        persist_rotation: KeyRotationPersistenceHook,
        set_application_signing_paused: ApplicationSigningPauseHook,
    ) -> KeyRotationResult:
        """Reconcile an accepted rotation using the mandatory durability hooks."""
        self._require_local_identity("activate_rotated_key")
        self._validate_rotation_hooks(
            persist_rotation, set_application_signing_paused
        )
        rotation = self._clone_rotation(result)
        self._validate_persisted_rotation(rotation)
        if submission is not None:
            self._validate_rotation_submission(rotation, submission)
            rotation = replace(rotation, submission=self._clone_submission(submission))
            try:
                self._persist_rotation(persist_rotation, rotation)
            except Exception as exc:
                from .exceptions import ManagedKeyRotationSubmissionError

                raise ManagedKeyRotationSubmissionError(
                    "failed to persist accepted managed key-rotation submission",
                    rotation,
                    state=submission.state,
                    transient=True,
                    retry_same_bytes=True,
                    cause=exc,
                ) from exc
        current = rotation.submission
        if current is None or not current.accepted:
            state = current.state if current is not None else "unsubmitted"
            raise ArgumentError(
                "activate_rotated_key requires an accepted submission for this "
                f"rotation's entry bytes; the append is {state} — retry with "
                "resume_key_rotation (same bytes and idempotency key) and keep "
                "application signing paused until accepted"
            )
        try:
            set_application_signing_paused(True)
        except Exception as exc:
            from .exceptions import ManagedKeyRotationActivationError

            raise ManagedKeyRotationActivationError(
                "failed to enforce application-signing pause before activation",
                rotation,
                cause=exc,
            ) from exc
        return self._finish_accepted_rotation(
            rotation, persist_rotation, set_application_signing_paused
        )

    def _submit_rotation(
        self,
        registry_client: AbstractRegistryClient,
        rotation: KeyRotationResult,
        persist_rotation: KeyRotationPersistenceHook,
        set_application_signing_paused: ApplicationSigningPauseHook,
    ) -> KeyRotationResult:
        from .exceptions import ManagedKeyRotationSubmissionError

        try:
            submission = registry_client.submit_prepared_event(
                rotation.domain, rotation.entry_bytes, rotation.idempotency_key
            )
        except Exception as exc:
            from .exceptions import ValidationError, VerificationError

            terminal = isinstance(exc, (ArgumentError, ValidationError)) or (
                isinstance(exc, VerificationError) and not exc.transient
            )
            if terminal:
                raise ManagedKeyRotationSubmissionError(
                    "managed key-rotation submission failed validation",
                    self._clone_rotation(rotation),
                    state="rejected",
                    transient=False,
                    retry_same_bytes=False,
                    cause=exc,
                ) from exc
            submission = SubmissionResult(
                state="pending",
                entry_hash=rotation.entry_hash,
                error_code="TLOG_SUBMISSION_INDETERMINATE",
            )
            candidate = replace(rotation, submission=submission)
            try:
                self._persist_rotation(persist_rotation, candidate)
            except Exception as persist_exc:
                exc = RuntimeError(f"{exc}; persistence also failed: {persist_exc}")
            raise ManagedKeyRotationSubmissionError(
                "managed key-rotation submission is indeterminate",
                self._clone_rotation(candidate),
                state="pending",
                transient=True,
                retry_same_bytes=True,
                cause=exc,
            ) from exc

        try:
            self._validate_rotation_submission(rotation, submission)
        except Exception as exc:
            raise ManagedKeyRotationSubmissionError(
                "registry returned an invalid managed key-rotation result",
                self._clone_rotation(rotation),
                state="rejected",
                transient=False,
                retry_same_bytes=False,
                cause=exc,
            ) from exc
        candidate = replace(rotation, submission=self._clone_submission(submission))
        try:
            self._persist_rotation(persist_rotation, candidate)
        except Exception as exc:
            raise ManagedKeyRotationSubmissionError(
                "failed to persist managed key-rotation submission state",
                self._clone_rotation(candidate),
                state=submission.state,
                transient=True,
                retry_same_bytes=submission.state != "rejected",
                cause=exc,
            ) from exc
        if submission.state == "rejected":
            raise ManagedKeyRotationSubmissionError(
                "registry rejected the prepared KEY_ROTATION",
                candidate,
                state="rejected",
                transient=False,
                retry_same_bytes=False,
            )
        if not submission.accepted:
            return candidate
        return self._finish_accepted_rotation(
            candidate, persist_rotation, set_application_signing_paused
        )

    def _finish_accepted_rotation(
        self,
        rotation: KeyRotationResult,
        persist_rotation: KeyRotationPersistenceHook,
        set_application_signing_paused: ApplicationSigningPauseHook,
    ) -> KeyRotationResult:
        from .exceptions import ManagedKeyRotationActivationError

        try:
            self._reconcile_rotation_keys(rotation)
        except Exception as exc:
            raise ManagedKeyRotationActivationError(
                "accepted managed key rotation could not reconcile local keys",
                self._clone_rotation(rotation),
                cause=exc,
            ) from exc
        activated = replace(rotation, activated=True, application_signing_paused=True)
        try:
            self._persist_rotation(persist_rotation, activated)
        except Exception as exc:
            raise ManagedKeyRotationActivationError(
                "failed to persist activated managed key rotation",
                self._clone_rotation(rotation),
                cause=exc,
            ) from exc
        try:
            set_application_signing_paused(False)
        except Exception as exc:
            raise ManagedKeyRotationActivationError(
                "failed to resume application signing after key activation",
                self._clone_rotation(activated),
                cause=exc,
            ) from exc
        completed = replace(activated, application_signing_paused=False)
        try:
            self._persist_rotation(persist_rotation, completed)
        except Exception as exc:
            raise ManagedKeyRotationActivationError(
                "failed to persist completed managed key rotation",
                self._clone_rotation(activated),
                cause=exc,
            ) from exc
        return completed

    def _reconcile_rotation_keys(self, rotation: KeyRotationResult) -> None:
        from .exceptions import ValidationError

        provider = self._require_operational_key_provider("managed key rotation")
        active = provider.signing_key()
        if not active.kid:
            raise ValidationError("managed key-rotation provider has no active kid")
        active_thumbprint = active.thumbprint()
        if active.kid == rotation.previous_kid:
            if active_thumbprint != rotation.previous_thumbprint:
                raise ValidationError("active key does not match persisted previous key")
            pending = provider.jwk(rotation.new_kid)
            if pending.thumbprint() != rotation.new_thumbprint:
                raise ValidationError("pending key does not match persisted rotation")
            provider.activate(rotation.new_kid)
        elif active.kid != rotation.new_kid:
            raise ValidationError(
                f"unexpected active key {active.kid!r} during rotation recovery"
            )
        elif active_thumbprint != rotation.new_thumbprint:
            raise ValidationError("active key does not match persisted new key")

        if rotation.previous_kid in provider.list_key_ids():
            provider.supersede(rotation.previous_kid)

    def _validate_persisted_rotation(self, rotation: KeyRotationResult) -> None:
        import hashlib

        from .c2sp_tlog import parse_c2sp_event_entry
        from .c2sp_tlog.prepared import C2spVerificationContext, parse_prepared_event
        from .exceptions import ArgumentError, ValidationError

        if (
            not rotation.domain
            or not rotation.log_reference
            or not rotation.previous_kid
            or not rotation.previous_thumbprint
            or not rotation.new_kid
            or not rotation.new_thumbprint
            or rotation.previous_public_key is None
            or not rotation.entry_bytes
            or not rotation.entry_hash
        ):
            raise ArgumentError("complete persisted key-rotation state is required")
        self._validate_rotation_idempotency_key(rotation.idempotency_key)
        if rotation.domain != self._local_identity.domain:
            raise ValidationError("persisted rotation belongs to a different domain")
        if rotation.log_reference != self._local_identity.log_ref:
            raise ValidationError("persisted rotation belongs to a different log reference")
        expected_hash = hashlib.sha256(rotation.entry_bytes).hexdigest()
        if rotation.entry_hash != expected_hash:
            raise ValidationError("persisted entry hash does not match entry bytes")
        if rotation.previous_public_key.thumbprint() != rotation.previous_thumbprint:
            raise ValidationError("persisted previous key does not match its thumbprint")
        parse_prepared_event(
            rotation.entry_bytes,
            rotation.log_reference,
            C2spVerificationContext(
                previous_operational_key=rotation.previous_public_key,
                fqdn=rotation.domain,
            ),
        )
        event = parse_c2sp_event_entry(rotation.entry_bytes)
        if not isinstance(event, KeyRotationEvent):
            raise ValidationError("persisted entry is not a KEY_ROTATION")
        if (
            event.domain != rotation.domain
            or event.previous_kid != rotation.previous_kid
            or event.previous_thumbprint != rotation.previous_thumbprint
            or event.new_kid != rotation.new_kid
            or event.new_thumbprint != rotation.new_thumbprint
            or event.new_public_key is None
            or event.new_public_key.thumbprint() != rotation.new_thumbprint
        ):
            raise ValidationError("persisted rotation metadata does not match entry bytes")
        if rotation.submission is not None:
            self._validate_rotation_submission(rotation, rotation.submission)

    @staticmethod
    def _validate_rotation_submission(
        rotation: KeyRotationResult, submission: SubmissionResult
    ) -> None:
        from .exceptions import ValidationError

        if submission.state not in SubmissionResult.VALID_STATES:
            raise ValidationError(f"unknown rotation submission state {submission.state!r}")
        prior = rotation.submission
        if (
            prior is not None
            and prior.entry_hash
            and submission.entry_hash
            and prior.entry_hash != submission.entry_hash
        ):
            raise ValidationError("registry reconciled a different rotation entry hash")
        if submission.entry_hash and submission.entry_hash != rotation.entry_hash:
            raise ValidationError("submission entry hash does not match persisted bytes")
        if submission.key_id and submission.key_id != rotation.new_kid:
            raise ValidationError("submission key_id does not match persisted new key")
        if submission.accepted and not submission.entry_hash:
            raise ValidationError("accepted rotation submission is missing entry_hash")

    @staticmethod
    def _validate_rotation_hooks(
        persist_rotation: KeyRotationPersistenceHook,
        set_application_signing_paused: ApplicationSigningPauseHook,
    ) -> None:
        if not callable(persist_rotation):
            raise ArgumentError("managed key rotation persistence hook is required")
        if not callable(set_application_signing_paused):
            raise ArgumentError("application-signing pause hook is required")

    @staticmethod
    def _validate_rotation_idempotency_key(value: str) -> None:
        if not value or value != value.strip() or len(value.encode("utf-8")) > 200:
            raise ArgumentError(
                "idempotency_key must be 1 to 200 bytes without surrounding whitespace"
            )

    @classmethod
    def _persist_rotation(
        cls,
        persist_rotation: KeyRotationPersistenceHook,
        rotation: KeyRotationResult,
    ) -> None:
        persist_rotation(cls._clone_rotation(rotation))

    @staticmethod
    def _clone_submission(submission: SubmissionResult | None) -> SubmissionResult | None:
        if submission is None:
            return None
        return replace(submission, raw=dict(submission.raw))

    @classmethod
    def _clone_rotation(cls, rotation: KeyRotationResult) -> KeyRotationResult:
        previous_public_key = rotation.previous_public_key
        if previous_public_key is not None:
            previous_public_key = replace(
                previous_public_key, _raw=dict(previous_public_key._raw)
            )
        return replace(
            rotation,
            entry_bytes=bytes(rotation.entry_bytes),
            previous_public_key=previous_public_key,
            submission=cls._clone_submission(rotation.submission),
        )

    @verification_operation
    def verify_domain(
        self,
        domain: str,
        peer_cert: TLSCertificate | None = None,
    ) -> VerifiedDomain:
        """Verify a DNSid identity, then enforce configured counterparty acceptance.

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

        Args:
            domain: FQDN of the identity to verify.
            peer_cert: TLS peer certificate from an mTLS connection.  Required
                when the verified record carries fl=mtls; raises
                VerificationError otherwise.

        Returns:
            A VerifiedDomain carrying the verified identity record, key sets,
            registry status, and a bound log reader.

        Raises:
            VerificationError: If any verification step fails — DNS
                resolution, DNSSEC, identity record parsing or validation,
                signature checks, key-set fetches, lifecycle-log checks, key
                age, policy flags, or status.  Carries a VerificationCode
                identifying the failing step.
        """
        return self._verify(domain, peer_cert, acceptance=True)

    @verification_operation
    def _verify_publication_evidence(self, domain: str) -> VerifiedDomain:
        """Internal protocol-only verification for registry publication confirmation."""
        return self._verify(domain, None, acceptance=False)

    def _verify(
        self, domain: str, peer_cert: TLSCertificate | None, *, acceptance: bool
    ) -> VerifiedDomain:
        """Shared per-invocation verification boundary.

        Only registry publication confirmation passes ``acceptance=False``;
        there is no public bypass.
        """
        domain = normalize_fqdn(domain)
        result = self._reusable_verification(domain)
        # mTLS binds the current peer, not reusable identity evidence.
        _enforce_mtls_policy(result.record, domain, peer_cert)
        if acceptance:
            self._enforce_counterparty_acceptance(result)
        self._require_fresh_evidence(result, fresh_dns_lookup=result.dns_ttl == 0)
        return result

    def _enforce_counterparty_acceptance(self, result: VerifiedDomain) -> None:
        """Apply trusted_entities to verified evidence; no network, no caching."""
        entities = self._config.verification.trusted_entities
        if entities is None:
            return
        gi = result.record.gi
        thumbprint = result.signing_key_thumbprint
        for entity in entities:
            if entity.governance_id != gi:
                continue
            if entity.entity_key_thumbprints is None or thumbprint in entity.entity_key_thumbprints:
                return
            reason = "entity key does not match a configured pin"
            break
        else:
            reason = "governance ID is not in the configured allowlist"
        # Message and fields carry only observed values, never the configured policy.
        raise VerificationError(
            VerificationCode.COUNTERPARTY_NOT_ACCEPTED,
            f"counterparty not accepted: {reason} "
            f"(gi={gi!r}, entity key thumbprint={thumbprint!r})",
            verified_governance_id=gi,
            verified_entity_key_thumbprint=thumbprint,
        )

    def _reusable_verification(self, domain: str) -> VerifiedDomain:
        """Return reusable verified evidence, coalescing same-domain network work."""
        with self._coordination_lock:
            full_future = self._verification_futures.get(domain)
            status_future = self._status_futures.get(domain)
        if full_future is not None or status_future is not None:
            future = full_future if full_future is not None else status_future
            assert future is not None
            result = wait_for_verification(future)
            return self._verify_domain_uncached(domain) if result.dns_ttl == 0 else result

        cached = self._cache.get(domain)
        if cached is not None:
            elapsed = _now() - cached.last_status_check_at
            if elapsed < self._config.verification.status_check_interval:
                return cached
            return self._coalesce(
                domain,
                self._status_futures,
                lambda: self._refresh_status(domain, cached),
            )

        return self._coalesce(
            domain,
            self._verification_futures,
            lambda: self._verify_domain_uncached(domain),
        )

    def _coalesce(
        self,
        domain: str,
        pending: dict[str, Future[VerifiedDomain]],
        work: Callable[[], VerifiedDomain],
    ) -> VerifiedDomain:
        with self._coordination_lock:
            future = pending.get(domain)
            leader = future is None
            if future is None:
                future = Future()
                pending[domain] = future
        if not leader:
            result = wait_for_verification(future)
            return self._verify_domain_uncached(domain) if result.dns_ttl == 0 else result

        try:
            result = work()
            remaining_seconds()
        except BaseException as exc:
            future.set_exception(exc)
            raise
        else:
            future.set_result(result)
            return result
        finally:
            with self._coordination_lock:
                if pending.get(domain) is future:
                    del pending[domain]

    def _refresh_status(self, domain: str, cached: VerifiedDomain) -> VerifiedDomain:
        import copy

        # A refresh may have completed between the caller's cache read and its
        # leadership claim. Reuse that result even when the configured interval
        # is zero, because this call overlapped the completed refresh.
        latest = self._cache.get(domain)
        if latest is None:
            return self._coalesce(
                domain,
                self._verification_futures,
                lambda: self._verify_domain_uncached(domain),
            )
        if latest.last_status_check_at > cached.last_status_check_at:
            return latest

        refreshed = copy.copy(latest)
        status = self._fetch_status(refreshed.record.su)
        if status.state != "ACTIVE":
            self._cache.evict(domain)
            raise VerificationError(
                VerificationCode.STATUS_NOT_ACTIVE,
                f"identity is not ACTIVE: {status.state}",
                agent_state=status.state,
            )
        refreshed.registry_status = status
        refreshed.last_status_check_at = _now()
        self._require_fresh_evidence(refreshed)
        self._cache.put(domain, refreshed)
        return refreshed

    def _verify_domain_uncached(self, domain: str) -> VerifiedDomain:
        from ._utils import b64url_decode_strict

        dnssec_mode = self._config.verification.dnssec_mode

        # -- Step 1: Fetch and parse the _dnsid TXT record ----------------
        dns_acquired_at = _now()  # Lookup start conservatively bounds response acquisition.
        records, dnssec_state = self._dns_resolver.fetch_txt(f"_dnsid.{domain}")

        if not isinstance(dnssec_state, DNSSECState):
            raise VerificationError(
                VerificationCode.DNSSEC_FAILED,
                f"DNS resolver returned an invalid DNSSEC state: {dnssec_state!r}",
            )

        if dnssec_state == DNSSECState.FAILED:
            raise VerificationError(
                VerificationCode.DNSSEC_FAILED,
                f"DNSSEC validation failed for {domain}",
            )
        if (
            dnssec_mode == DNSSECMode.VALIDATED
            and dnssec_state == DNSSECState.UNKNOWN
        ):
            raise VerificationError(
                VerificationCode.DNSSEC_FAILED,
                "DNSSEC validation status is unknown; validated mode requires "
                "a DNSSEC-aware resolver",
            )
        if (
            dnssec_mode == DNSSECMode.REQUIRED
            and dnssec_state != DNSSECState.VALID
        ):
            raise VerificationError(
                VerificationCode.DNSSEC_FAILED,
                f"DNSSEC required but state is {dnssec_state.name}",
            )
        if len(records) != 1:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"expected exactly one _dnsid TXT record, got {len(records)}",
            )

        raw = records[0].concatenate_strings()
        dns_ttl = records[0].ttl
        if type(dns_ttl) is not int or dns_ttl < 0:
            raise VerificationError(VerificationCode.DNS_RESOLUTION, "invalid DNS TTL")
        try:
            dns_expires_at = dns_acquired_at + datetime.timedelta(seconds=dns_ttl)
        except OverflowError as exc:
            raise VerificationError(VerificationCode.DNS_RESOLUTION, "invalid DNS TTL") from exc

        try:
            record = DnsIdTxtRecord.parse(raw)
        except Exception as exc:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"TXT record parse failed: {exc}",
                cause=exc,
            ) from exc

        record.identity_fqdn = domain

        try:
            record.validate()
        except Exception as exc:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"TXT record validation failed: {exc}",
                cause=exc,
            ) from exc

        # -- Step 2: Fetch ek and authenticate the TXT record -------------
        ek_allowed_host = _ek_pinning_host(record.gi, record.ek)
        ek_jwks, ek_tls_cert = self._fetch_key_set(
            record.ek, allowed_host=ek_allowed_host, domain_boundary=True
        )
        signing_key = ek_jwks.current_record_signing_key(record.v)

        # Draft 01 sg is bare unpadded base64url raw signature bytes. The exact
        # v= selector remains in canonical_bytes and is never rewritten.
        canonical_bytes = record.canonical().encode("ascii")
        if ".." in record.sg or ":" in record.sg:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "draft 01 sg must be bare unpadded base64url raw signature bytes",
            )
        try:
            sig_decoded = b64url_decode_strict(record.sg)
        except Exception as exc:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "sg= value is not valid base64url",
            ) from exc
        if not signing_key.verify(canonical_bytes, sig_decoded):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "_dnsid record signature invalid",
            )

        # sg is authenticated: record-derived locations (ku, lr, su) may now be
        # followed. The ku/lifecycle-log branch and the status fetch are
        # independent, so they run concurrently; the first definitive failure
        # cancels the sibling and error precedence is fixed (identity > status
        # > cancellation). Both must succeed before any result is built.
        (jwks, tls_cert, log_reader, key_bound_at), status = run_concurrently(
            lambda: self._verify_identity_evidence(domain, record, ek_jwks, signing_key),
            lambda: self._fetch_active_status(record.su),
        )

        result = VerifiedDomain(
            domain=domain,
            record=record,
            jwks=jwks,
            signing_key=signing_key,
            tls_cert=tls_cert,
            registry_status=status,
            verified_at=_now(),
            dns_ttl=dns_ttl,
            dns_expires_at=dns_expires_at,
            key_bound_at=key_bound_at,
            last_status_check_at=_now(),
            dnssec_state=dnssec_state,
            log_reader=log_reader,
            record_signing_jwks=ek_jwks,
            record_signing_tls_cert=ek_tls_cert,
        )
        self._require_fresh_evidence(result, fresh_dns_lookup=True)
        if dns_ttl > 0:
            self._cache.put(domain, result)
        return result

    def _verify_identity_evidence(
        self, domain: str, record: DnsIdTxtRecord, ek_jwks: JWKS, signing_key: Any
    ) -> tuple[JWKS, Any, LogReader, datetime.datetime]:
        """Post-sg identity branch: ku fetch, two-key separation, lifecycle binding, key age."""
        from ._utils import parse_ledger_ref

        # -- Step 3: Fetch the authenticated runtime key set --------------
        ku_host = _extract_host(record.ku)
        if normalize_fqdn(ku_host) != domain:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "ku host does not match identity domain",
            )
        # Construct bound LogReader for this counterparty's log method.
        if self._log_registry is not None:
            log_reader: LogReader = self._log_registry.new_reader(record.lr)
        else:
            method, _ = parse_ledger_ref(record.lr)
            log_reader = NoopLogReader(method=method)

        # The lifecycle history depends only on the sg-authenticated lr and the
        # ek signing key, not on ku contents, so readers that support it warm
        # their history concurrently with the ku fetch. Error precedence is
        # unchanged: a ku failure wins, then the log failure that
        # verify_bilateral_binding would have raised anyway.
        preload = getattr(log_reader, "preload_history", None)
        (jwks, tls_cert), _ = run_concurrently(
            lambda: self._fetch_key_set(record.ku, allowed_host=domain),
            (lambda: preload(domain, signing_key)) if callable(preload) else lambda: None,
        )
        operational_key = jwks.current_operational_signing_key(record.v)

        ek_thumbprints = {k.thumbprint() for k in ek_jwks.keys}
        ku_thumbprints = {k.thumbprint() for k in jwks.keys}
        if ek_thumbprints & ku_thumbprints:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "ek and ku JWK Sets share a key (RFC 7638 thumbprint collision)",
            )

        # -- Step 4: Lifecycle-log verification ----------------------------
        if signing_key.thumbprint() == operational_key.thumbprint():
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "draft 01 ek and ku keys must be distinct",
            )
        binding = _require_log_method(log_reader, "verify_bilateral_binding")(
            record, signing_key, operational_key
        )
        _require_log_method(log_reader, "verify_operational_continuity")(
            domain,
            binding.initial_operational_thumbprint,
            operational_key.thumbprint(),
        )

        # -- Key age (ka tag): draft 01 pins the operational key's binding ---
        key_bound_at = _ZERO_TIME
        if record.ka:
            key_bound_at = log_reader.key_timestamp(domain, operational_key.thumbprint())
            ka_duration = _parse_ka_duration(record.ka)
            if _now() - key_bound_at > ka_duration:
                raise VerificationError(
                    VerificationCode.KEY_AGE_EXCEEDED,
                    f"signing key exceeds maximum key age {record.ka}",
                )

        # -- Step 6: Policy flags are enforced per caller by verify_domain --
        # -- Step 8: Operation-level logchk is caller policy ---------------
        # VerifyDomain records the flag (via record.policy_flags()) but does
        # not decide whether the caller's next operation is high-value or
        # irreversible.  Callers that act on fl=logchk must enforce their own
        # operation-specific log-inclusion policy using result.log_reader
        # (e.g. verify_non_revocation) before such operations.
        return jwks, tls_cert, log_reader, key_bound_at

    def _fetch_active_status(self, su: str) -> Any:
        """Post-sg status branch (Step 7): fetch su and require ACTIVE."""
        status = self._fetch_status(su)
        if status.state != "ACTIVE":
            raise VerificationError(
                VerificationCode.STATUS_NOT_ACTIVE,
                f"identity is not ACTIVE: {status.state}",
                agent_state=status.state,
            )
        return status

    def _require_fresh_evidence(
        self, result: VerifiedDomain, *, fresh_dns_lookup: bool = False
    ) -> None:
        remaining_seconds()
        now = _now()
        code = None
        for cert in (result.tls_cert, result.record_signing_tls_cert):
            # A cert whose expiry is unknown (transport did not expose the
            # peer certificate) carries no freshness bound, matching
            # VerifiedDomain.expires_at.
            if cert is not None and cert.not_after != _ZERO_TIME and now >= cert.not_after:
                code = VerificationCode.TLS_ERROR
        if result.record.ka and now >= result.key_bound_at + _parse_ka_duration(result.record.ka):
            code = VerificationCode.KEY_AGE_EXCEEDED
        dns_expiry = result.dns_expires_at or (
            result.verified_at + datetime.timedelta(seconds=result.dns_ttl)
        )
        if code is None and not (fresh_dns_lookup and result.dns_ttl == 0) and now >= dns_expiry:
            code = VerificationCode.DNS_RESOLUTION
        if code is not None:
            self._cache.evict(result.domain)
            raise VerificationError(code, "identity evidence expired during verification",
                                    transient=code == VerificationCode.DNS_RESOLUTION)

    def verify_log_evidence(
        self,
        vd: VerifiedDomain,
        at: datetime.datetime | None = None,
    ) -> LoggedStateEvidence:
        """Verify and return complete, fresh operation-level log evidence.

        This does not refresh the identity's protocol status.

        Args:
            vd: A result previously returned by ``verify_domain``.
            at: Operation time; defaults to the current time.

        Returns:
            The accepted log completeness, checkpoint, and freshness boundary.
        """
        return vd.log_reader.verify_non_revocation(vd.domain, at or _now())

    def evict_domain(self, domain: str) -> None:
        """Remove *domain* from the identity cache."""
        self._cache.evict(normalize_fqdn(domain))

    def load_domain_log(self, vd: VerifiedDomain) -> DomainLog:
        """Load the full verified event history for a domain from its lifecycle log.

        Args:
            vd: A VerifiedDomain previously returned by verify_domain.

        Returns:
            A DomainLog containing the rebuilt event history.
        """
        events = vd.log_reader.rebuild_history(vd.domain)
        return DomainLog(domain=vd.domain, events=list(events))

    def _fetch_key_set(
        self, uri: str, allowed_host: str, domain_boundary: bool = False
    ) -> tuple[JWKS, Any]:
        """Fetch a JWKS pinned to an exact host or DNS domain boundary."""
        if self._https_fetcher is not None:
            from ._crypto import jwk_from_dict

            raw_jwks, tls_cert = self._https_fetcher.fetch_strict_json(
                uri, allowed_host=allowed_host, domain_boundary=domain_boundary
            )
            return JWKS(keys=[jwk_from_dict(k) for k in raw_jwks.get("keys", [])]), tls_cert
        kwargs = {"domain_boundary": True} if domain_boundary else {}
        return _fetch_jwks(
            uri,
            allowed_host=allowed_host,
            transport=self._transport_config,
            client=self._http_client,
            **kwargs,
        )

    def _fetch_status(self, su: str) -> Any:
        """Fetch the status endpoint using the injected HTTPSFetcher or the default transport.

        A transport-level fetch failure (DNS, connect, TLS handshake, 5xx)
        raises StatusUnavailable (transient): the identity's status is
        indeterminate, not failed.  Non-transient failures (e.g. a disallowed
        redirect or an invalid status document) keep their original codes.

        The HTTPSFetcher contract requires network errors to be raised as
        VerificationError(DNS_RESOLUTION) with transient=True; DNS_RESOLUTION
        is additionally remapped even without the flag, so an injected fetcher
        that omits it cannot leak a raw network error past this taxonomy.
        """
        try:
            if self._https_fetcher is not None:
                from ._https_client import _parse_agent_status_from_dict

                raw, _ = self._https_fetcher.fetch_strict_json(su)
                status = _parse_agent_status_from_dict(raw)
            else:
                status = _fetch_strict_json_status(
                    su, transport=self._transport_config, client=self._http_client
                )
        except VerificationError as exc:
            if exc.transient or exc.code == VerificationCode.DNS_RESOLUTION:
                raise VerificationError(
                    VerificationCode.STATUS_UNAVAILABLE,
                    f"status endpoint unavailable: {exc}",
                    transient=True,
                    cause=exc,
                ) from exc
            raise
        try:
            status.validate()
        except ValidationError as exc:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "invalid agent status document",
                cause=exc,
            ) from exc
        return status

    def close(self) -> None:
        """Close manager-owned HTTP resources.

        Closing is idempotent. The manager must not be closed while verification
        calls are active. Injected HTTPSFetcher instances remain caller-owned.
        """
        if not self._closed:
            if self._http_client is not None:
                self._http_client.close()
            self._closed = True

    def __enter__(self) -> IdentityManager:
        """Return this manager for synchronous context-manager use."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close manager-owned HTTP resources on context exit."""
        self.close()

    def create_dnsid_http_client(self) -> httpx.Client:
        """Return an httpx.Client scoped to this identity's transport config.

        Applies ca_bundle_path for TLS trust augmentation. A ``host:port``
        dns_server is used for hostname resolution; DoH URLs apply only to
        DNSid TXT lookups and this client uses the system hostname resolver.

        Returns:
            A new httpx.Client; the caller is responsible for closing it.
        """
        import httpx

        return httpx.Client(transport=_make_sdk_transport(self._transport_config))

    def create_dnsid_async_http_client(self) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient scoped to this identity's transport config.

        Applies ca_bundle_path for TLS trust augmentation. A ``host:port``
        dns_server is used for hostname resolution; DoH URLs apply only to
        DNSid TXT lookups and this client uses the system hostname resolver.

        Returns:
            A new httpx.AsyncClient; the caller is responsible for closing it.
        """
        import httpx

        return httpx.AsyncClient(transport=_make_async_sdk_transport(self._transport_config))


# ---------------------------------------------------------------------------
# Event signing (provider-explicit primitive shared with the manager facade)
# ---------------------------------------------------------------------------


def sign_event_with_provider(
    event: LogEvent,
    role: LogSignerRole,
    key_provider: KeyProvider,
    log_binding: Log | LogReader,
) -> LogEvent:
    """Add the signature for one role to *event* using an explicit provider.

    Lower-level primitive behind IdentityManager.sign_event for processes that
    intentionally hold only one signer role.  The bound log binding, not
    caller-supplied bytes, determines canonical content.  Does not require
    providers for any other role and does not write to the log.

    Args:
        event: The lifecycle log event to sign; mutated in place.
        role: The signer role whose signature to add.
        key_provider: Provider holding the key material for the role.
        log_binding: Bound log binding that determines canonical content.

    Returns:
        The same event with the role's signature added.

    Raises:
        ArgumentError: If PreviousOperational signing is requested for an
            event that is not a KEY_ROTATION event with previous_kid set.
    """
    from ._utils import b64url_encode

    canonical = log_binding.canonical(event)
    if role is LogSignerRole.PREVIOUS_OPERATIONAL:
        if not isinstance(event, KeyRotationEvent) or not event.previous_kid:
            raise ArgumentError(
                "PreviousOperational signing requires a KEY_ROTATION event with previous_kid set"
            )
        event.signing_kid = event.previous_kid
        event.sig = b64url_encode(key_provider.sign_key(event.previous_kid, canonical))
    elif role is LogSignerRole.OPERATIONAL_COUNTERSIGNATURE:
        event.operational_countersig = b64url_encode(key_provider.sign(canonical))
    else:  # ENTITY or OPERATIONAL — primary sig slot, current active key
        event.signing_kid = key_provider.signing_key().kid
        event.sig = b64url_encode(key_provider.sign(canonical))
    return event


def _required_log_signatures(event: LogEvent) -> list[LogSignerRole]:
    event_type = event.event_type
    if event_type == EventType.ISSUANCE:
        return [LogSignerRole.ENTITY, LogSignerRole.OPERATIONAL_COUNTERSIGNATURE]
    if event_type == EventType.KEY_ROTATION:
        return [LogSignerRole.PREVIOUS_OPERATIONAL]
    return [LogSignerRole.ENTITY]


def _role_signature_missing(event: LogEvent, role: LogSignerRole) -> bool:
    if role is LogSignerRole.OPERATIONAL_COUNTERSIGNATURE:
        return not event.operational_countersig
    return not event.sig


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _maybe_normalize_fqdn(s: str) -> str:
    from ._utils import is_domain_name

    if is_domain_name(s):
        return normalize_fqdn(s, agent_fqdn=False)
    return s


def _validate_verification_config(cfg: VerificationConfig) -> VerificationConfig:
    """Validate and return an immutable snapshot of verification settings."""
    if not isinstance(cfg, VerificationConfig):
        raise ArgumentError("config.verification must be a VerificationConfig")
    interval = cfg.status_check_interval
    if not isinstance(interval, datetime.timedelta) or interval < datetime.timedelta(0):
        raise ArgumentError("status_check_interval must be a non-negative timedelta")
    if not isinstance(cfg.dnssec_mode, DNSSECMode):
        raise ArgumentError(f"invalid DNSSEC mode: {cfg.dnssec_mode!r}")
    entities = cfg.trusted_entities
    if entities is None:
        return cfg
    if isinstance(entities, str | bytes) or not isinstance(entities, list | tuple):
        raise ArgumentError("trusted_entities must be a list of TrustedEntity or None")
    normalized: list[TrustedEntity] = []
    seen: set[str] = set()
    for entity in entities:
        if not isinstance(entity, TrustedEntity):
            raise ArgumentError("trusted_entities entries must be TrustedEntity")
        try:
            gi = normalize_fqdn(entity.governance_id)
        except ValidationError as exc:
            raise ArgumentError(f"invalid trusted entity governance_id: {exc}") from exc
        if gi in seen:
            raise ArgumentError(f"duplicate trusted entity: {gi!r}")
        seen.add(gi)
        pins = entity.entity_key_thumbprints
        if pins is not None:
            if isinstance(pins, str) or not pins:
                raise ArgumentError(f"entity_key_thumbprints for {gi!r} must be a non-empty list")
            pins = tuple(pins)
            if len(set(pins)) != len(pins):
                raise ArgumentError(f"duplicate entity_key_thumbprints for {gi!r}")
            for pin in pins:
                try:
                    ok = isinstance(pin, str) and len(b64url_decode_strict(pin)) == 32
                except ValueError:
                    ok = False
                if not ok:
                    raise ArgumentError(
                        f"invalid entity key thumbprint for {gi!r}: expected unpadded "
                        "base64url SHA-256 RFC 7638 thumbprint"
                    )
        normalized.append(TrustedEntity(governance_id=gi, entity_key_thumbprints=pins))
    return VerificationConfig(
        status_check_interval=interval,
        dnssec_mode=cfg.dnssec_mode,
        trusted_entities=tuple(normalized),
    )


def _validate_transport_config(
    cfg: TransportConfig, *, resolver_injected: bool, fetcher_injected: bool
) -> None:
    """Reject transport settings whose only SDK-managed consumers are injected."""
    if not isinstance(cfg, TransportConfig):
        raise ArgumentError("config.transport must be a TransportConfig")
    if cfg.dns_server and resolver_injected and fetcher_injected:
        raise ArgumentError(
            "transport.dns_server has no SDK-managed consumer: both dns_resolver "
            "and https_fetcher are injected"
        )
    if cfg.ca_bundle_path and fetcher_injected:
        raise ArgumentError(
            "transport.ca_bundle_path has no SDK-managed consumer: https_fetcher is injected"
        )


def _default_dns_resolver(transport_config: TransportConfig) -> DNSResolver:
    from ._default_resolver import DefaultDNSResolver

    return DefaultDNSResolver(dns_server=transport_config.dns_server)


def _extract_host(uri: str) -> str:
    from urllib.parse import urlparse

    return urlparse(uri).hostname or ""


def _enforce_mtls_policy(
    record: DnsIdTxtRecord,
    domain: str,
    peer_cert: TLSCertificate | None,
) -> None:
    """Enforce fl=mtls against the certificate for the current connection."""
    if "mtls" not in record.policy_flags():
        return
    if peer_cert is None:
        raise VerificationError(
            VerificationCode.TLS_ERROR,
            "fl=mtls requires a peer certificate but none was supplied",
            transient=False,
        )
    try:
        peer_cert.validate_against_fqdn(domain)
    except Exception as exc:
        raise VerificationError(
            VerificationCode.TLS_ERROR,
            f"fl=mtls peer certificate does not match {domain}",
            transient=False,
            cause=exc,
        ) from exc


def _ek_pinning_host(gi: str, ek_uri: str) -> str:
    """Return the TLS-pinning host for the ek JWKS fetch, anchored to *gi*.

    Draft 01 permits the ek host at or beneath gi. The fetch remains pinned to
    that DNS-label boundary rather than trusting the raw ek host.
    """
    from ._utils import is_domain_name

    ek_host = normalize_fqdn(_extract_host(ek_uri))
    if not is_domain_name(gi):
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            "draft 01 gi must be a lowercase ASCII DNS domain",
        )
    gi_domain = normalize_fqdn(gi)
    if ek_host != gi_domain and not ek_host.endswith("." + gi_domain):
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            "ek host must equal or be beneath gi",
        )
    return gi_domain


def _fetch_jwks(
    ku: str,
    allowed_host: str,
    transport: TransportConfig | None = None,
    domain_boundary: bool = False,
    client: httpx.Client | None = None,
) -> tuple[JWKS, Any]:
    from ._https_client import fetch_jwks

    sdk_transport = _make_sdk_transport(transport) if client is None else None
    return fetch_jwks(
        ku,
        allowed_host,
        verify=True,
        transport=sdk_transport,
        domain_boundary=domain_boundary,
        client=client,
    )


def _fetch_strict_json_status(
    su: str,
    transport: TransportConfig | None = None,
    client: httpx.Client | None = None,
) -> Any:
    from ._https_client import fetch_agent_status

    sdk_transport = _make_sdk_transport(transport) if client is None else None
    return fetch_agent_status(
        su, verify=True, transport=sdk_transport, client=client
    )


def _make_async_sdk_transport(config: TransportConfig | None) -> httpx.AsyncBaseTransport:
    import httpx

    if config is None:
        return httpx.AsyncHTTPTransport()

    import ssl

    import httpcore

    ssl_ctx: ssl.SSLContext | None = None
    if config.ca_bundle_path:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_verify_locations(cafile=config.ca_bundle_path)

    dns_backend: httpcore.AsyncNetworkBackend | None = None
    dns_server = config.dns_server or ""
    if dns_server and not dns_server.startswith("http"):
        raw_host, _, port_str = dns_server.rpartition(":")
        dns_host = raw_host or dns_server
        dns_port = int(port_str) if port_str else 53
        dns_backend = _AsyncDnsRoutingBackend(dns_host, dns_port)

    if ssl_ctx is None and dns_backend is None:
        return httpx.AsyncHTTPTransport()

    pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_ctx,
        network_backend=dns_backend,
    )
    return _AsyncHttpcoreTransport(pool)


def _resolve_a(host: str, dns_host: str, dns_port: int) -> str:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        import dns.resolver

        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [dns_host]
        r.port = dns_port
        return str(r.resolve(host, "A")[0])
    except Exception:
        return host


def _AsyncDnsRoutingBackend(dns_host: str, dns_port: int) -> httpcore.AsyncNetworkBackend:
    import httpcore
    from httpcore._backends.base import SOCKET_OPTION

    _h = dns_host
    _p = dns_port

    class _Backend(httpcore.AsyncNetworkBackend):
        def __init__(self) -> None:
            self._delegate = httpcore.AnyIOBackend()

        async def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Iterable[SOCKET_OPTION] | None = None,
        ) -> httpcore.AsyncNetworkStream:
            resolved = _resolve_a(host, _h, _p)
            return await self._delegate.connect_tcp(
                resolved, port, timeout, local_address, socket_options
            )

        async def connect_unix_socket(
            self,
            path: str,
            timeout: float | None = None,
            socket_options: Iterable[SOCKET_OPTION] | None = None,
        ) -> httpcore.AsyncNetworkStream:
            return await self._delegate.connect_unix_socket(path, timeout, socket_options)

        async def sleep(self, seconds: float) -> None:
            await self._delegate.sleep(seconds)

    return _Backend()


def _AsyncHttpcoreTransport(pool: httpcore.AsyncConnectionPool) -> httpx.AsyncBaseTransport:
    from collections.abc import AsyncIterable

    import httpcore
    import httpx
    from httpx._transports.default import AsyncResponseStream, map_httpcore_exceptions

    class _Transport(httpx.AsyncBaseTransport):
        _pool = pool

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            req = httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )
            with map_httpcore_exceptions():
                resp = await self._pool.handle_async_request(req)
            async_stream: AsyncIterable[bytes] = resp.stream  # type: ignore[assignment]
            return httpx.Response(
                status_code=resp.status,
                headers=resp.headers,
                stream=AsyncResponseStream(async_stream),
                extensions=resp.extensions,
            )

        async def aclose(self) -> None:
            await self._pool.aclose()

    return _Transport()


def _build_unsigned_txt_record(config: IdentityConfig) -> DnsIdTxtRecord:
    from .models import publish_allowed_version

    profile = config.publish_profile or _V_DRAFT01
    if not publish_allowed_version(profile):
        raise ArgumentError(f"unsupported DNSid publish profile: {profile!r}")

    # Draft 01 defines no default endpoint paths; both JWKS URLs
    # must be configured explicitly.
    if not config.ek_url or not config.ku_url:
        raise ArgumentError("draft 01 publishing requires ek_url and ku_url")
    ek = config.ek_url
    ku = config.ku_url
    record = DnsIdTxtRecord(
        v=profile,
        gi=config.governance_id,
        ek=ek,
        ku=ku,
        lr=config.log_ref,
        su=config.status_url,
        fl=config.policy_flags,
        ka=config.max_key_age,
        cu=config.capabilities_url,
        identity_fqdn=config.domain,
    )
    try:
        record.validate()
    except Exception as exc:
        raise ArgumentError(f"invalid TXT record configuration: {exc}") from exc
    return record


def _require_log_method(log_reader: LogReader, name: str) -> Any:
    """Return the named optional log-binding method, or fail closed.

    Draft 01 verification requires binding-level lifecycle checks (bilateral
    binding, operational continuity) that not every LogReader implements.
    """
    method = getattr(log_reader, name, None)
    if method is None or not callable(method):
        raise VerificationError(
            VerificationCode.LOG_ERROR,
            f"log method does not support {name} required by draft 01 verification",
        )
    return method


def _parse_ka_duration(ka: str) -> datetime.timedelta:
    mapping = {
        "24h": datetime.timedelta(hours=24),
        "7d": datetime.timedelta(days=7),
        "30d": datetime.timedelta(days=30),
        "90d": datetime.timedelta(days=90),
    }
    return mapping[ka]


class _PrivateCache(IdentityCache):
    """Manager-private namespace even when the storage backend is shared."""

    def __init__(self, backend: IdentityCache) -> None:
        import uuid

        self._backend = backend
        self._prefix = uuid.uuid4().hex + ":"

    def get(self, domain: str) -> VerifiedDomain | None:
        result = self._backend.get(self._prefix + domain)
        if result is not None and (result.dns_ttl <= 0 or _now() >= result.expiry()):
            self.evict(domain)
            return None
        return result

    def put(self, domain: str, result: VerifiedDomain) -> None:
        if result.dns_ttl <= 0 or _now() >= result.expiry():
            self.evict(domain)
        else:
            self._backend.put(self._prefix + domain, result)

    def evict(self, domain: str) -> None:
        self._backend.evict(self._prefix + domain)


class _InMemoryCache(IdentityCache):
    def __init__(self) -> None:
        import threading

        self._lock = threading.Lock()
        self._store: dict[str, VerifiedDomain] = {}

    def get(self, domain: str) -> VerifiedDomain | None:
        with self._lock:
            entry = self._store.get(domain)
            if entry is None:
                return None
            if entry.dns_ttl <= 0 or _now() >= entry.expiry():
                del self._store[domain]
                return None
            return entry

    def put(self, domain: str, result: VerifiedDomain) -> None:
        with self._lock:
            if result.dns_ttl <= 0 or _now() >= result.expiry():
                self._store.pop(domain, None)
            else:
                self._store[domain] = result

    def evict(self, domain: str) -> None:
        with self._lock:
            self._store.pop(domain, None)
