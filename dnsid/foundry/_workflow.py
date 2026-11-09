"""Known Foundry named Live creation and explicit public activation."""

from __future__ import annotations

import base64
import copy
import datetime
import hashlib
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, fields, replace
from typing import Any

from .._utils import b64url_decode_strict, b64url_encode, normalize_fqdn
from .._verification_budget import (
    BudgetExhausted,
    detached_budget,
    remaining_seconds,
    verification_budget,
)
from ..c2sp_tlog import C2spTlogReader
from ..c2sp_tlog.errors import C2spTlogError
from ..c2sp_tlog.managed_issuance import (
    ManagedIssuanceOperationError,
    ManagedIssuanceState,
    begin_managed_issuance,
    complete_managed_issuance,
    issuance_rejected,
    resume_managed_issuance,
)
from ..config_loading import (
    FoundryConfig,
    LoadedConfig,
    _has_trust,
    _log_registry_from_trust,
    _operational_key_provider,
    load_environment,
)
from ..enums import VerificationCode
from ..exceptions import (
    ArgumentError,
    RegistryRequestError,
    ValidationError,
    VerificationError,
)
from ..interfaces import KeyProvider
from ..manager import IdentityManager, IdentityManagerDependencies, _ek_pinning_host
from ..models import (
    JWK,
    AgentRegistration,
    DnsidConfig,
    IdentityConfig,
    IssuanceEvent,
    LiveAgentRegistrationInput,
    LiveProofReissueRequest,
    LiveProofRequest,
    PublicationConfig,
    SubmissionResult,
)
from ..registry import LogRegistry
from ..registry_client import (
    RegistryClient,
    _live_challenge_from_response,
    _live_public_jwk_dict,
    _validate_publication_config,
)
from ._issuance import IssuanceRegistry, IssuanceStore
from ._signing import ApplicationSigner, WorkflowKeyProvider, provider_call
from .errors import (
    FoundryDeadline,
    FoundryError,
    FoundryStateError,
    KeyMismatch,
    KeyMissing,
    KeyRevoked,
    SigningPaused,
    TerminalIdentity,
    UnsupportedAlgorithm,
    UnsupportedContract,
    UnsupportedRegistry,
    WorkflowOutcome,
)
from .store import (
    FileFoundryStore,
    FoundryStore,
    OperationKey,
    issuance_key,
    registration_key,
    validate_name,
    validate_operation,
)


class _BindingMismatch(UnsupportedContract):
    """A confirmed identity binding mismatch that requires a durable signing pause."""


_PUBLICATION = {
    "publish_profile": "publishProfile",
    "governance_id": "governanceId",
    "ku_url": "kuUrl",
    "ek_url": "ekUrl",
    "log_ref": "logRef",
    "status_url": "statusUrl",
    "capabilities_url": "capabilitiesUrl",
    "max_key_age": "maxKeyAge",
}


def create(
    name: str,
    *,
    config: LoadedConfig | None = None,
    api_key: str | None = None,
    key_provider: KeyProvider | None = None,
    registry_client: RegistryClient | None = None,
    store: FoundryStore | None = None,
    deps: IdentityManagerDependencies | None = None,
    timeout: float = 30.0,
    cancelled: threading.Event | None = None,
) -> FoundryIdentity:
    """Create or reopen one named identity without waiting for public ACTIVE.

    With no config, load the documented environment and its separate API credential.
    An explicit config is already composed: this function does not reread environment
    variables to override it. File/code callers supply credentials separately.
    Dependencies are injected through the same path as the one-argument facade.
    """
    validate_name(name)
    facade: _Foundry | None = None
    operation: dict[str, Any] = {}
    transferred = False
    try:
        with verification_budget(timeout, cancelled=cancelled):
            facade = _Foundry(config, api_key, key_provider, registry_client, store, deps)
            facade.configure()
            org, gi = facade.onboarding()
            key = (facade.registry_url, org, name)
            with facade.locked_operation(key) as operation:
                if operation:
                    facade.bindings(operation, org, gi)
                    _registry_outcome(operation)
                selected = facade.signing_key(operation)
                if not operation:
                    public = _live_key(selected)
                    operation.update(
                        schemaVersion=1,
                        phase="creation-pending",
                        registryUrl=key[0],
                        organizationId=org,
                        governanceId=gi,
                        name=name,
                        keySource=facade.key_source(public),
                        initialPublicKey=public,
                        creationInput={
                            "tier": "live",
                            "managed": True,
                            "environment": "production",
                            "name": name,
                            "public_key": public,
                        },
                    )
                    trust = facade.trust_document()
                    if trust:
                        operation["logTrust"] = trust
                    facade.save(key, operation)
                if not (operation.get("identityId") and operation.get("domain")):
                    frozen = operation["creationInput"]
                    creation_key = JWK.from_dict(frozen["public_key"])
                    request_id = registration_key(org, name, creation_key.thumbprint())
                    response = facade.registry.register_live_agent(
                        LiveAgentRegistrationInput(
                            public_key_jwk=creation_key,
                            name=frozen["name"],
                            environment=frozen.get("environment", ""),
                            capabilities_url=frozen.get("capabilities_url", ""),
                        ),
                        request_id,
                    )
                    remaining_seconds()
                    if (
                        response.request_id != request_id
                        or (
                            operation.get("identityId")
                            and operation["identityId"] != response.agent_id
                        )
                        or (
                            operation.get("domain")
                            and response.domain
                            and operation["domain"] != response.domain
                        )
                    ):
                        raise _BindingMismatch("Live replay changed its request or identity ID")
                    operation.update(
                        identityId=response.agent_id,
                        requestId=response.request_id,
                        registryStatus=response.status,
                    )
                    if response.domain:
                        operation["domain"] = response.domain
                    if operation.get("domain"):
                        operation["phase"] = "identity-known"
                    if response.challenge_transcript is not None:
                        if response.challenge_transcript.org_id != org:
                            raise _BindingMismatch(
                                "Live challenge belongs to another organization"
                            )
                        operation["proof"] = {
                            "challenge": response.challenge,
                            "challengeMessage": response.challenge_message,
                            "submissionState": "prepared",
                        }
                        operation["phase"] = "proof-pending"
                    facade.save(key, operation)
                    _registry_outcome(operation)
                    if not operation.get("domain"):
                        raise FoundryError(
                            "registry accepted creation without a domain; rerun create",
                            operation=operation,
                            resumable=True,
                        )
                else:
                    registration = facade.registration(operation)
                    facade.remember_registration(key, operation, registration)
                handle = FoundryIdentity(facade, key, operation, selected)
                transferred = True
                return handle
    except ArgumentError:
        raise
    except Exception as cause:
        error = _error(cause, operation)
        if error is cause:
            raise
        raise error from cause
    finally:
        if facade is not None and not transferred:
            facade.close()


class FoundryIdentity:
    """An immutable assigned domain with explicit, durable setup and signing control."""

    def __init__(
        self,
        facade: _Foundry,
        key: OperationKey,
        operation: dict[str, Any],
        selected: JWK,
    ) -> None:
        """Retain dependencies; no task or polling starts in the background."""
        self._facade, self._key = facade, key
        self._domain: str = operation["domain"]
        self._operation = copy.deepcopy(operation)
        self._signer = ApplicationSigner(facade.provider, selected)
        self._manager: IdentityManager | None = None
        self.state: str | None = None
        self.registry_status: str | None = operation.get("registryStatus")
        if (
            operation["phase"] == "complete"
            and operation.get("registryStatus") not in {"REVOKED", "RETIRED"}
            and not operation.get("signingPaused", False)
        ):
            self._signer.enable(selected)

    @property
    def domain(self) -> str:
        """The immutable server-assigned domain."""
        return self._domain

    def sign(self, data: bytes) -> bytes:
        """Sign raw application bytes, only after activation or a bound restart."""
        return self._signer.sign(data)

    def identity_manager(self) -> IdentityManager:
        """Return a core manager sharing this handle's application signer.

        Until publication configuration is known, no valid core manager can be
        constructed. The accessor raises SigningPaused instead of inventing URLs.
        """
        if self._manager is None:
            if "publicationConfig" not in self._operation:
                raise SigningPaused("publication configuration is not known; call active()")
            self._manager = self._facade.manager(self._operation, self._signer)
        return self._manager

    def active(
        self,
        *,
        timeout: float = 600.0,
        cancelled: threading.Event | None = None,
    ) -> FoundryIdentity:
        """Resume setup and make a fresh public observation under one deadline."""
        facade, key = self._facade, self._key
        operation = self._operation
        try:
            with verification_budget(timeout, cancelled=cancelled):
                with facade.locked_operation(key, self._signer) as operation:
                    if not operation:
                        raise FoundryStateError("saved Foundry operation is missing")
                    self._operation = operation
                    if operation.get("domain") != self.domain:
                        raise FoundryStateError("saved identity domain changed")
                    facade.bindings(operation, key[1], operation["governanceId"])
                    _registry_outcome(operation)
                    selected = facade.signing_key(operation)
                    registration = facade.registration(operation)
                    facade.remember_registration(key, operation, registration)
                    self._proof(operation, registration)
                    delay = 1.0
                    while registration.registry_status not in {"VERIFIED", "READY"}:
                        delay = _sleep(delay)
                        registration = facade.registration(operation)
                        facade.remember_registration(key, operation, registration)
                    # A used proof can settle only after the registry advances.
                    self._proof(operation, registration)
                    facade.publication(key, operation, registration)
                    # A new manager isolates readiness from application caches and acceptance.
                    with facade.manager(operation) as verifier:
                        entity = facade.entity_key(operation, verifier)
                        facade.save(key, operation)
                        issuance_store = IssuanceStore(facade.store, key, operation)
                        self._issuance(operation, entity, issuance_store)
                        delay = 1.0
                        while True:
                            try:
                                observed = verifier.verify_local_publication()
                                self.state = observed.registry_status.state
                                facade.check_public(operation, observed, selected)
                                evidence = verifier.verify_log_evidence(observed)
                                if evidence.logged_state in {"REVOKED", "RETIRED"}:
                                    operation["registryStatus"] = evidence.logged_state
                                    raise TerminalIdentity("public lifecycle history is terminal")
                                if evidence.logged_state != "ACTIVE":
                                    raise UnsupportedContract(
                                        "public lifecycle evidence is not ACTIVE"
                                    )
                                break
                            except VerificationError as cause:
                                if cause.agent_state is not None:
                                    self.state = cause.agent_state
                                if cause.agent_state in {"REVOKED", "RETIRED"}:
                                    operation["registryStatus"] = cause.agent_state
                                    raise TerminalIdentity(
                                        "public identity is terminal",
                                        operation=operation,
                                        cause=cause,
                                    ) from cause
                                if not cause.transient and cause.code not in {
                                    VerificationCode.RECORD_NOT_FOUND,
                                    VerificationCode.STATUS_NOT_ACTIVE,
                                }:
                                    if isinstance(cause, RegistryRequestError):
                                        raise
                                    raise _BindingMismatch(
                                        "public identity verification failed",
                                        operation=operation, cause=cause,
                                    ) from cause
                                delay = _sleep(delay)
                        state = issuance_store.load_managed_issuance(self.domain)
                        if state is not None and (not state.complete or state.activation_blocked):
                            complete_managed_issuance(
                                self.domain, issuance_store, lambda blocked: None
                            )
                        operation["phase"] = "complete"
                        operation["signingPaused"] = False
                        facade.save(key, operation)
                        self._signer.enable(selected)
                        self.registry_status = operation.get("registryStatus")
                        return self
        except Exception as cause:
            if isinstance(
                cause,
                (
                    KeyMissing,
                    KeyMismatch,
                    TerminalIdentity,
                    _BindingMismatch,
                    FoundryStateError,
                ),
            ):
                self._signer.paused = True
            self.registry_status = operation.get("registryStatus")
            error = _error(cause, operation)
            if error is cause:
                raise
            raise error from cause

    def _proof(self, operation: dict[str, Any], registration: AgentRegistration) -> None:
        proof = operation.get("proof")
        if not proof:
            return
        facade = self._facade
        if proof.get("submissionState") == "accepted" or (
            registration.registry_status in {"VERIFIED", "READY"}
        ):
            if operation["phase"] == "proof-pending":
                proof.setdefault("outcome", registration.registry_status)
                operation["phase"] = "identity-known"
                facade.save(self._key, operation)
            return
        initial = JWK.from_dict(operation["initialPublicKey"])
        _, transcript = _live_challenge_from_response(
            label="saved Foundry proof",
            agent_id=operation["identityId"],
            challenge=proof["challenge"],
            challenge_message=proof["challengeMessage"],
            expected_key_id=initial.thumbprint(),
            expected_domain=self.domain,
        )
        if transcript.org_id != operation["organizationId"]:
            raise FoundryStateError("saved proof organization mismatch")
        if transcript.expires_at <= datetime.datetime.now(datetime.UTC):
            try:
                response = facade.registry.reissue_live_proof(
                    self.domain,
                    LiveProofReissueRequest(operation["requestId"], initial),
                )
            except RegistryRequestError as cause:
                if cause.status_code == 409:
                    return
                raise
            if response.request_id != operation["requestId"] or (
                response.agent_id != operation["identityId"]
                or response.challenge_transcript.org_id != operation["organizationId"]
            ):
                raise _BindingMismatch("replacement proof changed identity bindings")
            proof.update(
                challenge=response.challenge,
                challengeMessage=response.challenge_message,
                submissionState="prepared",
            )
            proof.pop("signature", None)
            facade.save(self._key, operation)
        message = b64url_decode_strict(proof["challengeMessage"])
        if "signature" not in proof:
            proof["signature"] = b64url_encode(
                provider_call(
                    facade.provider.sign_key,
                    initial.kid,
                    message,
                )
            )
            facade.save(self._key, operation)
        if not initial.verify(message, b64url_decode_strict(proof["signature"])):
            raise FoundryStateError("saved proof signature does not match the frozen key")
        proof["submissionState"] = "submitting"
        facade.save(self._key, operation)
        response_proof = facade.registry.submit_live_proof(
            self.domain,
            LiveProofRequest(
                operation["requestId"],
                proof["challenge"],
                initial,
                proof["signature"],
            ),
        )
        if response_proof.request_id != operation["requestId"] or (
            response_proof.agent_id != operation["identityId"]
        ):
            raise _BindingMismatch("proof receipt changed identity bindings")
        proof.update(submissionState="accepted", outcome=response_proof.status)
        operation["phase"] = "identity-known"
        operation["registryStatus"] = response_proof.status
        facade.save(self._key, operation)

    def _issuance(
        self,
        operation: dict[str, Any],
        entity: JWK,
        store: IssuanceStore,
    ) -> None:
        facade = self._facade
        existing = store.load_managed_issuance(self.domain)
        if (
            existing is not None
            and existing.submission is not None
            and existing.submission.accepted
        ) or (existing is None and operation.get("registryStatus") == "READY"):
            try:
                recovered = facade.recover_issuance(operation, entity, store, expected=existing)
            except (C2spTlogError, VerificationError) as cause:
                raise FoundryError(
                    "accepted issuance cannot yet be reconciled with verified log evidence",
                    operation=operation,
                    resumable=True,
                    cause=cause,
                ) from cause
            if not recovered:
                raise FoundryError(
                    "accepted issuance is not visible in the log yet",
                    operation=operation,
                    resumable=True,
                )
            return
        arguments = dict(
            domain=self.domain,
            log_reference=operation["publicationConfig"]["logRef"],
            entity_public_key=entity,
            key_provider=WorkflowKeyProvider(facade.provider),
            registry_client=IssuanceRegistry(facade.registry, store),
            store=store,
            set_activation_blocked=lambda blocked: None,
        )
        delay = 1.0
        while True:
            try:
                if store.load_managed_issuance(self.domain) is None:
                    state = begin_managed_issuance(
                        **arguments,
                        governance_id=operation["governanceId"],
                        idempotency_key=issuance_key(operation["requestId"]),
                    )
                else:
                    state = resume_managed_issuance(**arguments)
                if state.submission is not None and state.submission.accepted:
                    return
            except ManagedIssuanceOperationError as cause:
                request_error = store.request_error
                if (
                    request_error is not None
                    and not request_error.transient
                    and not (issuance_rejected(request_error.error_code, request_error.status_code))
                ):
                    error = _error(request_error, operation)
                    error.resumable = True
                    raise error from request_error
                submission = cause.issuance.submission
                rejected = (
                    submission is not None
                    and submission.state == "rejected"
                    and (issuance_rejected(submission.error_code, submission.status_code))
                )
                remote = cause.__cause__
                if isinstance(remote, RegistryRequestError) and issuance_rejected(
                    remote.error_code,
                    remote.status_code,
                ):
                    operation["issuance"]["serverRejection"] = {
                        "httpStatus": remote.status_code,
                        "errorCode": remote.error_code,
                    }
                    facade.save(self._key, operation)
                    rejected = True
                saved_rejection = operation.get("issuance", {}).get("serverRejection", {})
                rejected = rejected or issuance_rejected(
                    saved_rejection.get("errorCode", ""),
                    saved_rejection.get("httpStatus"),
                )
                if rejected:
                    rejection_cause = (
                        RegistryRequestError(
                            "/issuance", saved_rejection["httpStatus"],
                            saved_rejection["errorCode"],
                        ) if saved_rejection else cause
                    )
                    # Rejection binds local bytes; a verified competing entry can still win.
                    try:
                        if facade.recover_issuance(operation, entity, store):
                            return
                    except (C2spTlogError, VerificationError) as evidence_error:
                        raise FoundryError(
                            "rejected issuance cannot yet be reconciled with verified log evidence",
                            operation=operation,
                            resumable=True,
                            cause=rejection_cause,
                        ) from evidence_error
                    raise FoundryError(
                        "rejected issuance is not visible in the log yet; call active() again",
                        operation=operation,
                        resumable=True,
                        cause=rejection_cause,
                    ) from cause
                if (
                    isinstance(remote, (ArgumentError, ValidationError))
                    or (isinstance(remote, VerificationError) and not remote.transient)
                    or not cause.transient
                ):
                    raise
            delay = _sleep(delay)

    def close(self) -> None:
        """Release owned clients; never cancel or delete the server identity."""
        if self._manager is not None:
            self._manager.close()
        self._facade.close()

    def __enter__(self) -> FoundryIdentity:
        """Keep resource ownership explicit for short-lived callers."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Close owned clients on context exit."""
        self.close()


class _Foundry:
    def __init__(
        self,
        config: LoadedConfig | None,
        credential: str | None,
        provider: KeyProvider | None,
        registry: RegistryClient | None,
        store: FoundryStore | None,
        deps: IdentityManagerDependencies | None,
    ) -> None:
        if config is None:
            config = load_environment()
            if credential is None:
                credential = (os.environ.get("DNSID_API_KEY") or "").strip() or None
        self.config = copy.deepcopy(config)
        self.deps = replace(deps) if deps is not None else IdentityManagerDependencies()
        self._injected_provider = provider is not None
        self._injected_log_registry = self.deps.log_registry is not None
        self._owned_registry = registry is None
        self._registry = registry
        self._credential = credential
        self._provider = provider
        self.store = store if store is not None else FileFoundryStore()
        self._owned_log_registry: LogRegistry | None = None

    @property
    def registry(self) -> RegistryClient:
        if self._registry is None:
            raise ArgumentError("Foundry registry has not been configured")
        return self._registry

    @property
    def provider(self) -> KeyProvider:
        if self._provider is None:
            raise KeyMissing("Foundry provider has no signing key")
        return self._provider

    @property
    def registry_url(self) -> str:
        return self.registry._base_url

    def configure(self) -> None:
        from ..manager import validate_dnsid_config

        if self.config.dnsid.identity is not None:
            raise ArgumentError("Foundry create does not accept ordinary identity selectors")
        validate_dnsid_config(
            self.config.dnsid,
            resolver_injected=self.deps.dns_resolver is not None,
            fetcher_injected=self.deps.https_fetcher is not None,
        )
        if not isinstance(self.config.foundry, FoundryConfig):
            raise ArgumentError("config.foundry must be a FoundryConfig")
        for value in (self.config.foundry.organization_id, self.config.foundry.governance_id):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ArgumentError("Foundry expectations must be nonempty strings")
        if self.config.foundry.governance_id is not None:
            normalize_fqdn(self.config.foundry.governance_id)
        if self._provider is None:
            self._provider = provider_call(_operational_key_provider, self.config.key_source, "")
            if self._provider is None:
                raise KeyMissing("configure an existing signing key or inject a key provider")
        if self.deps.log_registry is None:
            if not _has_trust(self.config.log_trust):
                raise ArgumentError(
                    "Foundry create requires explicit log_trust or deps.log_registry"
                )
            self._owned_log_registry = _log_registry_from_trust(
                self.config.log_trust,
                self.config.dnsid.transport,
            )
            self.deps.log_registry = self._owned_log_registry
        if self._registry is None:
            self._registry = RegistryClient(
                self.config.registry.registry_url or None,
                api_key=self._credential,
                transport_config=self.config.dnsid.transport,
            )

    def onboarding(self) -> tuple[str, str]:
        try:
            result = self.registry.get_organization_onboarding()
        except RegistryRequestError as cause:
            if cause.status_code in {404, 405}:
                raise UnsupportedRegistry(
                    "registry has no supported onboarding endpoint", cause=cause
                )
            raise
        except ValidationError as cause:
            raise UnsupportedRegistry("registry onboarding contract is incomplete", cause=cause)
        if not isinstance(result, dict) or not (
            isinstance(result.get("org_id"), str)
            and result["org_id"].strip()
            and isinstance(result.get("ek"), dict)
            and "status" in result["ek"]
        ):
            raise UnsupportedRegistry("registry onboarding contract is incomplete")
        if "gi" in result and not (
            isinstance(result["gi"], dict)
            and all(member in result["gi"] for member in ("domain", "state", "gate_authorized"))
        ):
            raise UnsupportedRegistry("registry onboarding contract is incomplete")
        if "governance_domain" not in result or "gi" not in result:
            raise WorkflowOutcome("organization onboarding is not ready", resumable=True)
        org = result["org_id"]
        try:
            gi = normalize_fqdn(result["governance_domain"])
            proof_gi = normalize_fqdn(result["gi"]["domain"])
        except (TypeError, ValidationError) as cause:
            raise UnsupportedRegistry("registry onboarding has invalid domain fields", cause=cause)
        if self.config.foundry.organization_id not in {None, org} or (
            self.config.foundry.governance_id is not None
            and normalize_fqdn(self.config.foundry.governance_id) != gi
        ):
            raise UnsupportedContract("configured Foundry account bindings do not match onboarding")
        if proof_gi != gi or (
            result["gi"]["state"] != "verified"
            or result["gi"]["gate_authorized"] is not True
            or result["ek"]["status"] != "verified"
        ):
            raise WorkflowOutcome("organization onboarding is not ready", resumable=True)
        remaining_seconds()
        return org, gi

    def bindings(self, operation: dict[str, Any], org: str, gi: str) -> None:
        validate_operation(operation, (self.registry_url, org, operation["name"]))
        if operation["governanceId"] != normalize_fqdn(gi):
            raise _BindingMismatch("saved governance binding differs from onboarding")
        configured = self.config.foundry
        if configured.organization_id not in {None, org} or (
            configured.governance_id is not None
            and normalize_fqdn(configured.governance_id) != operation["governanceId"]
        ):
            raise _BindingMismatch("configured account differs from the saved operation")
        trust = self.trust_document()
        if "logTrust" in operation and trust and operation["logTrust"] != trust:
            raise _BindingMismatch("configured log trust differs from the saved operation")

    def signing_key(self, operation: dict[str, Any]) -> JWK:
        if not provider_call(self.provider.list_key_ids):
            raise KeyMissing(
                "provider has no signing key; create the key first, for example through "
                "explicit KMS-first creation"
            )
        selected = provider_call(self.provider.signing_key)
        if operation:
            expected = JWK.from_dict(
                operation.get("currentPublicKey", operation["initialPublicKey"])
            )
            if (selected.kid, selected.alg, selected.thumbprint()) != (
                expected.kid,
                expected.alg,
                expected.thumbprint(),
            ):
                raise KeyMismatch(
                    "use the provider key this identity was created with; "
                    "run one identity per cloud provider",
                    operation=operation,
                )
        else:
            _live_key(selected)
        return selected

    def key_source(self, public: dict[str, Any]) -> dict[str, Any]:
        if self._injected_provider:
            return {"provider": "injected", "keyRef": public["kid"]}
        source = self.config.key_source
        result = {
            name: getattr(source, field)
            for name, field in (
                ("provider", "provider"),
                ("keyRef", "key_ref"),
                ("settings", "settings"),
                ("cliDirectory", "cli_directory"),
                ("keyStorePath", "key_store_path"),
            )
            if getattr(source, field) is not None
        }
        return result or {"provider": "injected", "keyRef": public["kid"]}

    def trust_document(self) -> dict[str, Any]:
        if self._injected_log_registry:
            return {}
        trust = self.config.log_trust
        result: dict[str, Any] = {}
        if trust.managed is not None:
            result["managed"] = trust.managed
        if trust.policy_url is not None:
            result["policyUrl"] = trust.policy_url
        if trust.policy_document is not None:
            result["policyDocument"] = b64url_encode(trust.policy_document)
        if trust.profile is not None:
            profile = trust.profile
            keys = []
            for key in profile.bundle_verifier_keys:
                encoded = base64.b64encode((key.signature_type or b"") + key.key_bytes).decode()
                keys.append(
                    f"{key.name}+{key.key_id.hex()}+{encoded}"
                    if key.key_id
                    else (f"{key.name} {encoded}")
                )
            result["profile"] = {
                "version": profile.version,
                "scope": profile.scope,
                "log_prefix": profile.log_prefix,
                "tlog_policy": profile.policy_document.decode("utf-8"),
                "bundle_verifier_keys": keys,
            }
        return result

    @contextmanager
    def locked_operation(
        self, key: OperationKey, signer: ApplicationSigner | None = None,
    ) -> Iterator[dict[str, Any]]:
        with self.store.lock(key):
            operation = self.store.load(key) or {}
            try:
                yield operation
            except Exception as cause:
                if operation and (
                    isinstance(cause, (KeyMismatch, TerminalIdentity, _BindingMismatch))
                    or getattr(cause, "error_code", "") == "KEY_MISMATCH"
                ):
                    operation["signingPaused"] = True
                    try:
                        with detached_budget(5.0):
                            self.save(key, operation)
                    except Exception as save_error:
                        cause.add_note(f"could not persist signing pause: {save_error!r}")
                    finally:
                        if signer is not None:
                            signer.paused = True
                raise

    def save(self, key: OperationKey, operation: dict[str, Any]) -> None:
        remaining_seconds()
        self.store.save(key, operation)
        remaining_seconds()

    def registration(self, operation: dict[str, Any]) -> AgentRegistration:
        result = self.registry.get_registration(operation["domain"])
        remaining_seconds()
        if result is None:
            raise FoundryError("registry identity is not available", resumable=True)
        if result.id != operation["identityId"] or result.domain != operation["domain"]:
            raise _BindingMismatch("registry read changed the saved identity binding")
        return result

    def remember_registration(
        self,
        key: OperationKey,
        operation: dict[str, Any],
        registration: AgentRegistration,
    ) -> None:
        operation["registryStatus"] = registration.registry_status
        self.save(key, operation)
        _registry_outcome(operation)

    def publication(
        self,
        key: OperationKey,
        operation: dict[str, Any],
        registration: AgentRegistration,
    ) -> None:
        publication = registration.publication_config
        if registration.publication_authority != "registry" or publication is None:
            raise UnsupportedContract("Foundry requires registry-managed publication configuration")
        if normalize_fqdn(publication.governance_id) != operation["governanceId"]:
            raise _BindingMismatch("publication governance binding mismatch")
        _validate_publication_config(publication, operation["domain"])
        snapshot = {
            _PUBLICATION[name]: value for name, value in asdict(publication).items() if value != ""
        }
        saved = operation.get("publicationConfig", {})
        if saved and {member: saved.get(member) for member in snapshot} != snapshot:
            raise _BindingMismatch("registry changed the saved publication configuration")
        operation["publicationConfig"] = {**saved, **snapshot}
        if registration.oidc_issuer_url:
            if operation.get("oidcIssuerUrl", registration.oidc_issuer_url) != (
                registration.oidc_issuer_url
            ):
                raise _BindingMismatch("registry changed the saved OIDC issuer")
            operation["oidcIssuerUrl"] = registration.oidc_issuer_url
        self.save(key, operation)

    def manager(
        self,
        operation: dict[str, Any],
        signer: ApplicationSigner | None = None,
    ) -> IdentityManager:
        publication = PublicationConfig(
            **{
                name: operation["publicationConfig"][member]
                for name, member in _PUBLICATION.items()
                if member in operation["publicationConfig"]
            }
        )
        identity = IdentityConfig(
            domain=operation["domain"],
            **{field.name: getattr(publication, field.name) for field in fields(publication)},
        )
        provider = signer or self.provider
        config = DnsidConfig(
            identity=identity,
            transport=copy.deepcopy(self.config.dnsid.transport),
            verification=copy.deepcopy(self.config.dnsid.verification),
        )
        return IdentityManager(
            config,
            provider,
            replace(
                self.deps,
                cache=self.deps.cache if signer is not None else None,
                entity_key_provider=None,
            ),
        )

    def entity_key(self, operation: dict[str, Any], verifier: IdentityManager) -> JWK:
        publication = operation["publicationConfig"]
        host = _ek_pinning_host(operation["governanceId"], publication["ekUrl"])
        keys, _ = verifier._fetch_key_set(publication["ekUrl"], host, True, revalidate=True)
        keys.validate_record_signing(publication["publishProfile"])
        entity = keys.keys[0]
        if (
            "entityPublicKey" in operation
            and JWK.from_dict(
                operation["entityPublicKey"],
            ).thumbprint()
            != entity.thumbprint()
        ):
            raise _BindingMismatch("entity key changed without supported continuity")
        operation["entityPublicKey"] = entity.to_dict()
        return entity

    def recover_issuance(
        self,
        operation: dict[str, Any],
        entity: JWK,
        store: IssuanceStore,
        *,
        expected: ManagedIssuanceState | None = None,
    ) -> bool:
        reference = operation["publicationConfig"]["logRef"]
        if self.deps.log_registry is None:
            raise ArgumentError("Foundry requires log trust")
        reader = self.deps.log_registry.new_reader(reference)
        if not isinstance(reader, C2spTlogReader):
            raise UnsupportedContract("Foundry managed issuance requires a c2sp-tlog reader")
        history = reader._load_complete_history(operation["domain"], entity, require_fresh=True)
        if history.current_stream_events:
            from ..models import DomainLog

            snapshot = DomainLog(
                operation["domain"], [item.event for item in history.current_stream_events]
            ).snapshot_at(datetime.datetime.now(datetime.UTC))
            if snapshot.historical_state in {"REVOKED", "RETIRED"}:
                operation["registryStatus"] = snapshot.historical_state
                raise TerminalIdentity(
                    "accepted lifecycle history is terminal", operation=operation
                )
        creation_key = JWK.from_dict(operation["creationInput"]["public_key"])
        for event in history.current_stream_events:
            # History verification already checked inclusion, signatures, and chain continuity.
            from ..c2sp_tlog import C2spVerificationContext, entry_bytes, parse_prepared_issuance

            if not isinstance(event.event, IssuanceEvent):
                continue
            initial = event.event.operational_key
            if initial is None or (
                initial.thumbprint() != creation_key.thumbprint()
                and snapshot.active_key_thumbprint != creation_key.thumbprint()
            ):
                raise KeyMismatch("creation key does not follow from the accepted issuance")
            context = C2spVerificationContext(
                fqdn=operation["domain"],
                gi=operation["governanceId"],
                entity_key=entity,
                operational_key=initial,
            )
            prepared = parse_prepared_issuance(event.data, context)
            if prepared.reference.lr != reference or entry_bytes(prepared, context) != event.data:
                raise _BindingMismatch("accepted issuance has an unexpected binding")
            if expected is not None:
                if (
                    expected.entry_bytes != event.data
                    or expected.submission is None
                    or (expected.submission.index != event.index)
                ):
                    raise _BindingMismatch("accepted log entry differs from saved acceptance")
                return True
            from ..models import LogRef

            state = ManagedIssuanceState(
                domain=operation["domain"],
                governance_id=operation["governanceId"],
                log_reference=reference,
                entity_public_key=entity,
                operational_public_key=initial,
                idempotency_key=issuance_key(operation["requestId"]),
                entry_bytes=event.data,
                entry_hash=hashlib.sha256(event.data).hexdigest(),
                submission=SubmissionResult(
                    "accepted",
                    hashlib.sha256(event.data).hexdigest(),
                    event.index,
                    LogRef.parse(f"{reference}@{event.index}"),
                ),
            )
            operation["initialPublicKey"] = initial.to_dict()
            if initial.thumbprint() != creation_key.thumbprint():
                operation["currentPublicKey"] = creation_key.to_dict()
            store.persist_managed_issuance(state)
            return True
        return False

    def check_public(self, operation: dict[str, Any], observed: Any, selected: JWK) -> None:
        publication = operation["publicationConfig"]
        if (observed.domain, observed.record.v, observed.record.gi, observed.record.lr) != (
            operation["domain"],
            publication["publishProfile"],
            operation["governanceId"],
            publication["logRef"],
        ) or observed.signing_key.thumbprint() != JWK.from_dict(
            operation["entityPublicKey"],
        ).thumbprint():
            raise _BindingMismatch("public identity does not match the expected bindings")
        public = observed.jwks.current_operational_signing_key(observed.record.v)
        if public.thumbprint() != selected.thumbprint():
            raise KeyMismatch("signed current ku does not serve the configured provider key")
        if observed.registry_status.state != "ACTIVE":
            raise UnsupportedContract("public protocol status is not ACTIVE")

    def close(self) -> None:
        if self._owned_registry and self._registry is not None:
            self._registry.close()
        if self._owned_log_registry is not None:
            self._owned_log_registry.close()


def _live_key(key: JWK) -> dict[str, Any]:
    if (key.kty, key.alg, key.to_dict().get("crv")) != ("OKP", "EdDSA", "Ed25519"):
        raise UnsupportedAlgorithm("Foundry named Live creation requires Ed25519/EdDSA")
    return _live_public_jwk_dict(key)


def _registry_outcome(operation: dict[str, Any]) -> None:
    state = operation.get("registryStatus")
    if state in {"REVOKED", "RETIRED"}:
        raise TerminalIdentity("terminal identities cannot be replaced", operation=operation)
    if state in {"ERROR", "REJECTED", "CANCELLED"}:
        raise WorkflowOutcome("registry workflow requires customer action", operation=operation)


def _sleep(delay: float) -> float:
    time.sleep(remaining_seconds(delay))
    remaining_seconds()
    return min(delay * 2, 15.0)


def _error(cause: Exception, operation: dict[str, Any]) -> FoundryError:
    facts = getattr(cause, "registration_response", None) or {}
    operation = {
        **{
            "identityId": facts.get("agent_id", facts.get("id")),
            "domain": facts.get("domain"),
            "registryStatus": facts.get("status"),
        },
        **operation,
    }
    if isinstance(cause, FoundryError):
        for field, value in (
            ("phase", operation.get("phase", "")),
            ("identity_id", operation.get("identityId")),
            ("domain", operation.get("domain")),
            ("registry_status", operation.get("registryStatus")),
        ):
            if not getattr(cause, field):
                setattr(cause, field, value)
        return cause
    if isinstance(cause, BudgetExhausted):
        return FoundryDeadline(
            "Foundry deadline exceeded or cancelled",
            operation=operation,
            resumable=True,
            cause=cause,
        )
    code = getattr(cause, "error_code", "")
    error_type: type[FoundryError] = {
        "KEY_MISSING": KeyMissing,
        "KEY_MISMATCH": KeyMismatch,
        "KEY_REVOKED": KeyRevoked,
    }.get(code, FoundryError)
    message = (
        "use the provider key this identity was created with; "
        "run one identity per cloud provider"
        if error_type is KeyMismatch
        else "Foundry operation failed; inspect the structured cause and resume facts"
    )
    return error_type(
        message,
        operation=operation,
        resumable=isinstance(cause, (TimeoutError, OSError)) or getattr(cause, "transient", False),
        cause=cause,
    )
