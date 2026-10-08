"""Durable managed setup using permanent server-side registration idempotency."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import os
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any

from ._utils import normalize_fqdn
from ._verification_budget import BudgetExhausted, remaining_seconds, verification_budget
from .config_loading import (
    LoadedConfig,
    _log_registry_from_trust,
    _operational_key_provider,
    _validate_key_source,
    _validate_log_trust,
    construct_identity_manager,
)
from .exceptions import ArgumentError, DNSidError, ValidationError, VerificationError
from .interfaces import KeyProvider, NoopLogReader
from .local_key_provider import LocalKeyProvider
from .managed_issuance import (
    ManagedIssuanceState,
    issue_managed_identity,
    validate_managed_issuance,
)
from .manager import IdentityManager, IdentityManagerDependencies, validate_dnsid_config
from .models import (
    JWK,
    AgentRegistration,
    AgentRegistrationInput,
    IdentityConfig,
    IssuanceEvent,
    LoggedStateEvidence,
    PublicationConfig,
    PublishedRecord,
    TrustedEntity,
    _parse_https_uri_host,
)
from .registry_client import RegistryClient, _public_jwk_dict, _validate_publication_config


class ManagedRegistrationError(DNSidError):
    """Setup failure retaining phase and identity, without credentials or private material."""

    def __init__(
        self,
        category: str,
        phase: str,
        state: dict[str, Any] | None = None,
        *,
        cause: BaseException | None = None,
        resumable: bool = False,
    ) -> None:
        """Initialize structured recovery guidance and preserve the underlying category."""
        super().__init__(f"managed registration {category} during {phase}")
        state = state or {}
        registration = state.get("registration") or state.get("creation_facts") or {}
        self.category = category
        self.phase = phase
        self.domain = registration.get("domain", "")
        self.registration_id = registration.get("id", "")
        self.registry_status = state.get("registry_status", "")
        self.convergence_state = state.get("phase", phase)
        self.resumable = resumable
        self.verification_code = getattr(cause, "code", None)
        self.cause_category = getattr(cause, "category", None)
        if isinstance(cause, DNSidError):
            self.status_code = cause.status_code
            self.error_code = cause.error_code
        if cause is not None:
            self.__cause__ = cause


class FileRegistrationStore:
    """Named operations and separate private keys on durable POSIX local storage.

    Requires an existing parent, flock, atomic replace, and file/directory fsync.
    Back up both operations/ and keys/ trees; container-local storage is not durable.
    Kernel locks recover after process exit. Never delete a live lock sidecar.
    """

    def __init__(self, directory: Path | str) -> None:
        """Select an explicit durable directory; initialization occurs under exclusive()."""
        self.directory = Path(directory).resolve()
        self._root = self.directory
        self._scope: tuple[str, str, str] | None = None
        self._key_path = self.directory / "key.json"
        self._held = False
        self._thread_lock = threading.Lock()

    def select(self, registry: str, organization: str, name: str) -> FileRegistrationStore:
        """Select a safe tenant-isolated path; the tuple is also checked in state."""
        scope = (registry, _organization_id(organization), _name(name))
        if self._scope is not None:
            if scope != self._scope:
                raise ManagedRegistrationError("store_scope_binding", "storage")
            return self
        digest = _digest(list(scope))
        selected = FileRegistrationStore(self.directory / "operations" / digest)
        selected._root = self.directory
        selected._scope = scope
        selected._key_path = self.directory / "keys" / digest / "key.json"
        return selected

    @property
    def key_path(self) -> Path:
        """Return the stable private-key location, separate from recovery state."""
        return self._key_path

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        """Hold a nonblocking process/thread lock; kernel recovery handles process death."""
        remaining_seconds()
        if os.name != "posix":
            raise ManagedRegistrationError("unsupported_platform", "storage")
        import fcntl

        if not self._thread_lock.acquire(blocking=False):
            raise ManagedRegistrationError("busy", "storage", resumable=True)
        fd: int | None = None
        try:
            if self._scope is not None and any(
                (self._root / name).exists() for name in ("registration.json", "key.json")
            ):
                raise ManagedRegistrationError("legacy_store", "storage")
            directories = [self._root]
            if self._scope is not None:
                directories += [
                    self.directory.parent,
                    self.directory,
                    self.key_path.parent.parent,
                    self.key_path.parent,
                ]
            for directory in directories:
                directory.mkdir(mode=0o700, exist_ok=True)
                os.chmod(directory, 0o700)
                _sync_directory(directory.parent)
            fd = os.open(self.directory / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ManagedRegistrationError("busy", "storage", resumable=True) from None
            self._held = True
            remaining_seconds()
            yield
        finally:
            self._held = False
            if fd is not None:
                os.close(fd)
            self._thread_lock.release()

    def load(self) -> dict[str, Any] | None:
        """Read bounded JSON, rejecting abandoned or partial initialization artifacts."""
        self._require_lock()
        from .config_loading import _json_object

        path = self.directory / "registration.json"
        if not path.exists():
            if any(p.name != ".lock" for p in self.directory.iterdir()) or (
                self._scope is not None and any(self.key_path.parent.iterdir())
            ):
                raise ManagedRegistrationError("incomplete_state", "storage")
            return None
        with path.open("rb") as file:
            raw = file.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ManagedRegistrationError("resource_limit", "storage")
        return _json_object(raw, "registration recovery state")

    def save(self, state: dict[str, Any]) -> None:
        """Flush public state before atomic replacement, then flush the parent directory."""
        self._require_lock()
        payload = json.dumps(state, sort_keys=True, allow_nan=False).encode()
        if len(payload) > 4 * 1024 * 1024:
            raise ManagedRegistrationError("resource_limit", "storage", state)
        fd, name = tempfile.mkstemp(prefix=".registration-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(payload)
                file.flush()
                os.fsync(file.fileno())
            os.replace(name, self.directory / "registration.json")
            _sync_directory(self.directory)
        finally:
            Path(name).unlink(missing_ok=True)

    def _require_lock(self) -> None:
        if not self._held:
            raise ManagedRegistrationError("store_not_locked", "storage")


def _sync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass
class ManagedRegistrationResult:
    """Retained creation snapshot, local application manager, and fresh public evidence."""

    registration: AgentRegistration
    manager: IdentityManager
    published_record: PublishedRecord
    logged_state_evidence: LoggedStateEvidence


def register_managed_identity(
    name: str,
    loaded: LoadedConfig,
    credential: str,
    store: FileRegistrationStore,
    input: AgentRegistrationInput | None = None,
    *,
    key_provider: KeyProvider | None = None,
    provider_reference: str = "",
    deps: IdentityManagerDependencies | None = None,
    log_registry_reference: str = "",
    timeout: float = 300.0,
    interval: float = 1.0,
    cancelled: threading.Event | None = None,
    replace_terminal: bool = False,
) -> ManagedRegistrationResult:
    """Register/resume a case-sensitive name with fresh public ACTIVE evidence.

    Requires permanent organization-scoped named replay on the registry.
    Resolve verified account bindings before generation; retain the initial
    public key and derive replay keys from organization/name/thumbprint.
    Use the same store to resume. Explicit replacement requires verified terminal
    history and a fresh key. Caller-injected key/log providers need stable references.
    The five-minute deadline covers SDK networking; injected dependencies must honor
    remaining_seconds(). Final verification is isolated from application policy/cache,
    and does not widen the returned manager's counterparty acceptance.
    """
    name = _name(name)
    if not math.isfinite(interval) or interval <= 0:
        raise ArgumentError("interval must be finite and positive")
    loaded = copy.deepcopy(loaded)
    deps = replace(deps) if deps else IdentityManagerDependencies()
    account = loaded.registration
    endpoint = account.entity_key_url
    try:
        gi = normalize_fqdn(account.governance_id) if account.governance_id else ""
        organization = _organization_id(account.organization_id) if account.organization_id else ""
        bootstrap_host = _parse_https_uri_host(endpoint, field_name="registration.entity_key_url")
    except (ValidationError, TypeError, ValueError) as error:
        raise ArgumentError("invalid registration account/GI/entity_key_url") from error
    _validate_endpoint(gi, bootstrap_host)
    validate_dnsid_config(
        loaded.dnsid,
        resolver_injected=deps.dns_resolver is not None,
        fetcher_injected=deps.https_fetcher is not None,
    )
    request = _request_dict(input if input is not None else AgentRegistrationInput())
    if request["name"] and _name(request["name"]) != name:
        raise ArgumentError("input.name must match the managed registration name")
    if gi and request["governance_domain"] and request["governance_domain"] != gi:
        raise ArgumentError("requested governance_domain disagrees with registration.governance_id")
    if key_provider is not None and not provider_reference:
        raise ArgumentError("injected key_provider requires a stable provider_reference")
    source = loaded.key_source
    source_domain = loaded.dnsid.identity.domain if loaded.dnsid.identity else request["domain"]
    source_selected = key_provider is None and any(
        (
            source.cli_directory,
            source.key_store_path,
            source.key_ref,
            source.generation,
            source.provider not in {None, "file"},
        )
    )
    if key_provider is None:
        _validate_key_source(source)
        if source.cli_directory and not source_domain:
            raise ArgumentError("CLI key selection requires an explicit local domain")
        if source.provider in {None, "file"} and (not source_selected or source.generation):
            import warnings

            warnings.warn(
                "Local file keys are unsuitable for production; configure keySource.provider "
                "with a cloud provider and keyRef.",
                UserWarning,
                stacklevel=2,
            )
    if deps.log_registry is not None:
        if not log_registry_reference:
            raise ArgumentError("injected log_registry requires a stable log_registry_reference")
        from .config_loading import LogTrust

        loaded.log_trust = LogTrust()
    else:
        _validate_log_trust(loaded.log_trust)
    state: dict[str, Any] | None = None
    manager: IdentityManager | None = None
    success = False
    phase = "validation"
    client = RegistryClient(
        loaded.registry.registry_url or None,
        api_key=credential,
        transport_config=loaded.dnsid.transport,
    )
    registry = client._base_url
    try:
        with ExitStack() as access:
            access.enter_context(verification_budget(timeout, cancelled=cancelled))
            phase = "provider"
            selected_provider = key_provider
            if key_provider is None and source_selected and source.generation is None:
                selected_provider = _operational_key_provider(source, source_domain)
                if selected_provider is None:
                    raise ArgumentError("selected provider unavailable; no file fallback")
            phase = "account"
            if not organization:
                organization, discovered_gi = _discover_account(client, organization, gi, interval)
                gi = gi or discovered_gi
            phase = "storage"
            store = store.select(registry, organization, name)
            access.enter_context(store.exclusive())
            phase = "recovery"
            state = store.load()
            if state is not None:
                _validate_state(state)
                if (state["registry"], state["organization"], state["name"]) != (
                    registry,
                    organization,
                    name,
                ):
                    raise ManagedRegistrationError("account_binding", phase, state)
                if gi and gi != state["governance_id"]:
                    raise ManagedRegistrationError("account_binding", phase, state)
                gi = gi or state["governance_id"]
            if not gi:
                phase = "account"
                _, gi = _discover_account(client, organization, gi, interval)
            _validate_endpoint(gi, bootstrap_host)
            if request["governance_domain"] and request["governance_domain"] != gi:
                raise ManagedRegistrationError("account_binding", phase, state)
            loaded.registration.governance_id = gi
            loaded.registration.organization_id = organization
            reference = (
                provider_reference
                if key_provider
                else (
                    json.dumps(asdict(source), sort_keys=True)
                    if source_selected
                    else str(store.key_path)
                )
            )
            binding = _binding_digest(loaded, gi, endpoint) + ":" + log_registry_reference
            if state is not None:
                if state["binding"] != binding or (
                    not replace_terminal
                    and not state["complete"]
                    and state["provider"] != reference
                ):
                    raise ManagedRegistrationError("conflicting_binding", "recovery", state)
                if input is not None and not replace_terminal:
                    if _input_fingerprint(request) != state["input_fingerprint"]:
                        raise ManagedRegistrationError("conflicting_input", "recovery", state)
                    if request["public_key_jwk"] is not None and state["initial_key"] is not None:
                        expected_key = JWK.from_dict(state["initial_key"]).thumbprint()
                        if JWK.from_dict(request["public_key_jwk"]).thumbprint() != expected_key:
                            raise ManagedRegistrationError("operational_binding", "recovery", state)
            phase = "trust"
            if deps.log_registry is None:
                deps.log_registry = _log_registry_from_trust(
                    loaded.log_trust, loaded.dnsid.transport
                )
            history = state["history"] if state is not None else []
            if replace_terminal:
                if state is None:
                    raise ManagedRegistrationError("replacement_requires_history", "replacement")
                if state["registration"] is not None:
                    phase = "replacement"
                    history = _terminal_history(state, client, deps, interval)
                    state = None
                elif not history:
                    raise ManagedRegistrationError(
                        "replacement_requires_terminal", "replacement", state
                    )
            locator = store.key_path
            if history:
                locator = locator.with_name(f"key-{len(history)}.json")
            if key_provider is None and source.generation is not None:
                locator = (
                    Path(source.generation.locator).expanduser().resolve()
                    / _digest([registry, organization, name])
                    / locator.name
                )
            if (
                state is not None
                and key_provider is None
                and (not source_selected or source.generation is not None)
                and state["key_locator"] != str(locator)
            ):
                raise ManagedRegistrationError("key_locator_binding", "recovery", state)
            if state is None:
                extras = _extra_input(request)
                state = {
                    "version": 3,
                    "history": history,
                    "binding": binding,
                    "registry": registry,
                    "organization": organization,
                    "name": name,
                    "governance_id": gi,
                    "input": extras,
                    "input_fingerprint": _input_fingerprint(request),
                    "provider": reference,
                    "key_locator": str(locator),
                    "key_creation_started": False,
                    "initial_key": None,
                    "creation_facts": None,
                    "registration": None,
                    "entity_key": None,
                    "issuance": None,
                    "acceptance": None,
                    "registry_status": "",
                    "phase": "intent",
                    "complete": False,
                }
                if history:
                    if key_provider is None:
                        key_provider = selected_provider
                    if key_provider is not None and any(
                        key_provider.signing_key().thumbprint() in item["key_history"]
                        for item in history
                    ):
                        raise ManagedRegistrationError("historical_key_reuse", "replacement", state)
                store.save(state)
            phase = "key"
            locator = Path(state["key_locator"])
            if key_provider is None:
                key_provider = selected_provider
            if key_provider is None:
                if state["initial_key"] is not None and not locator.exists():
                    raise ManagedRegistrationError("missing_key", phase, state)
                if not locator.exists() and state["key_creation_started"]:
                    raise ManagedRegistrationError("ambiguous_key_creation", phase, state)
                if not locator.exists():
                    state["key_creation_started"] = True
                    store.save(state)
                    if source.generation:
                        locator.parent.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        locator.parent.mkdir(mode=0o700, exist_ok=True)
                        _sync_directory(locator.parent.parent)
                key_provider = LocalKeyProvider.load(
                    locator,
                    create_if_missing=True,
                    algorithm=source.generation.algorithm if source.generation else "EdDSA",
                )
            if (
                state["complete"]
                and isinstance(key_provider, LocalKeyProvider)
                and key_provider._store.pending
            ):
                raise ManagedRegistrationError("pending_rotation_recovery_required", phase, state)
            operational = key_provider.signing_key()
            public = _public_jwk_dict(operational)
            if state["initial_key"] is None:
                if any(
                    operational.thumbprint() in item["key_history"] for item in state["history"]
                ):
                    raise ManagedRegistrationError("historical_key_reuse", "replacement", state)
                supplied = request["public_key_jwk"]
                if (
                    supplied is not None
                    and JWK.from_dict(supplied).thumbprint() != operational.thumbprint()
                ):
                    raise ManagedRegistrationError("operational_binding", phase, state)
                state["initial_key"] = public
                store.save(state)
            elif not state["complete"] and public != state["initial_key"]:
                raise ManagedRegistrationError("operational_binding", phase, state)
            registration_key, issuance_key = _replay_keys(state)
            phase = "creation"
            while state["registration"] is None:
                remaining_seconds()
                if _known_creation(state):
                    detail = _retry(
                        lambda: client.get_agent_detail(state["creation_facts"]["domain"]),
                        interval,
                    )
                    registration = _registration_with_facts(state, detail)
                    _retain_registration(state, registration)
                    store.save(state)
                    break
                state["phase"] = phase
                store.save(state)
                try:
                    registration = client.register_agent(
                        _creation_request(state),
                        registration_key,
                    )
                except DNSidError as error:
                    if error.registration_response:
                        facts = {
                            name: error.registration_response[name]
                            for name in ("id", "domain", "publication_config", "oidc_issuer_url")
                            if name in error.registration_response
                        }
                        publication_facts = facts.get("publication_config")
                        if isinstance(publication_facts, dict):
                            facts["publication_config"] = {
                                f.name: publication_facts[f.name]
                                for f in fields(PublicationConfig)
                                if f.name in publication_facts
                            }
                            facts["publication_config"].setdefault("capabilities_url", "")
                            facts["publication_config"].setdefault("max_key_age", "")
                        previous = state["creation_facts"] or {}
                        if any(
                            name in previous and previous[name] != value
                            for name, value in facts.items()
                        ):
                            raise ManagedRegistrationError(
                                "creation_binding", phase, state
                            ) from error
                        state["creation_facts"] = {**previous, **facts}
                        store.save(state)
                    if not getattr(error, "transient", False):
                        raise
                    _pause(interval)
                    continue
                try:
                    _retain_registration(state, registration)
                finally:
                    store.save(state)
            assert state["registration"] is not None
            registration = _registration_from_dict(state["registration"])
            phase = "identity_read"
            detail = _retry(lambda: client.get_agent_detail(registration.domain), interval)
            _check_detail(state, detail)
            current_publication = registration.publication_config
            if state["complete"] and detail is not None and detail.publication_config is not None:
                current_publication = detail.publication_config
            phase = "publication_binding"
            publication = registration.publication_config
            assert publication is not None
            _validate_publication_config(publication, registration.domain)
            if registration.raw.get("tier") == "live":
                raise ManagedRegistrationError("unsupported_workflow", phase, state)
            if registration.publication_authority != "registry":
                raise ManagedRegistrationError("unsupported_authority", phase, state)
            if publication.governance_id != gi or publication.ek_url != endpoint:
                raise ManagedRegistrationError("publication_binding", phase, state)
            assert current_publication is not None
            _validate_saved_identity(loaded, state, current_publication)
            identity = IdentityConfig(domain=registration.domain, **asdict(current_publication))
            local = replace(
                loaded,
                dnsid=replace(loaded.dnsid, identity=identity),
                key_source=replace(source, entity_key_path=None),
            )
            manager = construct_identity_manager(local, key_provider, deps)
            # Construction validates assigned log syntax and explicit independent trust.
            if manager._log_registry is None or isinstance(
                manager._local_log_binding, NoopLogReader
            ):
                raise ManagedRegistrationError("log_trust_required", phase, state)
            if not state["complete"]:
                phase = "ownership"
                status = _retry(lambda: client.get_agent_status(registration.domain), interval)
                while (
                    status is not None and not status.ready_for_publication and not status.published
                ):
                    state["registry_status"] = status.registry_status
                    store.save(state)
                    if status.failed or status.terminal:
                        raise ManagedRegistrationError("terminal_registry", phase, state)
                    _pause(interval)
                    status = _retry(lambda: client.get_agent_status(registration.domain), interval)
                if status is None:
                    raise ManagedRegistrationError("registration_missing", phase, state)
                if status.failed or status.terminal:
                    raise ManagedRegistrationError("terminal_registry", phase, state)
                state["registry_status"] = status.registry_status
                store.save(state)
            if state["entity_key"] is None:
                phase = "entity_key"
                keys, _ = _retry(lambda: manager._fetch_key_set(endpoint, gi, True), interval)
                state["entity_key"] = keys.current_record_signing_key(
                    publication.publish_profile
                ).to_dict()
                store.save(state)
            entity = JWK.from_dict(state["entity_key"])
            if state["acceptance"] is not None:
                phase = "issuance_recovery"
                _recover_issuance(state, manager._local_log_binding, entity)
            elif (
                state["issuance"] is None
                and detail is not None
                and (detail.dns_published or detail.registry_status == "READY")
            ):
                phase = "issuance_recovery"
                _recover_issuance(state, manager._local_log_binding, entity)
                store.save(state)
            if not state["complete"] and state["acceptance"] is None:
                phase = "issuance"

                def persist_issuance(issuance: ManagedIssuanceState) -> None:
                    state["issuance"] = issuance.to_dict()
                    state["phase"] = "issuance"
                    store.save(state)

                while True:
                    issuance = _retry(
                        lambda: issue_managed_identity(
                            domain=registration.domain,
                            governance_id=gi,
                            log_reference=publication.log_ref,
                            entity_key=entity,
                            operational_key_provider=key_provider,
                            registry_client=client,
                            idempotency_key=issuance_key,
                            persist_issuance=persist_issuance,
                            issuance=ManagedIssuanceState.from_dict(state["issuance"])
                            if state["issuance"]
                            else None,
                        ),
                        interval,
                    )
                    if issuance.submission is not None and issuance.submission.accepted:
                        break
                    _pause(interval)
            # Never use the application cache or owner credentials as public evidence.
            phase = "public_verification"
            isolated = replace(
                deps,
                log_registry=manager._log_registry,
                cache=None,
                entity_key_provider=None,
            )
            verifier_config = replace(
                local,
                dnsid=replace(
                    local.dnsid,
                    verification=replace(
                        local.dnsid.verification,
                        trusted_entities=[TrustedEntity(gi, (entity.thumbprint(),))],
                    ),
                ),
            )
            verifier = construct_identity_manager(verifier_config, key_provider, isolated)
            try:
                published = _retry(
                    lambda: verifier.await_registry_managed_publication(
                        client,
                        timeout=remaining_seconds(timeout),
                        interval=interval,
                    ),
                    interval,
                    publication=True,
                )
                state["registry_status"] = published.publication_status
                store.save(state)
                verified = _retry(
                    lambda: verifier.verify_domain(registration.domain), interval, publication=True
                )
                if (
                    verified.record.lr != publication.log_ref
                    or verified.record.v != publication.publish_profile
                    or verified.record.ek != endpoint
                    or verified.record.ku != current_publication.ku_url
                    or verified.record.su != publication.status_url
                    or verified.record.gi != gi
                    or verified.record.cu != publication.capabilities_url
                    or verified.record.ka != publication.max_key_age
                    or verified.signing_key.thumbprint() != entity.thumbprint()
                    or verified.jwks.current_operational_signing_key().thumbprint()
                    != operational.thumbprint()
                    or verified.registry_status.state != "ACTIVE"
                ):
                    raise ManagedRegistrationError("public_binding", phase, state)
                evidence = verifier.verify_log_evidence(verified)
                if (
                    evidence.log_reference != publication.log_ref
                    or evidence.logged_state != "ACTIVE"
                ):
                    raise ManagedRegistrationError("terminal_identity", phase, state)
                snapshot = verifier.load_domain_log(verified).snapshot_at(verified.verified_at)
                if (
                    snapshot.active_key_thumbprint != operational.thumbprint()
                    or snapshot.governance_id != gi
                    or snapshot.historical_state != "ACTIVE"
                    or not snapshot.events
                    or not isinstance(snapshot.events[0], IssuanceEvent)
                    or snapshot.events[0].operational_key is None
                    or snapshot.events[0].operational_key.thumbprint()
                    != JWK.from_dict(state["initial_key"]).thumbprint()
                ):
                    raise ManagedRegistrationError("rotation_binding", phase, state)
                if state["provider"] != reference:
                    if operational.thumbprint() == JWK.from_dict(state["initial_key"]).thumbprint():
                        raise ManagedRegistrationError("provider_rotation_required", phase, state)
                    state["provider"] = reference
                remaining_seconds()
                phase = "issuance_recovery"
                _recover_issuance(state, verifier._local_log_binding, entity)
                phase = "completion"
                state["complete"] = True
                state["phase"] = "complete"
                store.save(state)
                success = True
                return ManagedRegistrationResult(registration, manager, published, evidence)
            finally:
                verifier.close()
    except ManagedRegistrationError:
        raise
    except Exception as error:
        category = "invalid_state" if phase == "recovery" else "operation_failed"
        if isinstance(error, BudgetExhausted):
            category = "deadline_or_cancelled"
        if phase in {"key", "provider"} and isinstance(error, FileNotFoundError):
            category = "missing_key"
        if isinstance(error, VerificationError) and error.agent_state in {"REVOKED", "RETIRED"}:
            category = "terminal_identity"
        raise ManagedRegistrationError(
            category,
            phase,
            state,
            cause=error,
            resumable=bool(getattr(error, "transient", False))
            or (isinstance(error, OSError) and category != "missing_key"),
        ) from error
    finally:
        if manager is not None and not success:
            manager.close()


def _name(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 255:
        raise ArgumentError("name requires 1 to 255 Unicode code points")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ArgumentError("name must be valid Unicode") from None
    return value.strip()


def _organization_id(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(c.isspace() for c in value.strip()):
        raise ArgumentError("organization_id must be a nonempty account identifier")
    return value.strip()


def _digest(value: Any) -> str:
    from .c2sp_tlog.canonical import canonical_bytes

    return (
        base64.urlsafe_b64encode(hashlib.sha256(canonical_bytes(value)).digest())
        .rstrip(b"=")
        .decode()
    )


def _replay_keys(state: dict[str, Any]) -> tuple[str, str]:
    key = _digest(
        [
            "dnsid-managed-registration-v1",
            state["organization"],
            state["name"],
            JWK.from_dict(state["initial_key"]).thumbprint(),
        ]
    )
    return key, _digest(["dnsid-managed-issuance-v1", key])


def _extra_input(request: dict[str, Any]) -> dict[str, Any]:
    defaults = asdict(AgentRegistrationInput())
    return {
        key: value
        for key, value in request.items()
        if key not in {"name", "public_key_jwk"} and value != defaults[key]
    }


def _input_fingerprint(request: dict[str, Any]) -> str:
    return _digest(_extra_input(request))


def _creation_request(state: dict[str, Any]) -> AgentRegistrationInput:
    return AgentRegistrationInput(
        **(state["input"] or {}),
        name=state["name"],
        public_key_jwk=JWK.from_dict(state["initial_key"]) if state["initial_key"] else None,
    )


def _validate_endpoint(gi: str, host: str) -> None:
    if gi and host != gi and not host.endswith("." + gi):
        raise ArgumentError("entity_key_url must be within the expected governance domain")


def _discover_account(
    client: RegistryClient,
    organization: str,
    gi: str,
    interval: float,
) -> tuple[str, str]:
    raw = _retry(client.get_organization_onboarding, interval)
    discovered_org = _organization_id(raw.get("org_id", ""))
    discovered_gi = normalize_fqdn(raw.get("governance_domain", ""))
    proof, delegation = raw.get("gi"), raw.get("ek")
    if (
        not isinstance(proof, dict)
        or not isinstance(delegation, dict)
        or proof.get("state") != "verified"
        or proof.get("gate_authorized") is not True
        or normalize_fqdn(proof.get("domain", "")) != discovered_gi
        or delegation.get("status") != "verified"
    ):
        raise ManagedRegistrationError("account_not_verified", "account")
    if (organization and organization != discovered_org) or (gi and gi != discovered_gi):
        raise ManagedRegistrationError("account_binding", "account")
    return discovered_org, discovered_gi


def _known_creation(state: dict[str, Any]) -> bool:
    facts = state["creation_facts"] or {}
    return bool(facts.get("id") and facts.get("domain") and facts.get("publication_config"))


def _registration_with_facts(
    state: dict[str, Any],
    detail: AgentRegistration | None,
) -> AgentRegistration:
    facts = state["creation_facts"]
    if detail is None:
        raise ManagedRegistrationError("registration_missing", "identity_read", state)
    if (
        detail.id != facts["id"]
        or detail.domain != facts["domain"]
        or (
            detail.publication_config is not None
            and asdict(detail.publication_config) != facts["publication_config"]
        )
    ):
        raise ManagedRegistrationError("creation_binding", "identity_read", state)
    return replace(
        detail,
        publication_config=PublicationConfig(**facts["publication_config"]),
        oidc_issuer_url=facts.get("oidc_issuer_url", ""),
    )


def _check_detail(state: dict[str, Any], detail: AgentRegistration | None) -> None:
    if detail is None:
        raise ManagedRegistrationError("registration_missing", "identity_read", state)
    saved = _registration_from_dict(state["registration"])
    if (
        detail.id != saved.id
        or detail.domain != saved.domain
        or detail.registry_url != saved.registry_url
        or detail.publication_authority != saved.publication_authority
    ):
        raise ManagedRegistrationError("identity_binding", "identity_read", state)
    if detail.registry_status in {"REVOKED", "RETIRED"}:
        state["registry_status"] = detail.registry_status
        raise ManagedRegistrationError("terminal_identity", "identity_read", state)
    if detail.publication_config is not None:
        assert saved.publication_config is not None
        old, current = asdict(saved.publication_config), asdict(detail.publication_config)
        if state["complete"]:
            old.pop("ku_url")
            current.pop("ku_url")
        if old != current:
            raise ManagedRegistrationError("publication_binding", "identity_read", state)


def _terminal_history(
    state: dict[str, Any],
    client: RegistryClient,
    deps: IdentityManagerDependencies,
    interval: float,
) -> list[dict[str, Any]]:
    import datetime

    from .models import DomainLog, KeyRotationEvent

    registration = _registration_from_dict(state["registration"])
    detail = _retry(lambda: client.get_agent_detail(registration.domain), interval)
    if (
        detail is None
        or detail.id != registration.id
        or detail.domain != registration.domain
        or detail.registry_status not in {"REVOKED", "RETIRED"}
        or state["entity_key"] is None
        or deps.log_registry is None
    ):
        raise ManagedRegistrationError("replacement_requires_terminal", "replacement", state)
    binding = deps.log_registry.new_reader(state["registration"]["publication_config"]["log_ref"])
    _recover_issuance(state, binding, JWK.from_dict(state["entity_key"]))
    events = binding.rebuild_history(registration.domain)
    snapshot = DomainLog(registration.domain, list(events)).snapshot_at(
        datetime.datetime.now(datetime.UTC)
    )
    if snapshot.historical_state != detail.registry_status:
        raise ManagedRegistrationError("replacement_terminal_binding", "replacement", state)
    keys = [JWK.from_dict(state["initial_key"]).thumbprint()]
    keys += [event.new_thumbprint for event in events if isinstance(event, KeyRotationEvent)]
    previous = {key: value for key, value in state.items() if key != "history"}
    previous["registry_status"] = detail.registry_status
    previous["key_history"] = keys
    return [*state["history"], previous]


def _recover_issuance(state: dict[str, Any], binding: Any, entity: JWK) -> None:
    from .c2sp_tlog.lr import parse_c2sp_tlog_lr
    from .models import LogRef, SubmissionResult

    entry, ref = binding.recover_issuance(state["registration"]["domain"], entity)
    parsed = parse_c2sp_tlog_lr(str(ref))
    log_reference = state["registration"]["publication_config"]["log_ref"]
    if parsed.entry_index is None or str(ref) != f"{log_reference}@{parsed.entry_index}":
        raise ManagedRegistrationError("issuance_binding", "issuance_recovery", state)
    acceptance = {"entry_hash": hashlib.sha256(entry).hexdigest(), "log_ref": str(ref)}
    if state["acceptance"] is not None and state["acceptance"] != acceptance:
        raise ManagedRegistrationError("issuance_binding", "issuance_recovery", state)
    if state["issuance"] is not None:
        pending = ManagedIssuanceState.from_dict(state["issuance"])
        if pending.entry and pending.entry != entry:
            raise ManagedRegistrationError("issuance_binding", "issuance_recovery", state)
    recovered = ManagedIssuanceState(
        state["registration"]["domain"],
        state["governance_id"],
        log_reference,
        _replay_keys(state)[1],
        entity.thumbprint(),
        JWK.from_dict(state["initial_key"]).thumbprint(),
        entry=entry,
        submission=SubmissionResult(
            "accepted",
            acceptance["entry_hash"],
            parsed.entry_index,
            LogRef.parse(str(ref)),
        ),
    )
    validate_managed_issuance(recovered, entity, JWK.from_dict(state["initial_key"]))
    state["acceptance"] = acceptance
    state["issuance"] = None


def _request_dict(request: AgentRegistrationInput) -> dict[str, Any]:
    if not isinstance(request, AgentRegistrationInput):
        raise ArgumentError("input must be AgentRegistrationInput")
    data = {f.name: getattr(request, f.name) for f in fields(request)}
    strings = data.keys() - {"managed", "metadata", "public_key_jwk"}
    if (
        any(not isinstance(data[key], str) for key in strings)
        or type(request.managed) is not bool
        or not isinstance(request.metadata, dict)
        or (request.public_key_jwk is not None and not isinstance(request.public_key_jwk, JWK))
    ):
        raise ArgumentError("invalid registration input types")
    if request.tier == "live" or request.idempotency_key or request.metadata:
        raise ArgumentError("managed setup excludes Live, caller replay keys, and metadata")
    if request.domain and (request.root_domain or request.zone_id):
        raise ArgumentError("domain conflicts with root_domain/zone_id")
    if request.environment and request.environment not in {"production", "sandbox"}:
        raise ArgumentError("invalid registration environment")
    for name in ("domain", "root_domain", "governance_domain"):
        if data[name]:
            try:
                data[name] = normalize_fqdn(data[name], agent_fqdn=name == "domain")
            except ValidationError as error:
                raise ArgumentError("invalid registration selector") from error
    if request.capabilities_url:
        _parse_https_uri_host(request.capabilities_url, field_name="capabilities_url")
    data["public_key_jwk"] = (
        _public_jwk_dict(request.public_key_jwk) if request.public_key_jwk else None
    )
    return data


def _registration_from_dict(data: dict[str, Any]) -> AgentRegistration:
    return AgentRegistration(
        **{**data, "publication_config": PublicationConfig(**data["publication_config"])}
    )


def _retain_registration(state: dict[str, Any], registration: AgentRegistration) -> None:
    if not registration.id or registration.publication_config is None:
        state["creation_facts"] = state["creation_facts"] or {
            "id": registration.id,
            "domain": registration.domain,
            "oidc_issuer_url": registration.oidc_issuer_url,
        }
        raise ManagedRegistrationError("missing_creation_facts", "creation", state)
    data = {
        "id": registration.id,
        "domain": registration.domain,
        "publication_authority": registration.publication_authority,
        "registry_status": registration.registry_status,
        "registry_url": registration.registry_url,
        "publication_config": asdict(registration.publication_config),
        "oidc_issuer_url": registration.oidc_issuer_url,
        "raw": {"tier": registration.raw.get("tier", "")},
    }
    facts = state["creation_facts"] or {}
    for key in ("id", "domain", "oidc_issuer_url", "publication_config"):
        expected = facts.get(key)
        # Wire publication_config uses snake_case, as does durable storage.
        if expected is not None and expected != data[key]:
            raise ManagedRegistrationError("creation_binding", "creation", state)
    state["registration"] = data
    state["registry_status"] = registration.registry_status
    if registration.registry_url != state["registry"]:
        raise ManagedRegistrationError("registry_binding", "creation", state)
    request = asdict(_creation_request(state))
    if request["domain"] and request["domain"] != registration.domain:
        raise ManagedRegistrationError("creation_binding", "creation", state)
    if request["root_domain"] and not registration.domain.endswith("." + request["root_domain"]):
        raise ManagedRegistrationError("creation_binding", "creation", state)
    _validate_publication_config(registration.publication_config, registration.domain)
    state["input"] = None
    state["creation_facts"] = None


def _validate_saved_identity(
    loaded: LoadedConfig,
    state: dict[str, Any],
    current: PublicationConfig,
) -> None:
    if loaded.dnsid.identity is None or state["registration"] is None:
        return
    registration = _registration_from_dict(state["registration"])
    expected = IdentityConfig(domain=registration.domain, **asdict(current))
    for f in fields(expected):
        value = getattr(loaded.dnsid.identity, f.name)
        if value and f.name in {"domain", "governance_id"}:
            value = normalize_fqdn(value, agent_fqdn=f.name == "domain")
        if value and value != getattr(expected, f.name):
            raise ManagedRegistrationError("local_identity_binding", "recovery", state)


def _binding_digest(loaded: LoadedConfig, gi: str, endpoint: str) -> str:
    # Save a digest, not application acceptance policy or provider private material.
    data = asdict(replace(loaded, dnsid=replace(loaded.dnsid, identity=None)))
    data.pop("key_source")
    data["registration"] = {"governance_id": gi, "entity_key_url": endpoint}

    def encode(value: Any) -> Any:
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, frozenset | set):
            return sorted(value)
        import datetime

        if isinstance(value, datetime.timedelta):
            return value.total_seconds()
        raise TypeError("unsupported configuration binding")

    return hashlib.sha256(json.dumps(data, sort_keys=True, default=encode).encode()).hexdigest()


def _validate_state(state: dict[str, Any]) -> None:
    required = {
        "version",
        "history",
        "binding",
        "registry",
        "organization",
        "name",
        "governance_id",
        "input",
        "input_fingerprint",
        "provider",
        "key_locator",
        "key_creation_started",
        "initial_key",
        "creation_facts",
        "registration",
        "entity_key",
        "issuance",
        "acceptance",
        "registry_status",
        "phase",
        "complete",
    }
    if (
        set(state) != required
        or state["version"] != 3
        or type(state["key_creation_started"]) is not bool
        or type(state["complete"]) is not bool
    ):
        raise ValueError("invalid recovery schema")
    for key in (
        "binding",
        "registry",
        "organization",
        "name",
        "governance_id",
        "input_fingerprint",
        "provider",
        "key_locator",
        "phase",
    ):
        if not isinstance(state[key], str) or not state[key]:
            raise ValueError("missing recovery binding")
    if (
        _name(state["name"]) != state["name"]
        or _organization_id(state["organization"]) != state["organization"]
    ):
        raise ValueError("invalid account/name")
    if normalize_fqdn(state["governance_id"]) != state["governance_id"]:
        raise ValueError("invalid governance binding")
    if not isinstance(state["history"], list):
        raise ValueError("invalid replacement history")
    for item in state["history"]:
        previous = {key: value for key, value in item.items() if key != "key_history"}
        previous["history"] = []
        _validate_state(previous)
        if (item["registry"], item["organization"], item["name"]) != (
            state["registry"],
            state["organization"],
            state["name"],
        ) or item["registry_status"] not in {"REVOKED", "RETIRED"}:
            raise ValueError("conflicting replacement history")
        if not isinstance(item["key_history"], list) or not item["key_history"]:
            raise ValueError("missing historical keys")
    if state["initial_key"] is not None:
        initial = JWK.from_dict(state["initial_key"])
        _public_jwk_dict(initial)
        if any(initial.thumbprint() in item["key_history"] for item in state["history"]):
            raise ValueError("historical key reused")
    elif any(
        state[key] is not None for key in ("registration", "entity_key", "issuance", "acceptance")
    ):
        raise ValueError("missing original key")
    if state["registration"] is None:
        if not isinstance(state["input"], dict):
            raise ValueError("missing frozen creation input")
        request = _request_dict(_creation_request(state))
        if (
            _extra_input(request) != state["input"]
            or _input_fingerprint(request) != state["input_fingerprint"]
        ):
            raise ValueError("conflicting creation input")
    else:
        if state["input"] is not None or state["creation_facts"] is not None:
            raise ValueError("uncompacted creation state")
        registration = _registration_from_dict(state["registration"])
        assert registration.publication_config is not None
        _validate_publication_config(registration.publication_config, registration.domain)
        if not registration.id or registration.registry_url != state["registry"]:
            raise ValueError("conflicting immutable registration")
    if state["entity_key"] is not None:
        if state["registration"] is None:
            raise ValueError("entity key without retained registration")
        from .models import JWKS

        entity = JWK.from_dict(state["entity_key"])
        _public_jwk_dict(entity)
        JWKS([entity]).validate_record_signing()
    if state["issuance"] is not None:
        _validate_issuance(state)
    if state["acceptance"] is not None:
        acceptance = state["acceptance"]
        if state["issuance"] is not None or set(acceptance) != {"entry_hash", "log_ref"}:
            raise ValueError("invalid compact acceptance")
        if len(acceptance["entry_hash"]) != 64:
            raise ValueError("invalid accepted entry hash")
        bytes.fromhex(acceptance["entry_hash"])
        from .c2sp_tlog.lr import parse_c2sp_tlog_lr

        ref = parse_c2sp_tlog_lr(acceptance["log_ref"])
        publication = state["registration"]["publication_config"]
        if (
            ref.entry_index is None
            or acceptance["log_ref"] != f"{publication['log_ref']}@{ref.entry_index}"
        ):
            raise ValueError("conflicting accepted entry reference")
    if state["complete"] and state["acceptance"] is None:
        raise ValueError("completion without verified acceptance")


def _validate_issuance(state: dict[str, Any]) -> None:
    registration = _registration_from_dict(state["registration"])
    issuance = ManagedIssuanceState.from_dict(state["issuance"])
    publication = registration.publication_config
    assert publication is not None
    if (
        issuance.domain,
        issuance.governance_id,
        issuance.log_reference,
        issuance.idempotency_key,
    ) != (
        registration.domain,
        publication.governance_id,
        publication.log_ref,
        _replay_keys(state)[1],
    ):
        raise ValueError("conflicting issuance operation")
    validate_managed_issuance(
        issuance, JWK.from_dict(state["entity_key"]), JWK.from_dict(state["initial_key"])
    )


def _pause(interval: float) -> None:
    end = time.monotonic() + remaining_seconds(interval)
    while time.monotonic() < end:
        time.sleep(max(0, min(remaining_seconds(0.05), end - time.monotonic())))
    remaining_seconds()


def _retry(operation: Any, interval: float, *, publication: bool = False) -> Any:
    while True:
        remaining_seconds()
        try:
            return operation()
        except VerificationError as error:
            # Only absent TXT is an additional convergence condition; invalid signatures,
            # policy denial, and resource limits never become propagation retries.
            absent = publication and error.resource_absent
            if not error.transient and not absent:
                raise
            _pause(interval)
