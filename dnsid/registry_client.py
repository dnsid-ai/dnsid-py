"""RegistryClient — operator-side client for DNSid registry workflows."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

from .enums import RegistryRevocationReason
from .interfaces import AbstractRegistryClient
from .models import (
    JWK,
    AgentRegistration,
    AgentRegistrationInput,
    AgentStatus,
    CanonicalRecordContentResponse,
    KeyRotationPreparationRequest,
    LifecycleResult,
    LiveAgentRegistrationInput,
    LiveChallengeTranscript,
    LiveProofReissueRequest,
    LiveProofReissueResponse,
    LiveProofRequest,
    LiveProofResponse,
    LiveProvisioningResponse,
    PreparedRegistryEvent,
    PublicationConfig,
    PublishedRecord,
    RegistryAgentStatus,
    SubmissionResult,
)


def _is_ready_for_publication(status: str) -> bool:
    return status == "VERIFIED"


def _is_published_status(status: str) -> bool:
    return status in ("READY", "PUBLISHED", "ACTIVE", "READY_FOR_PUBLICATION")


def _is_failed_status(status: str) -> bool:
    return status in ("ERROR", "REJECTED", "CANCELLED")


def _is_terminal_status(status: str) -> bool:
    return status in ("RETIRED", "REVOKED", "REJECTED", "CANCELLED")


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class RegistryClient(AbstractRegistryClient):
    """Operator-side client for managing the local agent's own registration.

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

    Mutation calls require owner credentials (an organization session or API
    key), supplied as ``api_key`` and sent as an ``Authorization: Bearer``
    header. An agent bearer token is not sufficient. Legacy status reads are
    public, but Live status requires the same owner authentication because it
    may expose a proof challenge. A configured credential is sent on all reads.
    The credential is never included in ``repr()``/``str()``, exceptions, or logs.

    Restore/reactivation operations (un-retiring or un-revoking an agent) are
    deliberately not exposed: the registry treats RETIRED and REVOKED as
    terminal, so recovery is an operator/registry-console action, not an SDK
    call.  The signed ``_dnsid`` TXT record is authoritative in DNS, not in
    the registry API — read the effective published values (e.g. ku/su) by
    resolving and verifying the record with ``IdentityManager.verify_domain``.
    """

    def __init__(self, base_url: str | None = None, *, api_key: str | None = None) -> None:
        """Initialize the client with a registry base URL and optional credential.

        Args:
            base_url: HTTPS registry base URL, or HTTP loopback URL for the
                local registry; defaults to ``DEFAULT_REGISTRY_URL`` (the local
                registry from ``dnsid local up``). Hosted use requires an explicit
                URL; see :func:`dnsid.registry_client_from_environment`.
                A trailing slash is stripped.
            api_key: Owner session or organization API-key credential sent as
                an ``Authorization: Bearer`` header. Whitespace-only values are
                treated as absent; without one only legacy status reads are available.
                Constructors never read the environment themselves.

        Raises:
            ValueError: If *base_url* is not a safe HTTPS or loopback HTTP URL,
                or *api_key* contains control characters that could corrupt the
                Authorization header.
        """
        from .models import DEFAULT_REGISTRY_URL

        resolved = base_url if base_url else DEFAULT_REGISTRY_URL
        try:
            parsed = urlsplit(resolved)
            # Accessing port also rejects malformed port syntax.
            parsed.port
        except ValueError as exc:
            raise ValueError("base_url must be an HTTPS URL") from exc
        is_loopback = parsed.hostname in _LOOPBACK_HOSTS
        if not parsed.hostname or (
            parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback)
        ):
            raise ValueError("base_url must be HTTPS (or HTTP on loopback)")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not include userinfo")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not include query or fragment")
        self._base_url = resolved.rstrip("/")
        self._is_loopback = is_loopback
        # ponytail: one Bearer credential covers owner API keys and session tokens;
        # add other schemes only if the registry ever needs them.
        # Strip so whitespace-only keys fail the missing-auth check locally
        # instead of sending "Authorization: Bearer    " on a live request.
        stripped = (api_key or "").strip() or None
        # Reject control characters (CR/LF/NUL/other C0 + DEL) before they reach
        # HTTPX: it raises LocalProtocolError echoing the illegal header value,
        # which _post() would wrap into VerificationError and leak the credential.
        if stripped is not None and any(c < "\x20" or c == "\x7f" for c in stripped):
            raise ValueError("api_key contains illegal control characters")
        self._api_key = stripped

    def __repr__(self) -> str:
        """Return a repr that reports whether a credential is set, never its value."""
        # Never leak the credential; only report whether one is set.
        return (
            f"RegistryClient(base_url={self._base_url!r}, "
            f"authenticated={self._api_key is not None})"
        )

    __str__ = __repr__

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

    def _sanitize(self, text: str) -> str:
        # Defense in depth: HTTPX transport exceptions (e.g. LocalProtocolError,
        # SSL/proxy errors) can echo the illegal header value or request metadata
        # carrying the Bearer credential. Strip it before the text reaches a
        # VerificationError surfaced to callers or logs.
        if self._api_key and self._api_key in text:
            return text.replace(self._api_key, "***")
        return text

    def _transport_detail(self, exc: Exception) -> str:
        """Describe a transport failure without the credential, with a local hint.

        A refused connection to the loopback default almost always means the
        local registry is not running, so say so instead of echoing the socket error.
        """
        import httpx

        if isinstance(exc, httpx.ConnectError) and self._is_loopback:
            host = urlsplit(self._base_url).netloc
            return f"no registry at {host}; run `dnsid local up` or set DNSID_REGISTRY_URL"
        return self._sanitize(str(exc))

    def _require_auth(self, operation: str) -> None:
        # The local registry (``dnsid local up``) ignores Authorization, so a
        # loopback client needs no credential; the hosted registry does.
        if not self._api_key and not self._is_loopback:
            from .exceptions import ArgumentError

            raise ArgumentError(
                f"{operation} requires registry credentials; construct RegistryClient(api_key=...)"
            )

    # ------------------------------------------------------------------
    # Registration lifecycle
    # ------------------------------------------------------------------

    def register_agent(self, input: AgentRegistrationInput) -> AgentRegistration:
        """Register an agent with the registry.

        ``POST /api/v1/agent``

        Pass ``domain`` to register a name you control (self-managed), or
        ``zone_id`` to have the registry assign a name in a delegated zone
        (registry-managed). The two are mutually exclusive, and
        ``managed=True`` requires ``zone_id``. ``environment`` defaults to
        ``"production"``; ``"sandbox"`` is also accepted. For Live names use
        :meth:`register_live_agent`.
        """
        self._require_auth("register_agent")
        from .exceptions import ArgumentError

        environment = input.environment or "production"
        if environment not in {"production", "sandbox"}:
            raise ArgumentError('environment must be "production" or "sandbox"')
        if input.zone_id and input.domain:
            raise ArgumentError("zone_id and domain cannot both be supplied")
        if input.managed and not input.zone_id:
            raise ArgumentError("managed registration requires zone_id")
        effective_managed = input.managed or bool(input.zone_id)
        if effective_managed and input.domain:
            raise ArgumentError(
                "domain must not be supplied for managed registrations; the registry assigns it"
            )
        if not effective_managed and not input.domain:
            raise ArgumentError("self-managed registration requires a domain")
        if input.managed and input.public_key_jwk is None:
            raise ArgumentError("managed registration requires public_key_jwk")
        if input.idempotency_key:
            _validate_tlog_idempotency_key(input.idempotency_key)

        body: dict[str, Any] = {}
        if input.domain:
            body["domain"] = input.domain
        if input.public_key_jwk:
            body["public_key"] = _public_jwk_dict(input.public_key_jwk)
        body["environment"] = environment
        if input.managed:
            body["managed"] = input.managed
        if input.capabilities_url:
            body["capabilities_url"] = input.capabilities_url
        if input.name:
            body["name"] = input.name
        if input.zone_id:
            body["zone_id"] = input.zone_id

        headers = (
            {"Idempotency-Key": input.idempotency_key}
            if input.idempotency_key
            else None
        )
        data = self._post(
            "/api/v1/agent", body, extra_headers=headers, expected_status=201
        )
        domain = _require_str(data, "domain", "registry register response")
        publication_config = _publication_config_from_response(data)
        registration = self.get_registration(domain)
        if registration is None:
            from .exceptions import ValidationError

            raise ValidationError("registry created the agent but returned no registration")
        if publication_config is not None:
            registration = replace(registration, publication_config=publication_config)
        oidc_issuer_url = data.get("oidc_issuer_url")
        if oidc_issuer_url is not None:
            if not isinstance(oidc_issuer_url, str):
                from .exceptions import ValidationError

                raise ValidationError("registry register response has invalid oidc_issuer_url")
            registration = replace(registration, oidc_issuer_url=oidc_issuer_url)
        # The create response is the authoritative source of the agent ID;
        # keep it even when the status view omits it.
        created_id = data.get("id")
        if isinstance(created_id, str) and created_id:
            if registration.id and registration.id != created_id:
                from .exceptions import ValidationError

                raise ValidationError(
                    "registry status names a different agent than the one just created"
                )
            registration = replace(registration, id=created_id)
        return registration

    def register_live_agent(
        self, input: LiveAgentRegistrationInput, idempotency_key: str
    ) -> LiveProvisioningResponse:
        """Start managed Live registration and return its validated proof challenge.

        ``POST /api/v1/agent`` sends fixed ``tier="live"`` and ``managed=true``
        discriminators. Sign the exact base64url-decoded ``challenge_message``
        bytes; use the derived :attr:`LiveProvisioningResponse.domain` for the
        proof route.
        """
        self._require_auth("register_live_agent")
        from .exceptions import ArgumentError

        if input.environment not in {"", "production"}:
            raise ArgumentError('live registration environment must be "production" or omitted')
        _validate_tlog_idempotency_key(idempotency_key)
        public_key = _live_public_jwk_dict(input.public_key_jwk)
        body: dict[str, Any] = {
            "public_key": public_key,
            "environment": "production",
            "tier": "live",
            "managed": True,
        }
        if input.capabilities_url:
            body["capabilities_url"] = input.capabilities_url
        if input.name:
            body["name"] = input.name
        data = self._post(
            "/api/v1/agent",
            body,
            extra_headers={"Idempotency-Key": idempotency_key},
            expected_status=202,
        )
        return _live_provisioning_from_response(data, input.public_key_jwk)

    def verify_agent(self, domain: str) -> AgentRegistration:
        """Request registry verification for a registered self-managed agent.

        ``POST /api/v1/agent/{domain}/verify``
        """
        self._require_auth("verify_agent")
        from urllib.parse import quote

        data = self._post(f"/api/v1/agent/{quote(domain, safe='')}/verify")
        # fqdn is optional in the verify response; fall back to the requested
        # domain when the registry omits it.
        raw_fqdn = data.get("fqdn")
        fqdn = raw_fqdn if isinstance(raw_fqdn, str) and raw_fqdn else domain
        registration = self.get_registration(fqdn)
        if registration is None:
            from .exceptions import ValidationError

            raise ValidationError("registry accepted verification but returned no registration")
        return registration

    def revoke_agent(
        self,
        domain: str,
        agent_id: str,
        reason: RegistryRevocationReason,
    ) -> LifecycleResult:
        """Revoke an agent through the registry-owned terminal lifecycle flow.

        ``POST /api/v1/agent/{domain}/revoke``

        The registry owns persistence and the transparency-log append; this
        convenience method does not prepare or append a second local event.

        Args:
            domain: Agent FQDN to revoke.
            agent_id: Immutable registry agent ID for safe retries after domain
                re-registration.
            reason: Typed owner-authorized registry revocation reason.

        Returns:
            The registry lifecycle transition result.

        Raises:
            ArgumentError: If *reason* is not a ``RegistryRevocationReason``.
        """
        self._require_auth("revoke_agent")
        from urllib.parse import quote

        from .exceptions import ArgumentError

        if not isinstance(reason, RegistryRevocationReason):
            raise ArgumentError("revocation reason must be a RegistryRevocationReason")
        data = self._post(
            f"/api/v1/agent/{quote(domain, safe='')}/revoke",
            {"agent_id": agent_id, "reason": reason.value},
        )
        return _lifecycle_result_from_response(data)

    def retire_agent(self, domain: str, agent_id: str) -> LifecycleResult:
        """Retire an agent while retaining its key for historical verification.

        ``POST /api/v1/agent/{domain}/retire`` with the immutable *agent_id*.
        """
        self._require_auth("retire_agent")
        from urllib.parse import quote

        data = self._post(
            f"/api/v1/agent/{quote(domain, safe='')}/retire",
            {"agent_id": agent_id},
        )
        return _lifecycle_result_from_response(data)

    def cancel_agent(self, domain: str) -> LifecycleResult:
        """Cancel an agent that is still inside the registration workflow.

        ``POST /api/v1/agent/{domain}/cancel``. A PENDING agent cannot be
        revoked (the registry answers 409 ``INVALID_TRANSITION``); cancelling
        is the transition that removes it. Mirrors ``cancelAgent`` in the
        TypeScript SDK and ``CancelAgent`` in Go.
        """
        self._require_auth("cancel_agent")
        from urllib.parse import quote

        data = self._post(f"/api/v1/agent/{quote(domain, safe='')}/cancel")
        return _lifecycle_result_from_response(data)

    def submit_challenge_signature(
        self, domain: str, nonce: str, signature: bytes | str
    ) -> LifecycleResult:
        """Submit the signed verification challenge to prove key possession.

        ``POST /api/v1/agent/{domain}/challenge``

        During the ``VERIFICATION`` lifecycle state the registry exposes a
        challenge nonce on the status document (``raw["challenge"]``).  The
        agent signs the base64url-decoded nonce bytes with its active signing
        key and submits the signature here.  The registry accepts the
        challenge and completes verification asynchronously; use
        :meth:`wait_for_status` with ``target_state="VERIFIED"`` afterwards.
        The nonce is single-use — a fresh one must be fetched before retrying.

        Args:
            domain: Agent FQDN.
            nonce: Challenge nonce exactly as returned by the status endpoint.
            signature: Raw signature bytes (base64url-encoded automatically),
                or an already base64url-encoded signature string.
        """
        self._require_auth("submit_challenge_signature")
        from urllib.parse import quote

        import httpx

        from ._utils import b64url_encode

        sig_text = signature if isinstance(signature, str) else b64url_encode(signature)
        url = f"{self._base_url}/api/v1/agent/{quote(domain, safe='')}/challenge"
        _transport_err: Exception | None = None
        try:
            resp = httpx.post(
                url,
                json={"nonce": nonce, "signature": sig_text},
                headers=self._auth_headers(),
                timeout=10.0,
            )
        except httpx.TransportError as exc:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            _transport_err = VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry challenge request failed for {domain!r}: {self._transport_detail(exc)}",
                transient=True,
            )
        if _transport_err is not None:
            raise _transport_err from None
        if not resp.is_success:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry challenge returned HTTP {resp.status_code} for {domain!r}",
                transient=resp.status_code >= 500,
            )

        # The registry may reply 202 with an empty body; a JSON body with
        # id/status is optional and parsed when present.
        try:
            data = resp.json()
        except Exception:
            data = None
        if not isinstance(data, dict):
            data = {}
        raw_status = data.get("status")
        state = ""
        if isinstance(raw_status, str) and raw_status:
            state = str(raw_status).upper()
        return LifecycleResult(
            id=str(data.get("id") or ""),
            state=state,
            status_note=str(data.get("status_note") or ""),
            raw=data,
        )

    def submit_live_proof(
        self, domain: str, request: LiveProofRequest
    ) -> LiveProofResponse:
        """Submit signed proof for managed Live provisioning.

        ``POST /api/v1/agent/{domain}/proof`` requires owner/session/API-key
        credentials, not an agent bearer token. ``request.request_id`` is sent
        as the required ``Idempotency-Key`` header.
        """
        self._require_auth("submit_live_proof")
        _validate_tlog_idempotency_key(request.request_id)
        from urllib.parse import quote

        data = self._post(
            f"/api/v1/agent/{quote(domain, safe='')}/proof",
            {
                "request_id": request.request_id,
                "challenge": request.challenge,
                "public_key": _live_public_jwk_dict(request.public_key_jwk),
                "signature": request.signature,
            },
            extra_headers={"Idempotency-Key": request.request_id},
            expected_status=202,
        )
        return LiveProofResponse(
            request_id=_require_str(data, "request_id", "registry Live proof response"),
            agent_id=_require_str(data, "agent_id", "registry Live proof response"),
            status=_require_str(data, "status", "registry Live proof response"),
            raw=data,
        )

    def reissue_live_proof(
        self, domain: str, request: LiveProofReissueRequest
    ) -> LiveProofReissueResponse:
        """Request a replacement challenge for an expired managed Live proof.

        ``POST /api/v1/agent/{domain}/proof/reissue`` requires owner/session/API-key
        credentials, not an agent bearer token. ``request.request_id`` is sent
        as the required ``Idempotency-Key`` header. The original public key is
        validated locally and binds the replacement transcript, but is not sent.
        The replacement challenge supersedes every earlier challenge; only the
        latest message may be signed.
        """
        self._require_auth("reissue_live_proof")
        _validate_tlog_idempotency_key(request.request_id)
        _live_public_jwk_dict(request.public_key_jwk)
        expected_key_id = request.public_key_jwk.thumbprint()
        from urllib.parse import quote

        data = self._post(
            f"/api/v1/agent/{quote(domain, safe='')}/proof/reissue",
            {"request_id": request.request_id},
            extra_headers={"Idempotency-Key": request.request_id},
            expected_status=202,
        )
        return _live_proof_reissue_from_response(data, domain, expected_key_id)

    def get_status(self, domain: str) -> str | None:
        """Fetch the raw lifecycle status string from the registry.

        ``GET /api/v1/agent/{domain}/status``

        Returns the uppercased status string (e.g. ``"ACTIVE"``, ``"VERIFIED"``),
        or ``None`` if the agent is not registered (HTTP 404). Live status
        requires owner/session/API-key authentication; legacy status is public.
        """
        from urllib.parse import quote

        import httpx

        url = f"{self._base_url}/api/v1/agent/{quote(domain, safe='')}/status"
        _transport_err: Exception | None = None
        try:
            resp = httpx.get(url, headers=self._auth_headers(), timeout=10.0)
        except httpx.TransportError as exc:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            _transport_err = VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry status request failed for {domain!r}: {self._transport_detail(exc)}",
                transient=True,
            )
        if _transport_err is not None:
            raise _transport_err from None
        if resp.status_code == 404:
            return None
        if not resp.is_success:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry status returned HTTP {resp.status_code} for {domain!r}",
                transient=resp.status_code >= 500,
            )

        data = _parse_json(resp, f"registry status response for {domain!r}")
        raw = data.get("status") or data.get("state")
        return str(raw).upper() if raw is not None else None

    def get_agent_status(self, domain: str) -> RegistryAgentStatus | None:
        """Fetch registry lifecycle state.

        ``GET /api/v1/agent/{domain}/status``

        Returns ``None`` if the agent is not registered (HTTP 404). Live status
        requires owner/session/API-key authentication; legacy status is public.
        Returns a :class:`RegistryAgentStatus` with computed boolean flags that
        mirror the TypeScript ``RegistryAgentStatus`` interface.
        """
        from urllib.parse import quote

        import httpx

        url = f"{self._base_url}/api/v1/agent/{quote(domain, safe='')}/status"
        _transport_err: Exception | None = None
        try:
            resp = httpx.get(url, headers=self._auth_headers(), timeout=10.0)
        except httpx.TransportError as exc:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            _transport_err = VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry status request failed for {domain!r}: {self._transport_detail(exc)}",
                transient=True,
            )
        if _transport_err is not None:
            raise _transport_err from None
        if resp.status_code == 404:
            return None
        if not resp.is_success:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry status returned HTTP {resp.status_code} for {domain!r}",
                transient=resp.status_code >= 500,
            )

        data = _parse_json(resp, f"registry status response for {domain!r}")
        raw_status = str(data.get("status") or data.get("state") or "").upper()
        raw_dns_published = data.get("dns_published", data.get("dnsPublished"))
        dns_published = raw_dns_published if isinstance(raw_dns_published, bool) else None
        protocol_status = _protocol_status_from_response(data)
        return RegistryAgentStatus(
            registry_status=raw_status,
            dns_published=dns_published,
            protocol_status=protocol_status,
            ready_for_publication=_is_ready_for_publication(raw_status)
            or (raw_status == "READY" and dns_published is False),
            published=dns_published is True,
            failed=_is_failed_status(raw_status),
            terminal=_is_terminal_status(raw_status),
            publication_config=_publication_config_from_response(data),
            raw=data,
        )

    def get_registration(self, domain: str) -> AgentRegistration | None:
        """Return the current registry registration without conflating status namespaces."""
        from urllib.parse import quote

        import httpx

        url = f"{self._base_url}/api/v1/agent/{quote(domain, safe='')}/status"
        try:
            resp = httpx.get(url, headers=self._auth_headers(), timeout=10.0)
        except httpx.TransportError as exc:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry registration request failed for {domain!r}: "
                f"{self._transport_detail(exc)}",
                transient=True,
            ) from None
        if resp.status_code == 404:
            return None
        if not resp.is_success:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry registration returned HTTP {resp.status_code} for {domain!r}",
                transient=resp.status_code >= 500,
            )
        data = _parse_json(resp, f"registry registration response for {domain!r}")
        return _registration_from_response(domain, self._base_url, data)

    def wait_for_status(
        self,
        domain: str,
        *,
        timeout: float = 120.0,
        interval: float = 5.0,
        target_state: str | None = None,
    ) -> RegistryAgentStatus:
        """Poll the registry until the agent reaches a settled or target state.

        Returns when the agent is published, failed, or terminal — or when
        *target_state* (a raw registry status string such as ``"VERIFIED"``) is
        reached.  Raises :exc:`VerificationError(LOG_ERROR)` on timeout or if a
        failed/terminal state is reached before *target_state*.

        Args:
            domain: Agent FQDN.
            timeout: Maximum seconds to wait before raising.
            interval: Seconds between status polls.
            target_state: Raw registry status string to wait for specifically.
        """
        import time

        from .enums import VerificationCode
        from .exceptions import VerificationError

        deadline = time.monotonic() + timeout
        while True:
            status = self.get_agent_status(domain)
            if status is None:
                raise VerificationError(
                    VerificationCode.LOG_ERROR,
                    f"Agent {domain!r} not found in registry",
                )
            if target_state and status.registry_status == target_state:
                return status
            if status.published or status.failed or status.terminal:
                if target_state and not status.published:
                    raise VerificationError(
                        VerificationCode.LOG_ERROR,
                        f"Agent {domain!r} reached state {status.registry_status!r} "
                        f"before target {target_state!r}",
                    )
                return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerificationError(
                    VerificationCode.LOG_ERROR,
                    f"Timed out waiting for {domain!r} "
                    + (f"to reach {target_state!r} " if target_state else "")
                    + f"(current: {status.registry_status!r})",
                    transient=True,
                )
            time.sleep(min(interval, remaining))

    async def async_wait_for_status(
        self,
        domain: str,
        *,
        timeout: float = 120.0,
        interval: float = 5.0,
        target_state: str | None = None,
    ) -> RegistryAgentStatus:
        """Async variant of :meth:`wait_for_status`.

        Sleeps with ``asyncio.sleep`` between polls so the event loop is not
        blocked.  The status fetch itself is synchronous (httpx).
        """
        import asyncio
        import time

        from .enums import VerificationCode
        from .exceptions import VerificationError

        deadline = time.monotonic() + timeout
        while True:
            status = self.get_agent_status(domain)
            if status is None:
                raise VerificationError(
                    VerificationCode.LOG_ERROR,
                    f"Agent {domain!r} not found in registry",
                )
            if target_state and status.registry_status == target_state:
                return status
            if status.published or status.failed or status.terminal:
                if target_state and not status.published:
                    raise VerificationError(
                        VerificationCode.LOG_ERROR,
                        f"Agent {domain!r} reached state {status.registry_status!r} "
                        f"before target {target_state!r}",
                    )
                return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerificationError(
                    VerificationCode.LOG_ERROR,
                    f"Timed out waiting for {domain!r} "
                    + (f"to reach {target_state!r} " if target_state else "")
                    + f"(current: {status.registry_status!r})",
                    transient=True,
                )
            await asyncio.sleep(min(interval, remaining))

    def unregister_agent(self, domain: str) -> None:
        """Best-effort unregister. Silently ignores 404 and 405.

        ``DELETE /api/v1/agent/{domain}``
        """
        self._require_auth("unregister_agent")
        from urllib.parse import quote

        import httpx

        url = f"{self._base_url}/api/v1/agent/{quote(domain, safe='')}"
        _transport_err: Exception | None = None
        try:
            resp = httpx.request("DELETE", url, headers=self._auth_headers(), timeout=10.0)
        except httpx.TransportError as exc:
            from .enums import VerificationCode
            from .exceptions import VerificationError

            _transport_err = VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry unregister request failed for {domain!r}: {self._transport_detail(exc)}",
                transient=True,
            )
        if _transport_err is not None:
            raise _transport_err from None
        if not resp.is_success and resp.status_code not in (404, 405):
            from .enums import VerificationCode
            from .exceptions import VerificationError

            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry unregister returned HTTP {resp.status_code} for {domain!r}",
                transient=resp.status_code >= 500,
            )

    # ------------------------------------------------------------------
    # Publication
    # ------------------------------------------------------------------

    def canonical_record_content(
        self, domain: str, signing_kid: str
    ) -> CanonicalRecordContentResponse:
        """Fetch the registry's canonical TXT record content for signing.

        ``POST /api/v1/agent/{domain}/record``

        Returns a :class:`CanonicalRecordContentResponse` with the canonical
        byte string and the registry's view of the active signing key ID.
        The SDK MUST validate both before signing; this response is not trusted input.
        """
        self._require_auth("canonical_record_content")
        from urllib.parse import quote

        fqdn_enc = quote(domain, safe="")
        data = self._post(f"/api/v1/agent/{fqdn_enc}/record", {"signingKid": signing_kid})
        canonical = _require_str(data, "canonicalContent", "registry record response")
        registry_kid = _require_str(data, "signingKid", "registry record response")
        return CanonicalRecordContentResponse(canonical=canonical, signing_kid=registry_kid)

    def publish_signature(self, domain: str, sig: str) -> PublishedRecord:
        """Submit the record signature to complete the publish workflow.

        ``POST /api/v1/agent/{domain}/signature``

        *sig* MUST be the profile-owned sg value.  For draft 01 this is the bare
        unpadded base64url signature bytes.
        """
        self._require_auth("publish_signature")
        from urllib.parse import quote

        fqdn_enc = quote(domain, safe="")
        data = self._post(f"/api/v1/agent/{fqdn_enc}/signature", {"signature": sig})
        return _published_record_from_response(domain, data)

    # ------------------------------------------------------------------
    # Managed key rotation (c2sp-tlog submission adapter)
    # ------------------------------------------------------------------

    def prepare_issuance(self, domain: str, idempotency_key: str) -> PreparedRegistryEvent:
        """Fetch exact raw ISSUANCE bytes for operational countersigning.

        ``POST /api/v1/agent/{domain}/tlog/issuance/prepare`` has no request
        body. Both the response bytes and ``DNSID-Log-Reference`` header are
        untrusted and must be validated by the C2SP prepared-event binding.
        """
        self._require_auth("prepare_issuance")
        _validate_tlog_idempotency_key(idempotency_key)

        from urllib.parse import quote

        import httpx

        from .enums import VerificationCode
        from .exceptions import VerificationError

        path = f"/api/v1/agent/{quote(domain, safe='')}/tlog/issuance/prepare"
        try:
            response = httpx.post(
                f"{self._base_url}{path}",
                headers={
                    **self._auth_headers(),
                    "Content-Type": "application/json",
                    "Idempotency-Key": idempotency_key,
                },
                timeout=10.0,
            )
        except httpx.TransportError as exc:
            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry request to {path!r} failed: {self._transport_detail(exc)}",
                transient=True,
            ) from None
        if not response.is_success:
            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry request to {path!r} returned HTTP {response.status_code}",
                transient=response.status_code >= 500,
            )
        log_reference = response.headers.get("DNSID-Log-Reference", "")
        if not log_reference:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "registry prepared event is missing DNSID-Log-Reference",
            )
        return PreparedRegistryEvent(
            entry_bytes=bytes(response.content),
            log_reference=log_reference,
        )

    def prepare_key_rotation(
        self,
        domain: str,
        request: KeyRotationPreparationRequest,
        idempotency_key: str,
    ) -> PreparedRegistryEvent:
        """Request a registry-prepared KEY_ROTATION envelope.

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
        """
        self._require_auth("prepare_key_rotation")
        from urllib.parse import quote

        from .exceptions import ArgumentError
        from .models import _PRIVATE_JWK_MEMBERS

        _validate_tlog_idempotency_key(idempotency_key)
        raw_jwk = dict(request.public_key._raw)
        private_members = _PRIVATE_JWK_MEMBERS & raw_jwk.keys()
        if private_members:
            raise ArgumentError(
                f"public_key contains private JWK members: {sorted(private_members)}"
            )
        if not raw_jwk.get("kid") or not raw_jwk.get("alg"):
            raise ArgumentError("public_key must include kid and alg")

        import httpx

        from .enums import VerificationCode
        from .exceptions import VerificationError

        path = f"/api/v1/agent/{quote(domain, safe='')}/tlog/key-rotation/prepare"
        try:
            response = httpx.post(
                f"{self._base_url}{path}",
                json={
                    "previous_key_id": request.previous_key_id,
                    "public_key": raw_jwk,
                },
                headers={
                    **self._auth_headers(),
                    "Idempotency-Key": idempotency_key,
                },
                timeout=10.0,
            )
        except httpx.TransportError as exc:
            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry request to {path!r} failed: {self._transport_detail(exc)}",
                transient=True,
            ) from None
        if not response.is_success:
            raise VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry request to {path!r} returned HTTP {response.status_code}",
                transient=response.status_code >= 500,
            )
        log_reference = response.headers.get("DNSID-Log-Reference", "")
        if not log_reference:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "registry prepared event is missing DNSID-Log-Reference",
            )
        return PreparedRegistryEvent(
            entry_bytes=bytes(response.content),
            log_reference=log_reference,
        )

    def submit_prepared_event(
        self,
        domain: str,
        entry_bytes: bytes,
        idempotency_key: str,
    ) -> SubmissionResult:
        """Submit exact complete canonical entry bytes for append.

        ``POST /api/v1/agent/{domain}/tlog/events``

        The bytes are sent unchanged as the application/json request body;
        a timeout or indeterminate result is retried with the same bytes and
        the same idempotency key.  The registry's durable idempotency mapping
        returns the original pending/accepted result for the same
        (identity, key, byte-hash) triple and rejects key reuse with
        different bytes.
        """
        self._require_auth("submit_prepared_event")
        from urllib.parse import quote

        from .exceptions import ArgumentError

        _validate_tlog_idempotency_key(idempotency_key)
        if not entry_bytes:
            raise ArgumentError("submit_prepared_event requires non-empty entry bytes")

        import httpx

        from .enums import VerificationCode
        from .exceptions import VerificationError

        fqdn_enc = quote(domain, safe="")
        path = f"/api/v1/agent/{fqdn_enc}/tlog/events"
        try:
            response = httpx.post(
                f"{self._base_url}{path}",
                content=entry_bytes,
                headers={
                    **self._auth_headers(),
                    "Content-Type": "application/json",
                    "Idempotency-Key": idempotency_key,
                },
                timeout=10.0,
            )
        except httpx.TransportError:
            # The registry may have accepted the bytes before the connection
            # failed. Preserve an indeterminate result so callers retain and
            # retry this exact entry with this exact idempotency key.
            return SubmissionResult(
                state="pending",
                error_code="TLOG_SUBMISSION_TRANSPORT_ERROR",
            )

        try:
            data = response.json()
        except Exception:
            data = None
        if not isinstance(data, dict):
            return SubmissionResult(
                state=(
                    "pending" if response.is_success or response.status_code >= 500 else "rejected"
                ),
                error_code=f"TLOG_SUBMISSION_HTTP_{response.status_code}",
            )

        if response.is_success:
            try:
                result = _submission_result_from_response(data)
            except VerificationError:
                return SubmissionResult(
                    state="pending",
                    error_code="TLOG_SUBMISSION_INVALID_RESPONSE",
                    raw=data,
                )
        else:
            error_code = str(data.get("error") or "")
            if error_code in {
                "TLOG_SUBMISSION_BUSY",
                "TLOG_SUBMISSION_INDETERMINATE",
            }:
                result = SubmissionResult(state="pending", error_code=error_code, raw=data)
            elif response.status_code in (400, 404, 409, 422):
                result = SubmissionResult(state="rejected", error_code=error_code, raw=data)
            else:
                result = SubmissionResult(
                    state=("pending" if response.status_code >= 500 else "rejected"),
                    error_code=error_code or f"TLOG_SUBMISSION_HTTP_{response.status_code}",
                    raw=data,
                )

        if result.accepted:
            import hashlib

            expected_hash = hashlib.sha256(entry_bytes).hexdigest()
            if not result.entry_hash or result.entry_hash != expected_hash:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "registry accepted a different prepared-event byte sequence",
                )
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        expected_status: int | None = None,
    ) -> dict[str, Any]:
        import httpx

        from .enums import VerificationCode
        from .exceptions import VerificationError

        url = f"{self._base_url}{path}"
        headers = self._auth_headers()
        if extra_headers:
            headers = {**headers, **extra_headers}
        _transport_err: Exception | None = None
        try:
            if body is not None:
                resp = httpx.post(url, json=body, headers=headers, timeout=10.0)
            else:
                resp = httpx.post(url, headers=headers, timeout=10.0)
        except httpx.TransportError as exc:
            _transport_err = VerificationError(
                VerificationCode.LOG_ERROR,
                f"Registry request to {path!r} failed: {self._transport_detail(exc)}",
                transient=True,
            )
        if _transport_err is not None:
            raise _transport_err from None
        if not resp.is_success:
            # ponytail: authenticated path sends Authorization: Bearer, and an
            # error body may echo request metadata back — never surface resp.text.
            # The registry's short error code is the one safe, useful token.
            from .exceptions import RegistryRequestError

            raise RegistryRequestError(path, resp.status_code, _registry_error_code(resp))
        if expected_status is not None and resp.status_code != expected_status:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"Registry request to {path!r} expected HTTP {expected_status}, "
                f"received {resp.status_code}",
            )
        return _parse_json(resp, f"registry response for {path!r}")


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


_ERROR_CODE_RE = re.compile(r"^[A-Z0-9_]{1,64}$")


def _registry_error_code(resp: Any) -> str:
    """Return the registry's ``error`` code from an error body, or ``""``.

    Only a bare upper-case token is accepted, so free text can never leak
    through this path.
    """
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001 — any non-JSON body means no code
        return ""
    code = data.get("error") if isinstance(data, dict) else None
    return code if isinstance(code, str) and _ERROR_CODE_RE.fullmatch(code) else ""


def _parse_json(resp: object, label: str) -> dict[str, Any]:
    _parse_err: Exception | None = None
    try:
        data = resp.json()  # type: ignore[attr-defined]
    except Exception:
        from .enums import VerificationCode
        from .exceptions import VerificationError

        _parse_err = VerificationError(
            VerificationCode.LOG_ERROR,
            f"{label}: non-JSON response",
        )
    if _parse_err is not None:
        raise _parse_err from None
    if not isinstance(data, dict):
        from .enums import VerificationCode
        from .exceptions import VerificationError

        raise VerificationError(
            VerificationCode.LOG_ERROR,
            f"{label}: expected JSON object",
        )
    return data


def _require_string(data: dict[str, Any], field: str, label: str) -> str:
    value = data.get(field)
    if not isinstance(value, str):
        from .enums import VerificationCode
        from .exceptions import VerificationError

        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            f"{label}: {field!r} must be a string",
        )
    return value


def _require_str(data: dict[str, Any], field: str, label: str) -> str:
    value = _require_string(data, field, label)
    if not value:
        from .enums import VerificationCode
        from .exceptions import VerificationError

        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            f"{label}: {field!r} must be a non-empty string",
        )
    return value


def _validate_tlog_idempotency_key(key: str) -> None:
    """Enforce the product's exact tlog Idempotency-Key constraints."""
    from .exceptions import ArgumentError

    if not key or key != key.strip() or len(key.encode("utf-8")) > 200:
        raise ArgumentError("idempotency_key must be 1 to 200 bytes without surrounding whitespace")


def _public_jwk_dict(key: JWK) -> dict[str, Any]:
    from .exceptions import ArgumentError
    from .models import _PRIVATE_JWK_MEMBERS

    if not isinstance(key, JWK) or not isinstance(key._raw, dict):
        raise ArgumentError("public_key_jwk must be a JWK")
    private_members = set(key._raw) & _PRIVATE_JWK_MEMBERS
    nested = key._raw.get("keys")
    if isinstance(nested, list):
        for item in nested:
            if isinstance(item, dict):
                private_members.update(set(item) & _PRIVATE_JWK_MEMBERS)
    if private_members:
        raise ArgumentError(
            f"public_key_jwk contains private JWK members: {sorted(private_members)}"
        )
    return key.to_dict()


def _live_public_jwk_dict(key: JWK) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from ._crypto import compute_thumbprint
    from ._utils import b64url_decode_strict
    from .exceptions import ArgumentError

    raw = _public_jwk_dict(key)
    try:
        if (raw.get("kty"), raw.get("crv"), raw.get("alg")) != (
            "OKP",
            "Ed25519",
            "EdDSA",
        ):
            raise ValueError
        if raw.get("use", "") not in {"", "sig"}:
            raise ValueError
        x = raw.get("x")
        kid = raw.get("kid")
        if not isinstance(x, str) or not isinstance(kid, str) or not kid:
            raise ValueError
        ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode_strict(x))
        if kid != compute_thumbprint(raw):
            raise ValueError
    except (TypeError, ValueError):
        raise ArgumentError(
            "live public_key_jwk must be a valid public OKP/Ed25519 JWK "
            "with alg='EdDSA' and a matching kid"
        ) from None
    return raw


def _lifecycle_result_from_response(data: dict[str, Any]) -> LifecycleResult:
    raw_status = data.get("status") or data.get("state")
    return LifecycleResult(
        id=str(data.get("id") or ""),
        state=str(raw_status).upper() if raw_status is not None else "",
        status_note=str(data.get("status_note") or ""),
        raw=data,
    )


def _live_challenge_from_response(
    *,
    label: str,
    agent_id: str,
    challenge: str,
    challenge_message: str,
    expected_key_id: str | None = None,
    expected_domain: str | None = None,
) -> tuple[str, LiveChallengeTranscript]:
    import datetime
    import json

    from ._utils import b64url_decode_strict, normalize_fqdn
    from .enums import VerificationCode
    from .exceptions import VerificationError

    try:
        raw = json.loads(b64url_decode_strict(challenge_message).decode("utf-8"))
        if not isinstance(raw, dict):
            raise ValueError

        def text(name: str) -> str:
            value = raw.get(name)
            if not isinstance(value, str) or not value:
                raise ValueError
            return value

        protocol = text("protocol")
        org_id = text("org_id")
        transcript_agent_id = text("agent_id")
        fqdn = text("fqdn")
        key_id = text("key_id")
        nonce = text("nonce")
        expires = text("expires_at")
        if protocol != "dnsid-live-provisioning-pop/v1":
            raise ValueError
        if transcript_agent_id != agent_id or nonce != challenge:
            raise ValueError
        if expected_key_id is not None and key_id != expected_key_id:
            raise ValueError
        domain = normalize_fqdn(fqdn, agent_fqdn=True)
        if expected_domain is not None and domain != normalize_fqdn(
            expected_domain, agent_fqdn=True
        ):
            raise ValueError
        expires_at = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            raise ValueError
    except Exception:
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            f"{label}: invalid challenge transcript",
        ) from None
    return domain, LiveChallengeTranscript(
        protocol=protocol,
        org_id=org_id,
        agent_id=transcript_agent_id,
        fqdn=fqdn,
        key_id=key_id,
        nonce=nonce,
        expires_at=expires_at,
    )


def _live_provisioning_from_response(
    data: dict[str, Any], public_key: JWK
) -> LiveProvisioningResponse:
    label = "registry Live provisioning response"
    request_id = _require_str(data, "request_id", label)
    agent_id = _require_str(data, "agent_id", label)
    status = _require_str(data, "status", label)
    challenge = _require_string(data, "challenge", label)
    challenge_message = _require_string(data, "challenge_message", label)
    domain = ""
    transcript = None
    if status == "challenge_pending":
        domain, transcript = _live_challenge_from_response(
            label=label,
            agent_id=agent_id,
            challenge=challenge,
            challenge_message=challenge_message,
            expected_key_id=public_key.thumbprint(),
        )
    return LiveProvisioningResponse(
        request_id=request_id,
        agent_id=agent_id,
        status=status,
        challenge=challenge,
        challenge_message=challenge_message,
        domain=domain,
        challenge_transcript=transcript,
        raw=data,
    )


def _live_proof_reissue_from_response(
    data: dict[str, Any], expected_domain: str, expected_key_id: str
) -> LiveProofReissueResponse:
    label = "registry Live proof reissue response"
    request_id = _require_str(data, "request_id", label)
    agent_id = _require_str(data, "agent_id", label)
    status = _require_str(data, "status", label)
    challenge = _require_str(data, "challenge", label)
    challenge_message = _require_str(data, "challenge_message", label)
    domain, transcript = _live_challenge_from_response(
        label=label,
        agent_id=agent_id,
        challenge=challenge,
        challenge_message=challenge_message,
        expected_key_id=expected_key_id,
        expected_domain=expected_domain,
    )
    return LiveProofReissueResponse(
        request_id=request_id,
        agent_id=agent_id,
        status=status,
        challenge=challenge,
        challenge_message=challenge_message,
        domain=domain,
        challenge_transcript=transcript,
        raw=data,
    )


def _submission_result_from_response(data: dict[str, Any]) -> SubmissionResult:
    from .enums import VerificationCode
    from .exceptions import VerificationError
    from .models import LogRef

    state = str(data.get("state") or "").strip().lower()
    if state not in SubmissionResult.VALID_STATES:
        raise VerificationError(
            VerificationCode.LOG_ERROR,
            f"registry submission response: unknown state {state!r}",
        )
    index_raw = data.get("index")
    index = index_raw if isinstance(index_raw, int) and not isinstance(index_raw, bool) else None
    log_ref: LogRef | None = None
    log_ref_raw = data.get("lr") or data.get("logRef") or data.get("log_ref")
    if isinstance(log_ref_raw, str) and log_ref_raw:
        try:
            log_ref = LogRef.parse(log_ref_raw)
        except Exception:
            log_ref = None
    return SubmissionResult(
        state=state,
        entry_hash=str(data.get("entryHash") or data.get("entry_hash") or ""),
        index=index,
        log_ref=log_ref,
        key_id=str(data.get("keyId") or data.get("key_id") or ""),
        error_code=str(data.get("errorCode") or data.get("error_code") or ""),
        raw=data,
    )


def _published_record_from_response(domain: str, data: dict[str, Any]) -> PublishedRecord:
    publication_status = _require_str(data, "status", "registry publication response")
    protocol_status = _protocol_status_from_response(data)

    records = data.get("records")
    if isinstance(records, list) and records:
        first = records[0]
        if isinstance(first, dict):
            return PublishedRecord(
                domain=data.get("fqdn") or domain,
                owner_name=first.get("name", ""),
                txt_record=first.get("value", ""),
                ttl=int(first.get("ttl", 300)),
                publication_status=publication_status,
                protocol_status=protocol_status,
                raw=data,
            )
    return PublishedRecord(
        domain=data.get("fqdn") or domain,
        owner_name=data.get("ownerName", ""),
        txt_record=data.get("txtRecord", ""),
        ttl=int(data.get("ttl", 300)),
        publication_status=publication_status,
        protocol_status=protocol_status,
        raw=data,
    )


def _protocol_status_from_response(data: dict[str, Any]) -> AgentStatus | None:
    """Parse an authoritative complete protocolStatus object when supplied."""
    import datetime

    from .exceptions import ValidationError

    raw = data.get("protocolStatus", data.get("protocol_status"))
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValidationError("registry protocolStatus must be an object")
    state = raw.get("state")
    transition = raw.get("lastTransitionAt", raw.get("last_transition_at"))
    if not isinstance(state, str) or not isinstance(transition, str):
        raise ValidationError("registry protocolStatus is incomplete")
    try:
        parsed_transition = datetime.datetime.fromisoformat(transition.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("registry protocolStatus has invalid lastTransitionAt") from exc
    result = AgentStatus(
        state=state,
        last_transition_at=parsed_transition,
        revocation_reason=str(raw.get("revocationReason", raw.get("revocation_reason", ""))),
    )
    result.validate()
    return result


def _registration_from_response(
    requested_domain: str, registry_url: str, data: dict[str, Any]
) -> AgentRegistration:
    from .exceptions import ValidationError

    domain_value = data.get("domain") or data.get("fqdn") or requested_domain
    if not isinstance(domain_value, str) or not domain_value:
        raise ValidationError("registry registration is missing domain")
    managed = data.get("managed")
    if managed == "dnsid":
        authority = "registry"
    elif managed == "self":
        authority = "client"
    else:
        raise ValidationError("registry registration has unknown publication authority")
    raw_status = data.get("serverStatus", data.get("registryStatus", data.get("status")))
    if not isinstance(raw_status, str) or not raw_status:
        raise ValidationError("registry registration is missing registry status")
    raw_dns_published = data.get("dns_published", data.get("dnsPublished"))
    dns_published = raw_dns_published if isinstance(raw_dns_published, bool) else None
    publication_config = _publication_config_from_response(data)
    raw_id = data.get("id")
    return AgentRegistration(
        domain=domain_value,
        publication_authority=authority,
        registry_status=raw_status,
        registry_url=registry_url,
        dns_published=dns_published,
        protocol_status=_protocol_status_from_response(data),
        publication_config=publication_config,
        oidc_issuer_url=(
            _require_string(data, "oidc_issuer_url", "registry registration response")
            if "oidc_issuer_url" in data
            else ""
        ),
        id=raw_id if isinstance(raw_id, str) else "",
        raw=data,
    )


def _publication_config_from_response(data: dict[str, Any]) -> PublicationConfig | None:
    raw = data.get("publication_config", data.get("publicationConfig"))
    if raw is None:
        return None
    if not isinstance(raw, dict):
        from .exceptions import ValidationError

        raise ValidationError("registry publication_config must be an object")

    from .exceptions import ValidationError

    def required_field(name: str) -> str:
        value = raw.get(name)
        if not isinstance(value, str) or not value:
            raise ValidationError(f"registry publication_config is missing {name}")
        return value

    def optional_field(name: str) -> str:
        value = raw.get(name, "")
        if not isinstance(value, str):
            raise ValidationError(f"registry publication_config field {name} must be a string")
        return value

    return PublicationConfig(
        publish_profile=required_field("publish_profile"),
        governance_id=required_field("governance_id"),
        ku_url=required_field("ku_url"),
        ek_url=required_field("ek_url"),
        log_ref=required_field("log_ref"),
        status_url=required_field("status_url"),
        capabilities_url=optional_field("capabilities_url"),
        max_key_age=optional_field("max_key_age"),
    )
