"""Exception types raised by the DNSid SDK.

All SDK errors derive from :class:`DNSidError`.  ParseError signals a
structurally malformed TXT record; ValidationError a semantic constraint
violation; VerificationError a live verification failure carrying a
VerificationCode; ArgumentError an invalid caller-supplied argument.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .enums import LifecycleErrorCategory, VerificationCode
    from .models import KeyRotationResult


class DNSidError(Exception):
    """Base for all DNSid SDK errors."""


class ParseError(DNSidError):
    """TXT record RDATA is structurally malformed (syntax, missing/duplicate tags).

    Never transient; retry will not help.
    """


class ValidationError(DNSidError):
    """Data parses correctly but violates semantic constraints.

    Examples: malformed gi; ku host mismatch; bad ka value.
    Never transient.
    """


class ArgumentError(DNSidError):
    """Caller-supplied argument is invalid (wrong format, reserved field override, etc.)."""


class ManagedKeyRotationSubmissionError(DNSidError):
    """Managed rotation submission failed with recoverable exact-byte state."""

    def __init__(
        self,
        message: str,
        rotation: KeyRotationResult,
        *,
        state: str,
        transient: bool,
        retry_same_bytes: bool,
        cause: BaseException | None = None,
    ) -> None:
        """Initialize a typed submission/recovery failure."""
        super().__init__(message)
        self.rotation = rotation
        self.state = state
        self.transient = transient
        self.retry_same_bytes = retry_same_bytes
        if cause is not None:
            self.__cause__ = cause


class ManagedKeyRotationActivationError(DNSidError):
    """Accepted managed rotation has incomplete local reconciliation."""

    def __init__(
        self,
        message: str,
        rotation: KeyRotationResult,
        *,
        cause: BaseException | None = None,
    ) -> None:
        """Initialize an activation, pause-release, or persistence failure."""
        super().__init__(message)
        self.rotation = rotation
        if cause is not None:
            self.__cause__ = cause


class VerificationError(DNSidError):
    """A live verification step failed.

    Carries a structured code and transient flag so callers can decide whether to
    retry and what to surface to users or logs.
    """

    def __init__(
        self,
        code: VerificationCode,
        message: str,
        *,
        transient: bool = False,
        agent_state: str | None = None,
        category: str | None = None,
        cause: BaseException | None = None,
        verified_governance_id: str | None = None,
        verified_entity_key_thumbprint: str | None = None,
    ) -> None:
        """Initialize the error with a structured code and message.

        Args:
            code: Failure category from :class:`~dnsid.enums.VerificationCode`.
            message: Human-readable description of the failure.
            transient: True when retrying the operation may succeed.
            agent_state: Agent lifecycle state reported by the status endpoint,
                when known.
            category: Stable lifecycle failure-category string, when the
                failure maps to one (see LifecycleErrorCategory).
            cause: Underlying exception to chain as ``__cause__``.
            verified_governance_id: For ``COUNTERPARTY_NOT_ACCEPTED`` only, the
                observed verified governance ID.
            verified_entity_key_thumbprint: For ``COUNTERPARTY_NOT_ACCEPTED``
                only, the observed record-signing key's RFC 7638 thumbprint.
        """
        super().__init__(message)
        self.code = code
        self.message = message
        self.transient = transient
        self.agent_state = agent_state
        self.category = category
        self.verified_governance_id = verified_governance_id
        self.verified_entity_key_thumbprint = verified_entity_key_thumbprint
        if cause is not None:
            self.__cause__ = cause

    def __str__(self) -> str:
        """Return the message prefixed with the verification code name."""
        return f"[{self.code.name}] {self.message}"


class LifecycleVerificationError(VerificationError):
    """A verified lifecycle history violates the shared reducer contract."""

    def __init__(
        self,
        category: LifecycleErrorCategory,
        message: str,
        *,
        failing_event_index: int | None = None,
    ) -> None:
        """Initialize with a lifecycle failure category and message.

        Args:
            category: Stable failure category from LifecycleErrorCategory;
                also exposed as the string ``category`` on the base class.
            message: Human-readable description of the violation.
            failing_event_index: Zero-based index of the offending event in
                the verified history, when identifiable.
        """
        from .enums import VerificationCode

        super().__init__(VerificationCode.LOG_ERROR, message, category=category.value)
        self.category: LifecycleErrorCategory = category
        self.failing_event_index = failing_event_index


class RegistryRequestError(VerificationError):
    """The registry answered a request with a non-2xx status.

    A :class:`VerificationError` (code ``LOG_ERROR``) so existing handlers keep
    working, plus the two facts a caller can act on: the HTTP status and the
    registry's short ``error`` code (``INVALID_TRANSITION``, ``NOT_FOUND`` …).
    The response body is never echoed into the message: an authenticated
    request's error body may repeat request metadata.
    """

    def __init__(self, path: str, status_code: int, error_code: str = "") -> None:
        """Build the error for *path* from the status and the registry's error code."""
        from .enums import VerificationCode

        detail = f" ({error_code})" if error_code else ""
        super().__init__(
            VerificationCode.LOG_ERROR,
            f"Registry request to {path!r} returned HTTP {status_code}{detail}",
            transient=status_code >= 500,
        )
        self.status_code = status_code
        self.error_code = error_code
