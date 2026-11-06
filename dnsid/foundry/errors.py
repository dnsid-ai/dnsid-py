"""Structured Foundry workflow failures; wire codes are never renamed."""

from __future__ import annotations

from typing import Any

from ..exceptions import DNSidError


class FoundryError(DNSidError):
    """A failure with the latest durable facts and explicit resume semantics."""

    category = "workflow"

    def __init__(
        self,
        message: str,
        *,
        operation: dict[str, Any] | None = None,
        resumable: bool = False,
        cause: BaseException | None = None,
    ) -> None:
        """Retain non-secret routing facts, not credentials or private keys."""
        super().__init__(message)
        facts = operation or {}
        self.phase = facts.get("phase", "")
        self.identity_id = facts.get("identityId")
        self.domain = facts.get("domain")
        self.registry_status = facts.get("registryStatus")
        self.resumable = resumable
        self.status_code = getattr(cause, "status_code", None)
        self.error_code = getattr(cause, "error_code", "")
        self.__cause__ = cause


class KeyMissing(FoundryError):
    """The selected provider has no signing key and cannot provision it."""

    category = "KEY_MISSING"


class KeyMismatch(FoundryError):
    """The provider does not match the established identity binding."""

    category = "KEY_MISMATCH"


class KeyRevoked(FoundryError):
    """The registry explicitly reported a revoked organization credential."""

    category = "KEY_REVOKED"


class SigningPaused(FoundryError):
    """Application signing awaits verified setup or binding recovery."""

    category = "signing_paused"


class UnsupportedRegistry(FoundryError):
    """The registry does not serve the Identity Digital onboarding contract."""

    category = "unsupported_registry"


class UnsupportedContract(FoundryError):
    """A response or configuration cannot satisfy the supported contract."""

    category = "unsupported_contract"


class UnsupportedAlgorithm(FoundryError):
    """Named Live creation requires Ed25519 with EdDSA."""

    category = "unsupported_algorithm"


class FoundryBusy(FoundryError):
    """Another caller owns this operation until the caller's deadline."""

    category = "busy"


class FoundryDeadline(FoundryError):
    """The finite invocation budget ended; persisted progress remains."""

    category = "deadline"


class WorkflowOutcome(FoundryError):
    """The registry requires customer action or reports an error outcome."""

    category = "workflow_outcome"


class TerminalIdentity(FoundryError):
    """A revoked or retired identity cannot be replaced through create."""

    category = "terminal"


class FoundryStateError(FoundryError):
    """Missing, corrupt, or conflicting recovery state prevents mutation."""

    category = "state"
