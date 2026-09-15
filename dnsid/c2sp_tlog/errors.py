"""Error types for the c2sp-tlog log method."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .checkpoint_store import TrustedCheckpoint


class C2spLifecycleErrorCategory(StrEnum):
    """Stable failure categories used by C2SP lifecycle selection."""

    CHAIN_CONTINUITY = "CHAIN_CONTINUITY"
    DUPLICATE_ISSUANCE = "DUPLICATE_ISSUANCE"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    INCOMPLETE_STREAM = "INCOMPLETE_STREAM"
    INVALID_MIGRATION = "INVALID_MIGRATION"
    KEY_CONTINUITY = "KEY_CONTINUITY"
    TERMINAL_STATE = "TERMINAL_STATE"
    LOG_ROLLBACK = "LOG_ROLLBACK"
    LOG_FORK = "LOG_FORK"
    LOG_INCONSISTENT = "LOG_INCONSISTENT"
    CHECKPOINT_STORE_ERROR = "CHECKPOINT_STORE_ERROR"


class C2spTlogError(Exception):
    """Base error for the c2sp-tlog package.

    During verify_domain these surface as VerificationError with LOG_ERROR.
    """


class C2spTlogParseError(C2spTlogError):
    """Raised when C2SP wire data (checkpoints, proofs, entries) is malformed."""


class C2spTlogVerificationError(C2spTlogError):
    """Raised when C2SP evidence fails cryptographic or policy verification."""

    def __init__(
        self,
        message: str,
        *,
        category: C2spLifecycleErrorCategory | None = None,
        failing_candidate_index: int | None = None,
    ) -> None:
        """Initialize with a message and optional failure classification.

        Args:
            message: Human-readable description of the verification failure.
            category: Stable lifecycle failure category, when the failure
                maps to one.
            failing_candidate_index: Zero-based index of the candidate entry
                that failed, when identifiable.
        """
        super().__init__(message)
        self.category = category
        self.failing_candidate_index = failing_candidate_index


class C2spCheckpointConsistencyError(C2spTlogVerificationError):
    """A checkpoint violates previously accepted trust; never automatically retry.

    ``category`` identifies the failed check: ``LOG_ROLLBACK`` (smaller size),
    ``LOG_FORK`` (same size, different root), or ``LOG_INCONSISTENT`` (growing
    tree is not an extension). None establishes whether recovery was authorized.
    At the LogReader boundary this becomes a non-transient ``VerificationError``
    with the same category and this typed error as its ``__cause__``.
    """

    def __init__(
        self,
        message: str,
        *,
        category: C2spLifecycleErrorCategory,
        trusted: TrustedCheckpoint,
        observed: TrustedCheckpoint,
    ) -> None:
        """Capture both checkpoints so routing never requires message matching.

        Args:
            message: Description of the failed consistency check.
            category: The observed rollback, fork, or inconsistency category.
            trusted: Previously accepted checkpoint.
            observed: Candidate that failed the consistency check.
        """
        super().__init__(message, category=category)
        self.origin = trusted.origin
        self.trusted_tree_size = trusted.tree_size
        self.observed_tree_size = observed.tree_size
        self.trusted_root_hash = trusted.root_hash
        self.observed_root_hash = observed.root_hash


class C2spCheckpointStoreError(C2spTlogError):
    """Trusted storage is unavailable, corrupt, or changed during recovery.

    Fails closed as non-transient ``LOG_ERROR`` at the LogReader boundary.
    Restore storage or investigate before retrying; never substitute empty trust.
    """

    category = C2spLifecycleErrorCategory.CHECKPOINT_STORE_ERROR


class C2spTlogTransportError(C2spTlogError):
    """Raised when fetching C2SP verification resources fails.

    ``transient`` is true only when retrying the same read may succeed.  TLS,
    redirect, authentication, and configured resource-policy failures are
    non-transient; network reachability and server-unavailable failures are
    transient.
    """

    def __init__(
        self,
        message: str,
        *,
        transient: bool,
        cause: BaseException | None = None,
        status_code: int | None = None,
    ) -> None:
        """Initialize a classified transport failure.

        Args:
            message: Human-readable transport failure.
            transient: Whether retrying the same read may succeed.
            cause: Underlying transport exception, when available.
            status_code: HTTP response status, when the server responded.
        """
        super().__init__(message)
        self.transient = transient
        self.status_code = status_code
        self.category = C2spLifecycleErrorCategory.INVALID_EVIDENCE
        if cause is not None:
            self.__cause__ = cause
