"""Known Foundry named creation, separate from generic DNSid APIs.

``create(name)`` loads SDK environment configuration. Applications composing file
and code configuration pass ``config=LoadedConfig(...)`` and a separate credential.
Call ``identity.active()`` to complete public readiness; no background task runs.

Contract: dnsid-sdk-compliance a5e473d, design 13. No server revision is yet
certified for this adapter. Server acceptance SR-1 through SR-7 is a release gate;
ordinary 24-hour registration replay retention is not sufficient.
"""

from ._workflow import FoundryIdentity, create
from .errors import (
    FoundryBusy,
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
from .store import FileFoundryStore, FoundryStore

__all__ = [
    "FileFoundryStore",
    "FoundryBusy",
    "FoundryDeadline",
    "FoundryError",
    "FoundryIdentity",
    "FoundryStateError",
    "FoundryStore",
    "KeyMismatch",
    "KeyMissing",
    "KeyRevoked",
    "SigningPaused",
    "TerminalIdentity",
    "UnsupportedAlgorithm",
    "UnsupportedContract",
    "UnsupportedRegistry",
    "WorkflowOutcome",
    "create",
]
