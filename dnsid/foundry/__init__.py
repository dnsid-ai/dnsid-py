"""Known Foundry named creation, separate from generic DNSid APIs.

``create(name)`` loads SDK environment configuration. Applications composing file
and code configuration pass ``config=LoadedConfig(...)`` and a separate credential.
Call ``identity.active()`` to complete public readiness; no background task runs.
Create the provider's signing key first; Foundry never provisions or selects a key.
Foundry create rejects configuration with ordinary identity fields, including
``DNSID_DOMAIN`` and ``DNSID_GOVERNANCE_ID`` environment variables. Set Foundry's
expected GI through ``foundry.governanceId`` in file/code configuration.

The module stays source-only until the server's named-Live requirements are
released. It is excluded from wheels and sdists. No server revision is certified
for this adapter; ordinary 24-hour registration replay retention is not sufficient.
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
