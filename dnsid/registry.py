"""LogRegistry — single injection point for all log interaction."""

from __future__ import annotations

import re
from collections.abc import Callable

from .interfaces import LogReader, NoopLogReader

_METHOD_RE = re.compile(r"^[a-z][a-z0-9-]*$")

# Factory type: receives the full lr string, returns a bound LogReader.
LogReaderFactory = Callable[[str], LogReader]


class LogRegistry:
    """Holds one factory per log method; constructs bound LogReader instances on demand.

    For C2SP, prefer ``create_dnsid_managed_verification_registry()`` or
    ``create_c2sp_tlog_verification_registry(...)`` over manual registration.
    IdentityManager uses the registry to bind the local log and to construct
    counterparty readers during verification.
    """

    def __init__(self) -> None:
        """Initialize an empty registry with no registered log method factories."""
        self._factories: dict[str, LogReaderFactory] = {}

    def register(self, method: str, factory: LogReaderFactory) -> None:
        """Register a factory for *method* (e.g. 'c2sp-tlog').

        Args:
            method: Log method name; must match ``[a-z][a-z0-9-]*``.
            factory: Callable that builds a LogReader bound to a full lr string.

        Raises:
            ArgumentError: If *method* does not match ``[a-z][a-z0-9-]*``.
        """
        from .exceptions import ArgumentError

        if not _METHOD_RE.match(method):
            raise ArgumentError(f"log method {method!r} must match [a-z][a-z0-9-]*")
        self._factories[method] = factory

    def new_reader(self, lr: str) -> LogReader:
        """Construct a LogReader bound to the full log reference *lr*.

        Splits *lr* on the first ':' to extract the method prefix, then calls
        the registered factory.

        Args:
            lr: Full log reference string, e.g.
                ``"c2sp-tlog:public:https://log.dnsid.ai#<stream-id>"``.

        Returns:
            A LogReader bound to *lr*, or a NoopLogReader when the method has
            no registered factory.

        Raises:
            ParseError: If *lr* is malformed.
        """
        from ._utils import parse_ledger_ref

        method, _ = parse_ledger_ref(lr)  # raises ParseError if malformed

        factory = self._factories.get(method)
        if factory is None:
            return NoopLogReader(method=method)
        return factory(lr)
