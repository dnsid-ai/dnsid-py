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

    Example:
        registry = LogRegistry()
        registry.register("algorand", AlgorandLogReader)
        reader = registry.new_reader("algorand:AGENT_ADDR")

    IdentityManager uses this at construction (to derive localLog) and during
    VerifyDomain (to construct counterparty readers).
    """

    def __init__(self) -> None:
        """Initialize an empty registry with no registered log method factories."""
        self._factories: dict[str, LogReaderFactory] = {}

    def register(self, method: str, factory: LogReaderFactory) -> None:
        """Register a factory for *method* (e.g. 'algorand', 'ctlog', 'scitt').

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
            lr: Full log reference string, e.g. ``"algorand:AGENT_ADDR"``.

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
