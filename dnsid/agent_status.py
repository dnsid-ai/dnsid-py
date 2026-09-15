"""Agent status helpers."""

from __future__ import annotations

import datetime
from typing import Any


def active_status_document(
    last_transition_at: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Return a minimal ACTIVE status document for demos and tests.

    Suitable for serving directly from a ``/.well-known/status.json`` endpoint.
    The returned dict is JSON-serializable.

    Args:
        last_transition_at: Timestamp to record. Defaults to ``datetime.datetime.now(UTC)``.
    """
    if last_transition_at is None:
        last_transition_at = datetime.datetime.now(datetime.UTC)
    return {
        "state": "ACTIVE",
        "lastTransitionAt": last_transition_at.isoformat(),
    }
