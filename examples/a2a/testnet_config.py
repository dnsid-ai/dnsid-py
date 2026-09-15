"""Trusted configuration helpers for the local DNSid testnet example."""

from __future__ import annotations

from collections.abc import Mapping


def required_log_policy_url(environment: Mapping[str, str]) -> str:
    """Return the independently supplied testnet C2SP policy URL."""
    policy_url = environment.get("DNSID_LOG_POLICY_URL", "").strip()
    if not policy_url:
        raise RuntimeError("DNSID_LOG_POLICY_URL is required; run with `dnsid testnet run`")
    return policy_url
