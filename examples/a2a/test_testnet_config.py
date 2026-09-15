"""Tests for trusted DNSid testnet configuration."""

import pytest
from testnet_config import required_log_policy_url


def test_required_log_policy_url_returns_separately_supplied_value() -> None:
    environment = {
        "DNSID_LOG_REF": "c2sp-tlog:testnet:https://log-reference.invalid#stream",
        "DNSID_LOG_POLICY_URL": "https://trusted-policy.invalid:8443/policy",
    }

    assert required_log_policy_url(environment) == "https://trusted-policy.invalid:8443/policy"


def test_required_log_policy_url_fails_clearly_when_missing() -> None:
    with pytest.raises(RuntimeError, match="DNSID_LOG_POLICY_URL is required"):
        required_log_policy_url({"DNSID_LOG_REF": "c2sp-tlog:testnet:https://log.invalid#stream"})
