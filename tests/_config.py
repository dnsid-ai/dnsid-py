"""Test helper: build a DnsidConfig from flat identity + verification kwargs."""

from dnsid import DnsidConfig, IdentityConfig, VerificationConfig

_VERIFICATION_FIELDS = ("status_check_interval", "dnssec_mode", "trusted_entities")


def make_config(**kwargs) -> DnsidConfig:
    verification = {k: kwargs.pop(k) for k in _VERIFICATION_FIELDS if k in kwargs}
    return DnsidConfig(
        identity=IdentityConfig(**kwargs),
        verification=VerificationConfig(**verification),
    )
