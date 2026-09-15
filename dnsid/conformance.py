"""Machine-readable DNSid protocol conformance metadata."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class SDKConformance:
    """Immutable protocol-facing conformance metadata for this SDK release."""

    publish_profile: str
    verification_profiles: Mapping[str, str]
    specification_status: str
    log_bindings: Mapping[str, str]
    known_deviations: tuple[str, ...]


_DRAFT_01 = "dnsid-draft-01"
_C2SP_TLOG_BINDING = (
    "profile=1;"
    "tlog-checkpoint=https://c2sp.org/tlog-checkpoint@v1.0.0;"
    "tlog-tiles=https://c2sp.org/tlog-tiles@v0.1.0;"
    "tlog-proof=ab17a74116563005f908b9167e6421cc929a5c2b;"
    "tlog-policy=1896a5aea5559b3203d275d0206d872f59348cf5;"
    "tlog-witness=https://c2sp.org/tlog-witness@v1.0.0;"
    "tlog-cosignature=https://c2sp.org/tlog-cosignature@v1.0.1;"
    "tlog-mirror=d0fe789122c75b903bfc1680b0b8b8dc570f0db3;"
    "signed-note=https://c2sp.org/signed-note@v1.0.0;"
    "dnsid-method=d5a65d06f76eff4db81e50f8767a600d2ca7fc2a"
)


#: Immutable conformance metadata for the protocol behavior in this release.
SDK_CONFORMANCE = SDKConformance(
    publish_profile=_DRAFT_01,
    verification_profiles=MappingProxyType(
        {
            _DRAFT_01: _DRAFT_01,
            "DNSid1": _DRAFT_01,
        }
    ),
    specification_status="internet-draft",
    log_bindings=MappingProxyType({"c2sp-tlog": _C2SP_TLOG_BINDING}),
    known_deviations=(),
)


__all__ = ["SDKConformance", "SDK_CONFORMANCE"]
