"""Regression test: every name in dnsid.__all__ must be importable."""

import importlib
from dataclasses import FrozenInstanceError

import pytest

import dnsid


def test_all_names_are_accessible():
    """Every name in dnsid.__all__ must be an attribute of the dnsid package."""
    missing = [name for name in dnsid.__all__ if not hasattr(dnsid, name)]
    assert missing == [], f"Names in __all__ but not importable: {missing}"


def test_all_names_importable_via_from_import():
    """Each name in dnsid.__all__ can be imported with 'from dnsid import <name>'."""
    mod = importlib.import_module("dnsid")
    for name in dnsid.__all__:
        obj = getattr(mod, name, None)
        assert obj is not None, f"from dnsid import {name} failed (got None)"


def test_all_application_profiles_exported_at_top_level():
    """All four application profile classes are importable from the package root
    (parity with the TypeScript SDK's umbrella package), and the two with
    home submodules remain importable from there too."""
    for name in (
        "JoseProfile",
        "HttpSignatureProfile",
        "OIDCProfile",
        "WebBotAuthProfile",
    ):
        assert name in dnsid.__all__, f"{name} missing from dnsid.__all__"
        assert getattr(dnsid, name, None) is not None, f"dnsid.{name} not importable"

    from dnsid.http_signatures import HttpSignatureProfile
    from dnsid.jose import JoseProfile

    assert dnsid.JoseProfile is JoseProfile
    assert dnsid.HttpSignatureProfile is HttpSignatureProfile


def test_log_reader_dnsid1_binding_methods_fail_closed():
    """The shared LogReader interface declares the DNSid1 binding-level
    operations; bindings that cannot perform them fail closed."""
    import pytest

    from dnsid.enums import VerificationCode
    from dnsid.exceptions import VerificationError
    from dnsid.interfaces import NoopLogReader

    reader = NoopLogReader("microledger")
    with pytest.raises(VerificationError) as exc_info:
        reader.verify_bilateral_binding(None, None, None)
    assert exc_info.value.code == VerificationCode.LOG_ERROR
    with pytest.raises(VerificationError) as exc_info:
        reader.verify_operational_continuity("d.example", "t1", "t2")
    assert exc_info.value.code == VerificationCode.LOG_ERROR


def test_c2sp_spec_revision_metadata_exported():
    from dnsid.c2sp_tlog import C2SP_SPEC_REVISIONS, DNSID_C2SP_ENVELOPE_VERSION

    assert C2SP_SPEC_REVISIONS == {
        "tlog-checkpoint": "v1.0.0",
        "tlog-tiles": "v0.1.0",
        "tlog-proof": "ab17a74116563005f908b9167e6421cc929a5c2b",
        "tlog-policy": "1896a5aea5559b3203d275d0206d872f59348cf5",
        "tlog-witness": "v1.0.0",
        "tlog-cosignature": "v1.0.1",
        "tlog-mirror": "d0fe789122c75b903bfc1680b0b8b8dc570f0db3",
        "signed-note": "v1.0.0",
    }
    assert DNSID_C2SP_ENVELOPE_VERSION == 1


def test_sdk_conformance_metadata_exported_and_immutable():
    assert dnsid.SDK_CONFORMANCE == dnsid.SDKConformance(
        publish_profile="dnsid-draft-01",
        verification_profiles={
            "dnsid-draft-01": "dnsid-draft-01",
            "DNSid1": "dnsid-draft-01",
        },
        specification_status="internet-draft",
        log_bindings=dnsid.SDK_CONFORMANCE.log_bindings,
        known_deviations=(),
    )
    assert dnsid.SDK_CONFORMANCE.log_bindings["c2sp-tlog"] == (
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

    with pytest.raises(FrozenInstanceError):
        dnsid.SDK_CONFORMANCE.publish_profile = "changed"
    with pytest.raises(TypeError):
        dnsid.SDK_CONFORMANCE.verification_profiles["changed"] = "changed"
