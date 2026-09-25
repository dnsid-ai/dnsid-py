"""Catch misleading generated API signatures and return descriptions."""

import griffe

from scripts.gen_docs import REPO_ROOT, _render_docstring, _signature


def test_generated_call_signatures_and_returns():
    pkg = griffe.load("dnsid", search_paths=[str(REPO_ROOT)], docstring_parser=griffe.Parser.google)
    jose = pkg.members["jose"].members["JoseProfile"]
    registry = pkg.members["registry_client"].members["RegistryClient"]

    assert "jwt: str, *, expected_audience:" in _signature(jose.members["verify_jwt"])
    assert _signature(registry.members["async_wait_for_status"]).startswith(
        "async async_wait_for_status(domain: str, *,"
    )
    returns = "\n".join(_render_docstring(jose.members["verify_jws"]))
    assert returns.count("- `tuple[bytes, VerifiedDomain]` —") == 1
    assert "the decoded payload and the VerifiedDomain" in returns
