"""Tests for the WBA HTTP Message Signature signer (dnsid#1250, design §4.2/§7)."""

from __future__ import annotations

import hashlib

import pytest

from dnsid import HttpRequest
from dnsid._utils import b64_std_decode
from dnsid.exceptions import ArgumentError
from dnsid.http_signatures import _build_signature_base
from dnsid.local_key_provider import LocalKeyProvider
from dnsid.models import SignatureParams
from dnsid.wba_signer import (
    WBA_DIRECTORY_MEDIA_TYPE,
    WBA_TAG,
    WBAHttpSigner,
    WBAVariant,
    WebBotAuthConfig,
    WebBotAuthSigningOptions,
    serve_http_message_signatures_directory,
)

DOMAIN = "agent.example.com"


def _signer():
    return WBAHttpSigner(LocalKeyProvider.generate(), DOMAIN)


def _req():
    return HttpRequest(
        method="POST",
        url="https://target.example/api",
        headers={"host": "target.example"},
        body=b'{"hello":"world"}',
    )


def _sig_valid(signer: WBAHttpSigner, req: HttpRequest) -> bool:
    """Recompute the signature base from the signed request and verify it."""
    params = SignatureParams.parse(req.get_header("signature-input"))
    sig_base = _build_signature_base(req, params)
    prefix = f"{params.label}=:"
    raw = b64_std_decode(req.get_header("signature")[len(prefix) : -1])
    return signer._key_provider.signing_key().verify(sig_base, raw)


def test_active_is_wba_compliant_and_valid():
    signer, req = _signer(), _req()
    signer.sign(req, WBAVariant.ACTIVE)

    params = SignatureParams.parse(req.get_header("signature-input"))
    assert params.tag == WBA_TAG
    # keyid is the RFC 7638 thumbprint, not "{domain}#{kid}"
    assert params.key_id == signer._key_provider.signing_key().thumbprint()
    assert "#" not in params.key_id
    assert params.created is not None and params.expires is not None
    assert params.nonce
    assert 'signature-agent;key="sig1"' in params.components
    # Signature-Agent is a Dictionary member pointing at the well-known
    # directory URL by default.
    assert req.get_header("signature-agent") == (f'sig1="https://{DOMAIN}";type=directory')
    assert "@authority" in params.components
    assert "content-digest" in params.components  # body present
    assert _sig_valid(signer, req)


def test_nonce_is_64_random_bytes_base64url():
    from dnsid._utils import b64url_decode

    signer, req = _signer(), _req()
    signer.sign(req)
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert len(b64url_decode(params.nonce)) == 64
    assert "=" not in params.nonce


def test_default_ttl_is_60_seconds():
    signer, req = _signer(), _req()
    signer.sign(req)
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert params.expires == params.created + 60


def test_supplied_empty_content_is_hashed_and_covered():
    signer = _signer()
    req = HttpRequest(method="POST", url="https://target.example/api", body=b"")
    signer.sign(req)
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert req.get_header("content-digest") == (
        "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
    )
    assert "content-digest" in params.components


def test_absent_content_does_not_follow_content_length():
    signer = _signer()
    req = HttpRequest(
        method="POST",
        url="https://target.example/api",
        headers={"content-length": "0"},
        body=None,
    )
    signer.sign(req)
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert req.get_header("content-digest") == ""
    assert "content-digest" not in params.components


def test_ttl_override_via_options():
    signer, req = _signer(), _req()
    signer.sign(req, options=WebBotAuthSigningOptions(ttl=120))
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert params.expires == params.created + 120


def test_signature_agent_suppressed_via_options():
    signer, req = _signer(), _req()
    signer.sign(req, options=WebBotAuthSigningOptions(signature_agent=False))
    assert req.get_header("signature-agent") == ""
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert all(not c.startswith("signature-agent") for c in params.components)
    assert _sig_valid(signer, req)


def test_preserves_other_signature_agent_members():
    signer, req = _signer(), _req()
    req.set_header("signature-agent", 'other="https://other.example";type=directory')

    signer.sign(req)

    header = req.get_header("signature-agent")
    assert 'other="https://other.example";type=directory' in header
    assert f'sig1="https://{DOMAIN}";type=directory' in header
    assert _sig_valid(signer, req)


def test_non_ed25519_key_rejected():
    from tests.conftest import RealKeyProvider, make_ec_p256_pair

    private, pub = make_ec_p256_pair("k1")
    signer = WBAHttpSigner(RealKeyProvider("k1", {"k1": (private, pub)}), DOMAIN)
    with pytest.raises(ArgumentError, match="Ed25519"):
        signer.sign(_req())


def test_unknown_additional_component_rejected():
    signer, req = _signer(), _req()
    with pytest.raises(ArgumentError, match="unknown signature component"):
        signer.sign(req, options=WebBotAuthSigningOptions(additional_components=["Bad-Header"]))


def test_directory_response_is_signed_and_typed():
    from dnsid._utils import b64_std_decode as _b64d

    provider = LocalKeyProvider.generate()
    req = HttpRequest(
        method="GET",
        url=f"https://{DOMAIN}/.well-known/http-message-signatures-directory",
        headers={"host": DOMAIN},
    )
    res = serve_http_message_signatures_directory(req, provider)

    assert res.status == 200
    assert res.headers["content-type"] == WBA_DIRECTORY_MEDIA_TYPE
    assert res.headers["cache-control"] == "max-age=300"

    import json as _json

    body = _json.loads(res.body)
    key = body["keys"][0]
    # Directory JWKs use the RFC 7638 thumbprint as kid and the HTTP Message
    # Signatures algorithm name, not the JOSE name.
    assert key["kid"] == provider.signing_key().thumbprint()
    assert key["alg"] == "ed25519"
    assert key["use"] == "sig"
    assert key["kty"] == "OKP" and key["crv"] == "Ed25519" and key["x"]
    assert "d" not in key

    params = SignatureParams.parse(res.headers["signature-input"])
    assert params.tag == "http-message-signatures-directory"
    assert params.key_id == provider.signing_key().thumbprint()
    assert "@authority;req" in params.components

    # Recompute the response signature base and verify.
    from dnsid.http_signatures import _resolve_authority

    lines = [
        f'"@authority";req: {_resolve_authority(req)}',
        f'"content-type": {res.headers["content-type"]}',
        f'"cache-control": {res.headers["cache-control"]}',
        f'"content-digest": {res.headers["content-digest"]}',
        f'"@signature-params": {params.value_string()}',
    ]
    raw = _b64d(res.headers["signature"][len("sig1=:") : -1])
    assert provider.signing_key().verify("\n".join(lines).encode(), raw)


def test_signature_agent_must_be_https_uri():
    with pytest.raises(ArgumentError, match="https"):
        WBAHttpSigner(LocalKeyProvider.generate(), DOMAIN, signature_agent=DOMAIN)


def test_directory_discovery_emits_origin_and_explicit_type():
    signer = WBAHttpSigner(
        LocalKeyProvider.generate(),
        DOMAIN,
        config=WebBotAuthConfig(directory_url="https://bots.example/dir"),
    )
    req = _req()
    signer.sign(req)
    assert req.get_header("signature-agent") == 'sig1="https://bots.example";type=directory'


def test_jwks_uri_discovery_keeps_direct_endpoint():
    signer = WBAHttpSigner(
        LocalKeyProvider.generate(),
        DOMAIN,
        config=WebBotAuthConfig(
            signature_agent_uri="https://bots.example/keys.json",
            signature_agent_type="jwks_uri",
        ),
    )
    req = _req()
    signer.sign(req)
    assert req.get_header("signature-agent") == (
        'sig1="https://bots.example/keys.json";type=jwks_uri'
    )


@pytest.mark.parametrize("ttl", [0, -1, 301])
def test_request_ttl_outside_profile_bounds_rejected(ttl):
    signer, req = _signer(), _req()
    with pytest.raises(ArgumentError, match="TTL"):
        signer.sign(req, options=WebBotAuthSigningOptions(ttl=ttl))


def test_configuration_bounds_rejected():
    with pytest.raises(ArgumentError, match="signature_ttl"):
        WebBotAuthConfig(signature_ttl=301)
    with pytest.raises(ArgumentError, match="clock_skew"):
        WebBotAuthConfig(clock_skew=-1)


def test_revoked_produces_a_valid_signature():
    # Revocation is directory state, not a signature property — sig must verify.
    signer, req = _signer(), _req()
    signer.sign(req, WBAVariant.REVOKED)
    assert _sig_valid(signer, req)


def test_key_mismatch_does_not_verify():
    signer, req = _signer(), _req()
    signer.sign(req, WBAVariant.KEY_MISMATCH)
    # Advertised keyid is the real one, but a different key signed it.
    assert (
        SignatureParams.parse(req.get_header("signature-input")).key_id
        == signer._key_provider.signing_key().thumbprint()
    )
    assert not _sig_valid(signer, req)


def test_no_sig_omits_signature_headers():
    signer, req = _signer(), _req()
    signer.sign(req, WBAVariant.NO_SIG)
    assert req.get_header("signature") == ""
    assert req.get_header("signature-input") == ""
    assert req.get_header("signature-agent") == ""


def test_tampered_body_breaks_content_digest():
    signer, req = _signer(), _req()
    signer.sign(req, WBAVariant.TAMPERED)
    # The signature itself still verifies (it covers the digest header)...
    assert _sig_valid(signer, req)
    # ...but the body no longer matches the covered content-digest → WAF rejects.
    _, expected = req.get_header("content-digest").split(":", 1)
    expected_bytes = b64_std_decode(expected.rstrip(":"))
    assert hashlib.sha256(req.body).digest() != expected_bytes


def test_expired_has_expires_in_the_past():
    signer, req = _signer(), _req()
    signer.sign(req, WBAVariant.EXPIRED)
    params = SignatureParams.parse(req.get_header("signature-input"))
    now = int(__import__("time").time())
    assert params.expires is not None and params.expires < now
    # Signature is cryptographically valid; only the timestamp is stale.
    assert _sig_valid(signer, req)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
