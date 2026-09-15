from __future__ import annotations

import datetime
import http.server
import json
import logging
import threading
import time
from unittest.mock import MagicMock
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from dnsid import (
    JWKS,
    NetworkError,
    OAuthError,
    OIDCAssertionOptions,
    OIDCConfig,
    OIDCProfile,
    OIDCTokenExchangeOptions,
    TLSCertificate,
    VerifiedDomain,
    VerifyOIDCTokenOptions,
)
from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_decode, b64url_encode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.manager import IdentityManager, IdentityManagerDependencies
from tests._config import make_config
from tests.conftest import MockDNSResolver


def _profile(provider, config: OIDCConfig | None = None) -> OIDCProfile:
    mgr = IdentityManager(
        make_config(
            domain="agent.example.com",
            governance_id="example.com",
            log_ref="microledger:abc",
            status_url="https://agent.example.com/status",
        ),
        provider,
        deps=IdentityManagerDependencies(dns_resolver=MockDNSResolver()),
    )
    return OIDCProfile.from_identity_manager(mgr, config=config)


def _decode(token: str) -> tuple[dict, dict]:
    header, claims, _ = token.split(".")
    return json.loads(b64url_decode(header)), json.loads(b64url_decode(claims))


def _form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def test_create_oidc_assertion_uses_issuer_as_audience(ec_provider):
    oidc = _profile(ec_provider)
    token = oidc.create_oidc_assertion(OIDCAssertionOptions("https://issuer.example.com"))
    header, claims = _decode(token)

    assert header["typ"] == "JWT"
    assert header["alg"] == "ES256"
    assert header["kid"] == "k1"
    assert claims["iss"] == "agent.example.com"
    assert claims["sub"] == "agent.example.com"
    assert claims["aud"] == ["https://issuer.example.com"]
    assert claims["fqdn"] == "agent.example.com"
    assert claims["exp"] - claims["iat"] == 300
    assert len(claims["jti"]) == 32
    int(claims["jti"], 16)


def test_verification_only_profile_rejects_signing_cleanly():
    manager = IdentityManager.for_verification(
        IdentityManagerDependencies(dns_resolver=MockDNSResolver())
    )
    oidc = OIDCProfile.from_identity_manager(manager)

    with pytest.raises(ArgumentError, match="verification-only"):
        oidc.create_oidc_assertion(OIDCAssertionOptions("https://issuer.example.com"))


def test_oidc_config_preserves_default_scope_positional_compatibility():
    config = OIDCConfig("email")

    assert config.default_scope == "email"
    assert config.default_issuer == ""


def test_create_oidc_assertion_rejects_reserved_claims_and_bad_expiry(ec_provider):
    oidc = _profile(ec_provider)

    with pytest.raises(ArgumentError):
        oidc.create_oidc_assertion(
            OIDCAssertionOptions("https://issuer.example.com", additional_claims={"iss": "x"})
        )

    with pytest.raises(ArgumentError):
        oidc.create_oidc_assertion(
            OIDCAssertionOptions(
                "https://issuer.example.com", expiry=datetime.timedelta(seconds=901)
            )
        )

    with pytest.raises(ArgumentError):
        oidc.create_oidc_assertion(
            OIDCAssertionOptions("https://issuer.example.com", expiry=datetime.timedelta(seconds=0))
        )


def test_issuer_must_be_https_unless_loopback(ec_provider):
    oidc = _profile(ec_provider)
    with pytest.raises(ArgumentError):
        oidc.create_oidc_assertion(OIDCAssertionOptions("http://issuer.example.com"))

    local = _profile(ec_provider, OIDCConfig(allow_http_loopback_issuer=True))
    token = local.create_oidc_assertion(OIDCAssertionOptions("http://127.0.0.1:9999"))
    _, claims = _decode(token)
    assert claims["aud"] == ["http://127.0.0.1:9999"]


def test_loopback_http_discovery_uses_default_hardened_transport(ec_provider):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            issuer = f"http://127.0.0.1:{self.server.server_port}"
            body = json.dumps(
                {
                    "issuer": issuer,
                    "token_endpoint": f"{issuer}/token",
                    "jwks_uri": f"{issuer}/jwks",
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        issuer = f"http://127.0.0.1:{server.server_port}"
        oidc = _profile(ec_provider, OIDCConfig(allow_http_loopback_issuer=True))
        document = oidc.discover_oidc_issuer(issuer)
        assert document.issuer == issuer
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_issuer_and_configured_endpoints_reject_userinfo(ec_provider):
    oidc = _profile(
        ec_provider,
        OIDCConfig(default_issuer="https://issuer.example.com"),
    )

    with pytest.raises(ArgumentError, match="issuer"):
        oidc.create_oidc_assertion(
            OIDCAssertionOptions("https://issuer.example.com@evil.example")
        )

    bad_options = [
        OIDCTokenExchangeOptions(
            audience="rp.example.com",
            server_url="https://issuer.example.com@evil.example",
        ),
        OIDCTokenExchangeOptions(
            audience="rp.example.com",
            discovery_url="https://issuer.example.com@evil.example/.well-known/openid-configuration",
        ),
        OIDCTokenExchangeOptions(
            audience="rp.example.com",
            token_endpoint="https://issuer.example.com@evil.example/token",
        ),
    ]
    for opts in bad_options:
        with pytest.raises(ArgumentError, match="invalid OIDC"):
            oidc.mint_oidc_token(opts)


def test_discovery_rejects_cross_origin_endpoints(monkeypatch, ec_provider):
    oidc = _profile(ec_provider)
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda _url, *_args: {
            "issuer": "https://issuer.example.com",
            "token_endpoint": "https://evil.example.com/token",
            "jwks_uri": "https://issuer.example.com/jwks",
        },
    )

    with pytest.raises(VerificationError, match="token_endpoint"):
        oidc.discover_oidc_issuer("https://issuer.example.com")


def test_discovery_rejects_invalid_discovered_issuer_as_verification_error(
    monkeypatch, ec_provider
):
    oidc = _profile(ec_provider)
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda _url, *_args: {
            "issuer": "https://issuer.example.com@evil.example",
            "token_endpoint": "https://issuer.example.com/token",
            "jwks_uri": "https://issuer.example.com/jwks",
        },
    )

    with pytest.raises(VerificationError, match="issuer is invalid"):
        oidc.discover_oidc_issuer("https://issuer.example.com")


def test_server_url_mode_rejects_invalid_discovered_issuer_as_verification_error(
    ec_provider,
):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/openid-configuration"
        return httpx.Response(
            200,
            json={
                "issuer": "https://issuer.example.com@evil.example",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    oidc = _profile(
        ec_provider,
        OIDCConfig(http_client=client, allow_http_loopback_issuer=True),
    )

    with pytest.raises(VerificationError, match="issuer is invalid"):
        oidc.mint_oidc_token(
            OIDCTokenExchangeOptions(
                audience="rp.example.com",
                server_url="http://127.0.0.1:3001",
            )
        )

    client.close()


def test_discovery_url_appends_well_known_to_issuer(monkeypatch, ec_provider):
    oidc = _profile(ec_provider)
    seen = []

    def get_json(url: str, *_args) -> dict:
        seen.append(url)
        return {
            "issuer": "https://issuer.example.com/tenant",
            "token_endpoint": "https://issuer.example.com/token",
            "jwks_uri": "https://issuer.example.com/jwks",
        }

    monkeypatch.setattr("dnsid.oidc._get_json", get_json)
    oidc.discover_oidc_issuer("https://issuer.example.com/tenant")

    assert seen == ["https://issuer.example.com/tenant/.well-known/openid-configuration"]


def test_exchange_posts_expected_form(monkeypatch, ec_provider):
    oidc = _profile(ec_provider)
    seen = {}
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda _url, *_args: {
            "issuer": "https://issuer.example.com",
            "token_endpoint": "https://issuer.example.com/token",
            "jwks_uri": "https://issuer.example.com/jwks",
        },
    )

    def post_form(url: str, form: dict[str, str], *_args) -> dict:
        seen["url"] = url
        seen["form"] = form
        return {"access_token": "tok", "token_type": "Bearer", "expires_in": 60}

    monkeypatch.setattr("dnsid.oidc._post_form_json", post_form)
    result = oidc.exchange_oidc_token(
        OIDCTokenExchangeOptions("https://issuer.example.com", audience="rp.example.com")
    )

    assert result.access_token == "tok"
    assert seen["url"] == "https://issuer.example.com/token"
    assert seen["form"]["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assert seen["form"]["audience"] == "rp.example.com"
    assert seen["form"]["scope"] == "openid"


def test_mint_oidc_token_server_url_mode_ignores_discovered_token_endpoint(ed_provider):
    seen: dict[str, str] = {}
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": "https://oidc.custom.example",
                    "token_endpoint": "https://evil.example/token",
                    "jwks_uri": "https://oidc.custom.example/jwks",
                },
            )
        if request.url.path == "/token":
            seen.update(_form(request))
            header, claims = _decode(seen["assertion"])
            assert header["alg"] == "EdDSA"
            assert header["kid"] == "k1"
            assert claims["iss"] == "agent.example.com"
            assert claims["sub"] == "agent.example.com"
            assert claims["aud"] == ["https://oidc.custom.example"]
            return httpx.Response(
                200,
                json={
                    "access_token": "server-mode-token",
                    "token_type": "Bearer",
                    "expires_in": 60,
                    "scope": seen["scope"],
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    oidc = _profile(
        ed_provider,
        OIDCConfig(http_client=client, allow_http_loopback_issuer=True),
    )

    result = oidc.mint_oidc_token(
        OIDCTokenExchangeOptions(
            audience="https://api.example.com",
            server_url="http://127.0.0.1:3001",
            scope=["openid", "profile"],
        )
    )

    assert result.access_token == "server-mode-token"
    assert result.issuer == "https://oidc.custom.example"
    assert result.token_endpoint == "http://127.0.0.1:3001/token"
    assert result.audience == "https://api.example.com"
    assert result.requested_scope == "openid profile"
    assert result.assertion_issued_at is not None
    assert result.assertion_expires_at is not None
    assert (
        result.assertion_expires_at - result.assertion_issued_at
        == datetime.timedelta(seconds=300)
    )
    assert seen["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assert seen["audience"] == "https://api.example.com"
    assert seen["scope"] == "openid profile"
    assert "https://evil.example/token" not in urls
    client.close()


def test_token_endpoint_override_skips_discovery_and_uses_configured_issuer(ed_provider):
    requests: list[str] = []
    assertion_claims: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        assert request.url.path == "/custom-token"
        form = _form(request)
        _, claims = _decode(form["assertion"])
        assertion_claims.update(claims)
        return httpx.Response(
            200,
            json={"access_token": "override-token", "token_type": "Bearer", "expires_in": 60},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    oidc = _profile(
        ed_provider,
        OIDCConfig(
            default_issuer="https://issuer.override.example",
            http_client=client,
            allow_http_loopback_issuer=True,
        ),
    )

    result = oidc.mint_oidc_token(
        OIDCTokenExchangeOptions(
            audience="rp.example.com",
            token_endpoint="http://127.0.0.1:3001/custom-token",
        )
    )

    assert result.access_token == "override-token"
    assert assertion_claims["aud"] == ["https://issuer.override.example"]
    assert requests == ["http://127.0.0.1:3001/custom-token"]
    client.close()


@pytest.mark.parametrize("scope", [[""], ["openid profile"], [" openid"], ["openid\nprofile"]])
def test_scope_list_entries_must_be_single_tokens(ed_provider, scope):
    oidc = _profile(ed_provider, OIDCConfig(default_issuer="https://issuer.example.com"))

    with pytest.raises(ArgumentError, match="scope list entries"):
        oidc.mint_oidc_token(
            OIDCTokenExchangeOptions(
                audience="rp.example.com",
                token_endpoint="http://127.0.0.1:3001/token",
                scope=scope,
            )
        )


def test_discovery_url_override_and_timeout_use_injected_http_client(ed_provider):
    seen_timeouts: list[dict[str, float]] = []
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        seen_timeouts.append(request.extensions["timeout"])
        if request.url.path == "/custom-discovery":
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/custom-token",
                    "jwks_uri": "https://issuer.example.com/jwks",
                },
            )
        if request.url.path == "/custom-token":
            return httpx.Response(
                200,
                json={"access_token": "custom-discovery-token", "token_type": "Bearer"},
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    oidc = _profile(
        ed_provider,
        OIDCConfig(
            http_client=client,
            timeout=2.5,
            allow_http_loopback_issuer=True,
        ),
    )

    result = oidc.mint_oidc_token(
        OIDCTokenExchangeOptions(
            issuer="https://issuer.example.com",
            audience="rp.example.com",
            discovery_url="http://127.0.0.1:3001/custom-discovery",
        )
    )

    assert result.access_token == "custom-discovery-token"
    assert seen_urls == [
        "http://127.0.0.1:3001/custom-discovery",
        "https://issuer.example.com/custom-token",
    ]
    assert all(timeout["connect"] == 2.5 for timeout in seen_timeouts)
    client.close()


def test_loopback_discovery_override_requires_explicit_opt_in(ed_provider):
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    oidc = _profile(ed_provider, OIDCConfig(http_client=client))
    try:
        with pytest.raises(ArgumentError, match="explicit opt-in"):
            oidc.discover_oidc_issuer(
                "https://issuer.example.com",
                discovery_url="http://127.0.0.1:3001/custom-discovery",
            )
        assert called is False
    finally:
        client.close()


def test_discovery_and_token_errors_surface_cleanly(ed_provider):
    discovery_client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(503, json={}))
    )
    oidc = _profile(ed_provider, OIDCConfig(http_client=discovery_client))

    with pytest.raises(NetworkError, match="HTTP 503"):
        oidc.mint_oidc_token(
            OIDCTokenExchangeOptions(
                issuer="https://issuer.example.com", audience="rp.example.com"
            )
        )
    discovery_client.close()

    def token_error_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                    "jwks_uri": "https://issuer.example.com/jwks",
                },
            )
        return httpx.Response(
            400,
            json={"error": "invalid_scope", "error_description": "scope is not permitted"},
        )

    token_client = httpx.Client(transport=httpx.MockTransport(token_error_handler))
    oidc = _profile(ed_provider, OIDCConfig(http_client=token_client))
    with pytest.raises(OAuthError, match="scope is not permitted") as excinfo:
        oidc.mint_oidc_token(
            OIDCTokenExchangeOptions(
                issuer="https://issuer.example.com", audience="rp.example.com"
            )
        )
    assert excinfo.value.error == "invalid_scope"
    token_client.close()


def test_mint_oidc_token_does_not_log_assertion_or_access_token(caplog, ed_provider):
    captured_assertion = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_assertion
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                    "jwks_uri": "https://issuer.example.com/jwks",
                },
            )
        captured_assertion = _form(request)["assertion"]
        return httpx.Response(
            200,
            json={"access_token": "opaque-response-value-for-log-test", "token_type": "Bearer"},
        )

    caplog.set_level(logging.DEBUG)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    oidc = _profile(ed_provider, OIDCConfig(http_client=client))

    result = oidc.mint_oidc_token(
        OIDCTokenExchangeOptions(issuer="https://issuer.example.com", audience="rp.example.com")
    )

    assert result.access_token == "opaque-response-value-for-log-test"
    assert captured_assertion
    assert captured_assertion not in caplog.text
    assert "opaque-response-value-for-log-test" not in caplog.text
    client.close()


def _rsa_jwk(private_key: rsa.RSAPrivateKey, kid: str = "rsa1") -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    n = b64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = b64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": n, "e": e}


def _rs256_token(
    private_key: rsa.RSAPrivateKey,
    kid: str = "rsa1",
    aud="rp.example.com",
    extra_claims: dict | None = None,
) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    claims = {
        "iss": "https://issuer.example.com",
        "sub": "agent.example.com",
        "aud": aud,
        "iat": now,
        "exp": now + 300,
        **(extra_claims or {}),
    }
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    c = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    sig = private_key.sign(f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{c}.{b64url_encode(sig)}"


def test_verify_oidc_token_rs256_and_dnsid_subject(monkeypatch, ec_provider):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _rs256_token(issuer_key)
    oidc = _profile(ec_provider, OIDCConfig(allowed_issuers=["https://issuer.example.com"]))
    verified = MagicMock(spec=VerifiedDomain)
    verified.jwks = JWKS(keys=[jwk_from_dict(_rsa_jwk(issuer_key))])

    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda url, *_args: (
            {
                "issuer": "https://issuer.example.com",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
            }
            if url.endswith("openid-configuration")
            else {"keys": [_rsa_jwk(issuer_key)]}
        ),
    )
    monkeypatch.setattr(oidc._resolver, "verify_domain", MagicMock(return_value=verified))

    peer_cert = TLSCertificate(san_dns_names=["agent.example.com"])
    result = oidc.verify_oidc_token(
        token,
        VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com"),
        peer_cert=peer_cert,
    )

    assert result.subject == "agent.example.com"
    assert result.verified_domain is verified
    oidc._resolver.verify_domain.assert_called_once_with(
        "agent.example.com", peer_cert=peer_cert
    )


def test_verify_oidc_token_rejects_invalid_audience_and_azp(monkeypatch, ec_provider):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oidc = _profile(ec_provider, OIDCConfig(allowed_issuers=["https://issuer.example.com"]))
    jwk = _rsa_jwk(issuer_key)
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda url, *_args: (
            {
                "issuer": "https://issuer.example.com",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
            }
            if url.endswith("openid-configuration")
            else {"keys": [jwk]}
        ),
    )

    token = _rs256_token(issuer_key, aud=["rp.example.com", "other.example.com"])
    with pytest.raises(VerificationError, match="audience mismatch"):
        oidc.verify_oidc_token(
            token, VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com", False)
        )

    token = _rs256_token(
        issuer_key,
        aud="rp.example.com",
        extra_claims={"azp": "other.example.com"},
    )
    with pytest.raises(VerificationError, match="azp mismatch"):
        oidc.verify_oidc_token(
            token, VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com", False)
        )


def test_verify_oidc_token_accepts_alg_less_rsa_jwk(monkeypatch, ec_provider):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _rs256_token(issuer_key)
    oidc = _profile(ec_provider, OIDCConfig(allowed_issuers=["https://issuer.example.com"]))
    jwk = _rsa_jwk(issuer_key)
    del jwk["alg"]
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda url, *_args: (
            {
                "issuer": "https://issuer.example.com",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
            }
            if url.endswith("openid-configuration")
            else {"keys": [jwk]}
        ),
    )

    result = oidc.verify_oidc_token(
        token, VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com", False)
    )

    assert result.subject == "agent.example.com"


def test_verify_oidc_token_rejects_non_signing_jwk(monkeypatch, ec_provider):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _rs256_token(issuer_key)
    oidc = _profile(ec_provider, OIDCConfig(allowed_issuers=["https://issuer.example.com"]))

    def assert_rejected(jwk: dict) -> None:
        monkeypatch.setattr(
            "dnsid.oidc._get_json",
            lambda url, *_args: (
                {
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                    "jwks_uri": "https://issuer.example.com/jwks",
                }
                if url.endswith("openid-configuration")
                else {"keys": [jwk]}
            ),
        )
        with pytest.raises(VerificationError, match="signing key mismatch"):
            oidc.verify_oidc_token(
                token, VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com", False)
            )

    assert_rejected({**_rsa_jwk(issuer_key), "use": "enc"})
    assert_rejected({**_rsa_jwk(issuer_key), "key_ops": ["encrypt"]})


def test_verify_oidc_token_rejects_non_finite_numeric_dates(monkeypatch, ec_provider):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oidc = _profile(ec_provider, OIDCConfig(allowed_issuers=["https://issuer.example.com"]))
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda url, *_args: (
            {
                "issuer": "https://issuer.example.com",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
            }
            if url.endswith("openid-configuration")
            else {"keys": [_rsa_jwk(issuer_key)]}
        ),
    )

    for claim, value in [("iat", float("nan")), ("exp", float("inf")), ("nbf", float("inf"))]:
        token = _rs256_token(issuer_key, extra_claims={claim: value})
        with pytest.raises(VerificationError, match="malformed JOSE JSON"):
            oidc.verify_oidc_token(
                token, VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com", False)
            )


def test_verify_oidc_token_requires_allowed_issuer(ec_provider):
    oidc = _profile(ec_provider)
    with pytest.raises(VerificationError, match="not allowed"):
        oidc.verify_oidc_token("x.y.z", VerifyOIDCTokenOptions("https://issuer.example.com", "rp"))


def test_verify_oidc_token_rejects_non_string_sub(monkeypatch, ec_provider):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oidc = _profile(ec_provider, OIDCConfig(allowed_issuers=["https://issuer.example.com"]))
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda url, *_args: (
            {
                "issuer": "https://issuer.example.com",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
            }
            if url.endswith("openid-configuration")
            else {"keys": [_rsa_jwk(issuer_key)]}
        ),
    )
    opts = VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com", False)

    for bad_sub in [True, 123, {"x": "y"}]:
        token = _rs256_token(issuer_key, extra_claims={"sub": bad_sub})
        with pytest.raises(VerificationError, match="missing sub"):
            oidc.verify_oidc_token(token, opts)


def test_verify_oidc_token_rejects_invalid_signature_encoding(monkeypatch, ec_provider):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oidc = _profile(ec_provider, OIDCConfig(allowed_issuers=["https://issuer.example.com"]))
    monkeypatch.setattr(
        "dnsid.oidc._get_json",
        lambda url, *_args: (
            {
                "issuer": "https://issuer.example.com",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
            }
            if url.endswith("openid-configuration")
            else {"keys": [_rsa_jwk(issuer_key)]}
        ),
    )
    valid = _rs256_token(issuer_key)
    header, claims, _ = valid.split(".")
    token = f"{header}.{claims}.a"  # invalid base64url length

    with pytest.raises(VerificationError, match="invalid JOSE base64url"):
        oidc.verify_oidc_token(
            token, VerifyOIDCTokenOptions("https://issuer.example.com", "rp.example.com", False)
        )
