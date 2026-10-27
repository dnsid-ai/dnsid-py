"""Native negotiated response conformance through the public HTTP profile APIs."""

from __future__ import annotations

import asyncio
import datetime
import gzip
import hashlib
import threading
import time
from copy import deepcopy
from types import SimpleNamespace

import http_sf
import httpx
import pytest

from dnsid import (
    JWKS,
    AgentStatus,
    DnsidConfig,
    HttpRequest,
    HttpSignatureProfile,
    HttpSigningOptions,
    IdentityManager,
    IdentityManagerDependencies,
    ResponseSignatureOptions,
    SignatureParams,
    TLSCertificate,
    TrustedEntity,
    VerificationConfig,
)
from dnsid._utils import b64_std_encode, b64url_decode, b64url_encode
from dnsid._verification_budget import verification_budget
from dnsid.enums import DNSSECState, VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.http_signatures import HttpMessageSignatureConfig, _build_signature_base
from dnsid.models import TXTRecord
from tests.conftest import MockDNSResolver, RealKeyProvider, make_ec_p256_pair
from tests.test_verify_domain import _make_signed_txt_record, _stub_log_registry

DOMAIN = "service.example.com"
REQUIRED = [
    "@status", "@method;req", "@authority;req", "@target-uri;req",
    "accept-signature;req", "signature-input;req", "signature;req",
    "content-digest", "cache-control",
]


@pytest.fixture
def make_env(ec_pair, ec_provider, monkeypatch):
    def build(*, provider=None, fl="", trusted=None):
        provider = provider or ec_provider
        now = datetime.datetime.now(datetime.UTC)
        monkeypatch.setattr("dnsid.http_signatures._now", lambda: now)
        txt = _make_signed_txt_record(ec_pair[0], ec_pair[1], DOMAIN, fl=fl)
        state = SimpleNamespace(
            now=now, provider=provider, dns_calls=[], status_calls=[],
            status=AgentStatus(state="ACTIVE", last_transition_at=now),
            jwks=JWKS(keys=[provider.signing_key()]),
        )

        def dns(name):
            state.dns_calls.append(name)
            assert name == f"_dnsid.{DOMAIN}"
            return [TXTRecord(strings=[txt.encode()], ttl=300)], DNSSECState.UNKNOWN

        resolver = MockDNSResolver()
        resolver.fetch_txt = dns
        manager = IdentityManager(
            DnsidConfig(verification=VerificationConfig(trusted_entities=trusted)), None,
            IdentityManagerDependencies(dns_resolver=resolver, log_registry=_stub_log_registry()),
        )
        cert = TLSCertificate(not_after=now + datetime.timedelta(days=1), san_dns_names=[DOMAIN])

        def jwks(uri, **kwargs):
            return (state.jwks if uri.startswith(f"https://{DOMAIN}/")
                    else JWKS(keys=[ec_pair[1]])), cert

        def status(*args, **kwargs):
            state.status_calls.append(args)
            return state.status

        async def async_jwks(uri, **kwargs):
            return jwks(uri, **kwargs)

        async def async_status(*args, **kwargs):
            return status(*args, **kwargs)

        monkeypatch.setattr("dnsid.manager._fetch_jwks", jwks)
        monkeypatch.setattr("dnsid.manager._fetch_strict_json_status", status)
        monkeypatch.setattr("dnsid.manager.async_fetch_jwks", async_jwks)
        monkeypatch.setattr("dnsid.manager.async_fetch_agent_status", async_status)
        state.manager = manager
        state.client = HttpSignatureProfile(manager, provider, "caller.example.com")
        state.server = HttpSignatureProfile(manager, provider, DOMAIN)
        state.policy = ResponseSignatureOptions("SERVICE.EXAMPLE.COM.")
        state.opts = HttpSigningOptions(response_signature=state.policy)
        return state
    return build


@pytest.fixture
def env(make_env, ed_provider):
    # Keep operational and entity material distinct for real VerifyDomain calls.
    return make_env(provider=ed_provider)


def prepared(env, *, method="POST", body=b"request"):
    return env.client.create_signed_http_request(
        HttpRequest(method, "https://gateway.example/api?q=one", body=body), env.opts,
    )


def signed(env, request=None, *, status=200, body=b"response", headers=None):
    request = request or prepared(env)
    response = HttpRequest("", "", headers=headers or {}, body=body, status=status)
    env.server.sign_requested_http_response(request, response)
    return request, response


def verify(env, request, response, **kwargs):
    return env.client.verify_signed_http_response(request, response, env.policy, **kwargs)


def resign(env, request, response, **changes):
    """Build a real valid signature for a boundary case, without changing the verifier."""
    params = SignatureParams.parse(response.get_header("signature-input"))
    for name, value in changes.items():
        setattr(params, name, value)
    # Do not retain parameters that the test explicitly removes.
    params.parameters = []
    base = _build_signature_base(response, params, request_context=request)
    signature = env.provider.sign(base)
    assert env.provider.signing_key().verify(base, signature)
    response.set_header("signature-input", params.serialize())
    response.set_header("signature", f"{params.label}=:{b64_std_encode(signature)}:")
    return params


def wire_request(request):
    return HttpRequest(request.method, str(request.url), dict(request.headers), request.content)


def wire_response(env, request, *, status=200, body=b"response", headers=None):
    _, response = signed(env, wire_request(request), status=status, body=body, headers=headers)
    return httpx.Response(status, headers=response.headers, content=body)


def test_option_absent_and_server_no_negotiation(env, monkeypatch):
    request = env.client.create_signed_http_request(HttpRequest("GET", "http://gateway.example/"))
    assert not request.has_header("accept-signature")
    response = HttpRequest("", "", body=b"unsigned", status=200)
    monkeypatch.setattr(env.provider, "signing_key", lambda: pytest.fail("key provider called"))
    assert env.server.sign_requested_http_response(request, response) is response
    keyless = HttpSignatureProfile(env.manager, None, "")
    assert keyless.sign_requested_http_response(request, response) is response
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as base:
        # Request-only clients continue to return unsigned HTTP errors.
        monkeypatch.undo()
        with env.client.create_signed_http_client(base) as client:
            assert client.get("http://gateway.example/").status_code == 503


def test_preparation_and_fresh_attempts(env):
    env.policy.additional_components = ["content-type", "@method;req=?1", "content-type"]
    first, second = prepared(env), prepared(env)
    for request in (first, second):
        field = http_sf.parse(request.get_header("accept-signature").encode(), tltype="dictionary")
        assert list(field) == ["sig1"]
        components, parameters = field["sig1"]
        assert list(parameters) == ["created", "expires", "nonce"]
        assert parameters["created"] is True and parameters["expires"] is True
        assert len(b64url_decode(parameters["nonce"])) >= 32
        assert b64url_encode(b64url_decode(parameters["nonce"])) == parameters["nonce"]
        assert [name for name, _ in components] == [c.split(";")[0] for c in REQUIRED] + ["content-type"]
        assert all(p.get("req") is True for _, p in components[1:7])
        signature = SignatureParams.parse(request.get_header("signature-input"))
        assert "accept-signature" in signature.components
    assert first.get_header("accept-signature") != second.get_header("accept-signature")
    assert first.get_header("signature") != second.get_header("signature")


@pytest.mark.parametrize("kind", ["domain", "http", "existing", "component", "derived", "type"])
def test_invalid_local_options_before_key_or_network(env, monkeypatch, kind):
    request = HttpRequest("GET", "https://gateway.example/")
    if kind == "domain":
        env.policy.expected_domain = "bad..example"
    elif kind == "http":
        request.url = "http://gateway.example/"
    elif kind == "existing":
        request.set_header("Accept-Signature", "caller-policy")
    elif kind == "derived":
        env.policy.additional_components = ["@method"]
    elif kind == "type":
        env.policy.additional_components = [False]
    else:
        env.policy.additional_components = ["content-type;sf"]
    before = deepcopy(request)
    monkeypatch.setattr(env.provider, "signing_key", lambda: pytest.fail("key called"))
    with pytest.raises(ArgumentError):
        env.client.create_signed_http_request(request, env.opts)
    assert request == before
    assert not env.dns_calls


def test_nondefault_reordered_and_equivalent_flags(env):
    request = prepared(env)
    field = http_sf.parse(request.get_header("accept-signature").encode(), tltype="dictionary")
    items, flags = field["sig1"]
    items.reverse()
    request.set_header("accept-signature", http_sf.ser({"reply": (items, flags)}).replace(";req", ";req=?1").replace(";created", ";created=?1").replace(";expires", ";expires=?1"))
    _, response = signed(env, request)
    params = SignatureParams.parse(response.get_header("signature-input"))
    assert params.label == "reply"
    assert params.components == list(reversed(REQUIRED))
    assert type(params.created) is int and type(params.expires) is int
    assert params.nonce == flags["nonce"]
    assert verify(env, request, response).domain == DOMAIN


def test_additional_metadata_and_standalone_policy(env):
    env.policy.additional_components = ["content-type"]
    request = prepared(env)
    response = HttpRequest("", "", body=b"data", status=200)
    with pytest.raises(VerificationError):
        env.server.sign_requested_http_response(request, response)
    assert response.headers == {}
    request, response = signed(env, request, headers={"content-type": "text/plain"})
    assert verify(env, request, response).domain == DOMAIN
    response.set_header("content-type", "text/html")
    with pytest.raises(VerificationError):
        verify(env, request, response)
    resign(env, request, response, components=REQUIRED)
    with pytest.raises(VerificationError):
        verify(env, request, response)
    env.policy.additional_components = []
    other_request, other_response = signed(env)
    other_response.set_header("content-type", "not-covered")
    assert verify(env, other_request, other_response).domain == DOMAIN
    env.policy.additional_components = ["content-type"]
    with pytest.raises(VerificationError, match="locally required"):
        verify(env, other_request, other_response)


@pytest.mark.parametrize("change", [
    lambda s: "broken",
    lambda s: s + ", " + s,
    lambda s: s + ";created",
    lambda s: s + ";nonce=\"duplicate\"",
    lambda s: s + ";extra;extra",
    lambda s: s + ";keyid=\"constraint\"",
    lambda s: s.replace('"@status"', '"@status" "@status"'),
    lambda s: s.replace('"@method";req', '"@method";req=?0'),
    lambda s: s.replace('"@method";req', '"@method";req;req'),
    lambda s: s.replace('"@status"', '"@status";sf'),
    lambda s: s.replace('"cache-control"', '"cache-control";tr'),
    lambda s: s.replace('"@status"', '"@unsupported"'),
    lambda s: s.replace('"@status"', '@status'),
    lambda s: s.replace(';created;', ';created=123;'),
    lambda s: s.replace(';expires;', ';expires=?0;'),
    lambda s: s[:s.index(';nonce=')] + ';nonce=token',
    lambda s: s[:s.index(';nonce=')] + ';nonce="AA"',
    lambda s: s[:s.index(';nonce=')] + ';nonce="' + 'A' * 43 + '="',
    lambda s: s[:s.index(';nonce=')] + ';nonce="' + 'A' * 42 + 'B"',
    lambda s: s[:s.index(';nonce=')] + ';nonce="' + 'A' * 1025 + '"',
    lambda s: s + ', other=("@status");created;expires;nonce="' + 'A' * 43 + '"',
    lambda s: s.replace(';created;', ';created=@1;'),
])
def test_strict_negotiation_rejects_atomically(env, monkeypatch, change):
    request = prepared(env)
    request.set_header("accept-signature", change(request.get_header("accept-signature")))
    response = HttpRequest("", "", {"cache-control": "private"}, b"body", 200)
    before = deepcopy(response)
    monkeypatch.setattr(env.provider, "signing_key", lambda: pytest.fail("key called"))
    with pytest.raises(VerificationError) as caught:
        env.server.sign_requested_http_response(request, response)
    assert caught.value.transient is False
    assert response == before


@pytest.mark.parametrize("method,status,content", [
    ("GET", 200, b"ordinary"), ("GET", 200, b""), ("HEAD", 200, None),
    ("GET", 204, None), ("GET", 304, None),
])
def test_content_semantics(env, method, status, content):
    request = prepared(env, method=method)
    _, response = signed(env, request, status=status, body=content, headers={"cache-control": 'private, custom="a,b"'})
    assert response.body is content
    assert response.get_header("cache-control") == 'private, custom="a,b", no-store'
    assert response.get_header("content-digest") == f"sha-256=:{b64_std_encode(hashlib.sha256(content or b'').digest())}:"
    assert verify(env, request, response).domain == DOMAIN


def test_unavailable_content(env):
    request, response = signed(env)
    response.body = None
    with pytest.raises(VerificationError, match="unavailable"):
        verify(env, request, response)
    response.headers = {}
    with pytest.raises(VerificationError, match="unavailable"):
        env.server.sign_requested_http_response(request, response)


@pytest.mark.parametrize("field", ["signature", "signature-input"])
def test_colliding_labels_and_preservation(env, field):
    request, response = signed(env)
    original = deepcopy(response)
    # A collision in either dictionary is enough, including an incomplete signature.
    response.headers = {field: original.get_header(field)}
    before = deepcopy(response)
    with pytest.raises(VerificationError, match="already exists"):
        env.server.sign_requested_http_response(request, response)
    assert response == before
    response.headers = {k: v.replace("sig1=", "other=", 1) for k, v in original.headers.items()}
    env.server.sign_requested_http_response(request, response)
    assert set(SignatureParams.parse_dictionary(response.get_header("signature-input"))) == {"other", "sig1"}
    assert verify(env, request, response).domain == DOMAIN


@pytest.mark.parametrize("failure", ["key-change", "provider", "oversize"])
def test_signing_failure_is_atomic(env, monkeypatch, failure):
    request = prepared(env)
    response = HttpRequest("", "", {"cache-control": "private"}, b"body", 200)
    if failure == "key-change":
        pair = make_ec_p256_pair("new")
        other = RealKeyProvider("new", {"new": pair})
        monkeypatch.setattr(env.provider, "sign", other.sign)
    elif failure == "provider":
        def fail(payload):
            raise ArgumentError("provider failed")
        monkeypatch.setattr(env.provider, "sign", fail)
    else:
        response.body = b"x" * (8 * 1024 * 1024 + 1)
    before = deepcopy(response)
    with pytest.raises((ArgumentError, VerificationError)):
        env.server.sign_requested_http_response(request, response)
    assert response == before


@pytest.mark.parametrize("change", [
    {"label": "wrong"}, {"nonce": "A" * 43}, {"nonce": ""},
    {"components": REQUIRED[:-1]}, {"components": list(reversed(REQUIRED))},
    {"created": None}, {"expires": None}, {"created": True}, {"alg": ""},
    {"alg": "ecdsa-p256-sha256"}, {"alg": "unsupported"},
    {"key_id": DOMAIN + "#removed"}, {"key_id": ""}, {"key_id": "bad..example#key"},
    {"key_id": DOMAIN + "#key#extra"},
])
def test_valid_crypto_cannot_bypass_negotiation_or_key_policy(env, change):
    request, response = signed(env)
    resign(env, request, response, **change)
    with pytest.raises(VerificationError):
        verify(env, request, response)


def test_missing_and_unrelated_signatures(env):
    request, response = signed(env)
    resign(env, request, response, label="unrelated")
    with pytest.raises(VerificationError):
        verify(env, request, response)
    response.headers = {}
    with pytest.raises(VerificationError):
        verify(env, request, response)


@pytest.mark.parametrize("time_case", ["old", "future", "expired", "equal", "lifetime"])
def test_freshness(env, time_case):
    request, response = signed(env)
    now = int(env.now.timestamp())
    changes = {
        "old": dict(created=now - 301, expires=now + 1),
        "future": dict(created=now + 6, expires=now + 100),
        "expired": dict(created=now - 100, expires=now - 6),
        "equal": dict(created=now, expires=now),
        "lifetime": dict(created=now, expires=now + 301),
    }
    resign(env, request, response, **changes[time_case])
    with pytest.raises(VerificationError):
        verify(env, request, response)
    assert not env.dns_calls


@pytest.mark.parametrize("target", [
    "status", "body", "cache-control", "method", "authority", "url",
    "accept-signature", "signature-input", "signature",
])
def test_request_and_response_tampering(env, target):
    request, response = signed(env)
    if target == "status":
        response.status = 201
    elif target == "body":
        response.body = b"changed"
    elif target == "cache-control":
        response.set_header(target, "private, no-store")
    elif target == "method":
        request.method = "DELETE"
    elif target == "authority":
        request.set_header("host", "other.example")
    elif target == "url":
        request.url += "&changed=yes"
    elif target == "accept-signature":
        request.set_header(target, request.get_header(target).replace("sig1=", "other="))
    else:
        request.set_header(target, request.get_header(target).replace("sig1=", "other="))
    with pytest.raises(VerificationError):
        verify(env, request, response)


@pytest.mark.parametrize("changed", ["content", "caller", "signature-params"])
def test_gateway_cannot_substitute_a_differently_signed_request(env, ec_provider, changed):
    original = prepared(env)
    gateway = deepcopy(original)
    signer = env.client
    if changed == "content":
        gateway.body = b"different operation"
    elif changed == "caller":
        signer = HttpSignatureProfile(env.manager, ec_provider, "gateway.example.com")
    signer.create_signed_http_request(gateway, HttpSigningOptions(
        additional_components=["accept-signature"], tag="changed" if changed == "signature-params" else "",
    ))
    _, response = signed(env, gateway)
    assert verify(env, gateway, response).domain == DOMAIN
    with pytest.raises(VerificationError):
        verify(env, original, response)


def test_expected_identity_before_discovery(env):
    request, response = signed(env)
    resign(env, request, response, key_id="other.example.com#k1")
    with pytest.raises(VerificationError, match="expected_domain"):
        verify(env, request, response)
    assert not env.dns_calls


def test_current_key_and_metadata(env):
    request, response = signed(env)
    pair = make_ec_p256_pair("new")
    env.jwks = JWKS(keys=[pair[1]])
    with pytest.raises(VerificationError) as caught:
        verify(env, request, response)
    assert caught.value.code is VerificationCode.KEY_NOT_FOUND
    env.manager.evict_domain(DOMAIN)
    key = deepcopy(env.provider.signing_key())
    key.alg = key._raw["alg"] = "ES256"
    env.jwks = JWKS(keys=[key])
    with pytest.raises(VerificationError):
        verify(env, request, response)


def test_status_denial_on_cache_hit(env):
    request, response = signed(env)
    assert verify(env, request, response).domain == DOMAIN
    env.status.state = "RETIRED"
    with pytest.raises(VerificationError):
        verify(env, request, response)
    assert len(env.dns_calls) == 1 and len(env.status_calls) == 2


def test_acceptance_denial_including_cache_hit(make_env, ed_provider):
    env = make_env(provider=ed_provider, trusted=[TrustedEntity("other.example")])
    request, response = signed(env)
    for _ in range(2):
        with pytest.raises(VerificationError) as caught:
            verify(env, request, response)
        assert caught.value.code is VerificationCode.COUNTERPARTY_NOT_ACCEPTED
        assert caught.value.transient is False
    assert len(env.dns_calls) == 1


def test_lifecycle_and_acquisition_errors(env, monkeypatch):
    from tests.test_verify_domain import _StubLogBinding

    def fail(*args):
        raise VerificationError(VerificationCode.RECORD_INVALID, "invalid bilateral binding")
    request, response = signed(env)
    with monkeypatch.context() as scoped:
        scoped.setattr(_StubLogBinding, "verify_bilateral_binding", fail)
        with pytest.raises(VerificationError, match="bilateral"):
            verify(env, request, response)

    def unavailable(*args, **kwargs):
        raise VerificationError(VerificationCode.STATUS_UNAVAILABLE, "status unavailable", transient=True)
    monkeypatch.setattr("dnsid.manager._fetch_strict_json_status", unavailable)
    with pytest.raises(VerificationError) as caught:
        verify(env, request, response)
    assert caught.value.transient is True


def test_mtls_current_peer_on_cache_hit(make_env, ed_provider):
    env = make_env(provider=ed_provider, fl="mtls")
    request, response = signed(env)
    good = TLSCertificate(san_dns_names=[DOMAIN])
    assert verify(env, request, response, peer_cert=good).domain == DOMAIN
    for peer in (None, TLSCertificate(san_dns_names=["wrong.example"])):
        with pytest.raises(VerificationError):
            verify(env, request, response, peer_cert=peer)
    assert len(env.dns_calls) == 1


@pytest.mark.parametrize("status", [200, 302, 404, 503])
def test_signed_client_verifies_all_statuses_and_fresh_sends(env, status):
    requests = []
    def handle(request):
        requests.append(wire_request(request))
        return wire_response(env, request, status=status, headers={"location": "https://other.example/"})
    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=True) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            request = client.build_request("POST", "https://gateway.example/", content=b"request")
            for _ in range(2):
                response = client.send(request, follow_redirects=True)
                assert response.status_code == status and response.content == b"response"
                assert not response.history
    assert len(requests) == 2
    assert requests[0].get_header("accept-signature") != requests[1].get_header("accept-signature")
    assert requests[0].get_header("signature") != requests[1].get_header("signature")


def test_unsigned_error_is_not_returned(env):
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            with pytest.raises(VerificationError):
                client.get("https://gateway.example/")


def test_sync_client_snapshot(env):
    def handle(request):
        response = wire_response(env, request)
        env.policy.expected_domain = "attacker.example"
        env.policy.additional_components.append("content-type")
        original.method = "DELETE"
        original.url = httpx.URL("https://attacker.example/")
        original.headers["accept-signature"] = "mutated"
        request.headers["signature"] = "mutated by transport"
        return response
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            original = client.build_request("GET", "https://gateway.example/")
            assert client.send(original).content == b"response"


def test_retrying_and_unknown_transports_are_rejected(env):
    with httpx.Client(transport=httpx.HTTPTransport(retries=2)) as base:
        with pytest.raises(ArgumentError, match="retries disabled"):
            env.client.create_signed_http_client(base, env.opts)
    class Replay(httpx.BaseTransport):
        def handle_request(self, request):
            pytest.fail("unsupported transport must not send")
    with httpx.Client(transport=Replay()) as base:
        with pytest.raises(ArgumentError):
            env.client.create_signed_http_client(base, env.opts)


@pytest.mark.parametrize("method,status", [("GET", 100), ("GET", 101), ("CONNECT", 200)])
def test_nonordinary_responses(env, method, status):
    request, response = signed(env)
    request.method = method
    response.status = status
    resign(env, request, response)
    with pytest.raises(VerificationError, match="ordinary final"):
        verify(env, request, response)
    response.headers = {}
    with pytest.raises(VerificationError):
        env.server.sign_requested_http_response(request, response)


@pytest.mark.parametrize("kind", ["accept", "signature", "body", "components", "labels"])
def test_resource_limits(env, kind):
    request, response = signed(env)
    if kind == "accept":
        request.set_header("accept-signature", " " * 16385)
    elif kind == "signature":
        response.set_header("signature", "a" * 65537)
    elif kind == "body":
        response.body = b"x" * (8 * 1024 * 1024 + 1)
    elif kind == "components":
        for i in range(56):
            response.set_header(f"x-{i}", "value")
        resign(env, request, response, components=REQUIRED + [f"x-{i}" for i in range(56)])
    else:
        original = response.get_header("signature-input")
        response.set_header("signature-input", ", ".join(original.replace("sig1=", f"s{i}=", 1) for i in range(17)))
    with pytest.raises(VerificationError):
        verify(env, request, response)
    assert not env.dns_calls


@pytest.mark.parametrize("cache", ["private", 'custom="x,no-store,y"', '"no-store"'])
def test_signed_cache_policy_is_required(env, cache):
    request, response = signed(env)
    response.set_header("cache-control", cache)
    resign(env, request, response)
    with pytest.raises(VerificationError, match="no-store"):
        verify(env, request, response)


def test_response_cache_reuse_rejected(env):
    cached = []
    def handle(request):
        if not cached:
            cached.append(wire_response(env, request))
        response = cached[0]
        return httpx.Response(200, headers=response.headers, content=response.content)
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            assert client.get("https://gateway.example/").content == b"response"
            with pytest.raises(VerificationError):
                client.get("https://gateway.example/")


class SyncBody(httpx.SyncByteStream):
    def __init__(self, content):
        self.content, self.closed = content, False

    def __iter__(self):
        yield self.content

    def close(self):
        self.closed = True


@pytest.mark.parametrize("failure", ["unsigned", "oversize", "deadline", "cancelled", "decoded"])
def test_sync_rejection_closes_resources(env, failure):
    body = SyncBody(b"x" * (8 * 1024 * 1024 + 1) if failure == "oversize" else b"response")
    responses = []
    cancel = threading.Event()
    def handle(request):
        response = wire_response(env, request)
        response.stream = body
        del response._content
        response.is_closed = response.is_stream_consumed = False
        if failure == "unsigned":
            response.headers.pop("signature")
        elif failure == "deadline":
            time.sleep(0.02)
        elif failure == "cancelled":
            cancel.set()
        elif failure == "decoded":
            response = httpx.Response(200, headers={"content-encoding": "gzip"}, content=gzip.compress(b"response"))
        responses.append(response)
        return response
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            with pytest.raises(VerificationError):
                with verification_budget(0.01 if failure == "deadline" else 30, cancelled=cancel):
                    client.get("https://gateway.example/")
    assert responses[0].is_closed
    assert body.closed or failure == "decoded"


def test_raw_coded_content_verified_before_decoding(env):
    raw = gzip.compress(b"response")
    body = SyncBody(raw)
    def handle(request):
        _, response = signed(env, wire_request(request), body=raw, headers={"content-encoding": "gzip"})
        return httpx.Response(200, headers=response.headers, stream=body)
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            assert client.get("https://gateway.example/").content == b"response"
    assert body.closed


@pytest.mark.asyncio
async def test_async_client_snapshot_and_verification(env):
    sent = []
    async def handle(request):
        sent.append(wire_request(request))
        result = wire_response(env, request, status=503)
        env.policy.expected_domain = "attacker.example"
        original.headers["signature"] = "mutated"
        original.method = "DELETE"
        await asyncio.sleep(0)
        return result
    async with env.client.create_signed_async_http_client(
        opts=env.opts, transport=httpx.MockTransport(handle),
    ) as client:
        original = client.build_request("POST", "https://gateway.example/", content=b"request")
        result = await client.send(original, follow_redirects=True)
        assert result.status_code == 503 and result.content == b"response"
    assert len(sent) == 1


class AsyncBody(httpx.AsyncByteStream):
    def __init__(self, content=b"response", wait=False):
        self.content, self.wait, self.closed = content, wait, False
        self.entered = asyncio.Event()

    async def __aiter__(self):
        self.entered.set()
        if self.wait:
            await asyncio.Event().wait()
        yield self.content

    async def aclose(self):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["unsigned", "oversize", "deadline", "cancelled", "success"])
async def test_async_stream_resources_and_bounds(env, failure):
    body = AsyncBody(
        b"x" * (8 * 1024 * 1024 + 1) if failure == "oversize" else b"response",
        wait=failure in {"cancelled", "deadline"},
    )
    async def handle(request):
        _, response = signed(env, wire_request(request))
        if failure == "unsigned":
            response.headers.pop("signature")
        return httpx.Response(200, headers=response.headers, stream=body)
    async with env.client.create_signed_async_http_client(opts=env.opts, transport=httpx.MockTransport(handle)) as client:
        if failure == "cancelled":
            task = asyncio.create_task(client.get("https://gateway.example/"))
            await body.entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif failure == "success":
            assert (await client.get("https://gateway.example/")).content == b"response"
        else:
            with pytest.raises(VerificationError):
                with verification_budget(0.01 if failure == "deadline" else 30):
                    await client.get("https://gateway.example/")
    assert body.closed


@pytest.mark.asyncio
async def test_async_retry_transport_rejected(env):
    async with httpx.AsyncHTTPTransport(retries=1) as transport:
        with pytest.raises(ArgumentError):
            env.client.create_signed_async_http_client(opts=env.opts, transport=transport)


@pytest.mark.asyncio
async def test_standalone_async_resolver_and_peer(env):
    request, response = signed(env)
    seen = []
    class Resolver:
        async def async_verify_domain(self, domain, peer_cert=None):
            seen.append((domain, peer_cert))
            return env.manager.verify_domain(domain, peer_cert=peer_cert)
    profile = HttpSignatureProfile(Resolver(), None, "")
    peer = TLSCertificate(san_dns_names=[DOMAIN])
    assert (await profile.async_verify_signed_http_response(request, response, env.policy, peer_cert=peer)).domain == DOMAIN
    assert seen == [(DOMAIN, peer)]


def test_es256_response_and_server_max_age(make_env):
    pair = make_ec_p256_pair("operational")
    env = make_env(provider=RealKeyProvider("operational", {"operational": pair}))
    env.server = HttpSignatureProfile(env.manager, env.provider, DOMAIN,
        config=HttpMessageSignatureConfig(max_age=datetime.timedelta(seconds=60)))
    request, response = signed(env)
    params = SignatureParams.parse(response.get_header("signature-input"))
    assert params.alg == "ecdsa-p256-sha256" and params.expires - params.created == 60
    assert verify(env, request, response).domain == DOMAIN


def test_server_requires_local_key_only_when_negotiating(env):
    request = prepared(env)
    response = HttpRequest("", "", body=b"body", status=200)
    with pytest.raises(ArgumentError):
        HttpSignatureProfile(env.manager, None, "").sign_requested_http_response(request, response)
    assert response.headers == {}


@pytest.mark.parametrize("field", ["signature", "signature-input"])
def test_self_referential_additions_are_rejected(env, field):
    env.policy.additional_components = [field]
    with pytest.raises(ArgumentError):
        prepared(env)
    env.policy.additional_components = []
    request = prepared(env)
    request.set_header(
        "accept-signature", request.get_header("accept-signature").replace(")", f' "{field}")', 1),
    )
    response = HttpRequest("", "", {}, b"response", 200)
    with pytest.raises(VerificationError):
        env.server.sign_requested_http_response(request, response)
    assert response.headers == {}


@pytest.mark.parametrize("digest", ["sha-512=:AA==:", "sha-256=:AA==:", "sha-256=token"])
def test_signed_incorrect_digest_rejected(env, digest):
    request, response = signed(env)
    response.set_header("content-digest", digest)
    resign(env, request, response)
    with pytest.raises(VerificationError):
        verify(env, request, response)


def test_equivalent_parameter_order_and_dictionary_selection(env):
    env.policy.additional_components = ['example;req;key="value"']
    request = HttpRequest("GET", "https://gateway.example/", headers={"example": 'value="metadata"'})
    env.client.create_signed_http_request(request, env.opts)
    _, response = signed(env, request)
    params = SignatureParams.parse(response.get_header("signature-input"))
    components = params.components[:-1] + ['example;key="value";req=?1']
    resign(env, request, response, components=components)
    assert verify(env, request, response).domain == DOMAIN


def test_client_preflight_rejection_and_request_cleanup(env):
    body = SyncBody(b"request")
    def handle(request):
        pytest.fail("preflight must not send")
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            request = httpx.Request("POST", "http://gateway.example/", stream=body)
            with pytest.raises(ArgumentError):
                client.send(request)
    assert body.closed


def test_auth_resend_disabled_and_timeout_shared(env):
    class ReplayAuth(httpx.Auth):
        def auth_flow(self, request):
            pytest.fail("HTTPX auth must not be invoked in negotiated mode")
            yield request
    sent = []
    def handle(request):
        sent.append(request)
        assert all(0 < timeout <= 1 for timeout in request.extensions["timeout"].values())
        return wire_response(env, request, status=401)
    with httpx.Client(transport=httpx.MockTransport(handle), auth=ReplayAuth()) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            client.auth = ReplayAuth()
            with verification_budget(1):
                assert client.get("https://gateway.example/", auth=ReplayAuth()).status_code == 401
    assert len(sent) == 1


def test_raw_decompression_is_bounded(env):
    raw = gzip.compress(b"x" * (8 * 1024 * 1024 + 1))
    body = SyncBody(raw)
    def handle(request):
        _, response = signed(env, wire_request(request), body=raw, headers={"content-encoding": "gzip"})
        return httpx.Response(200, headers=response.headers, stream=body)
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            with pytest.raises(VerificationError, match="decoded"):
                client.get("https://gateway.example/")
    assert body.closed


@pytest.mark.parametrize("async_client", [False, True])
@pytest.mark.asyncio
async def test_clients_never_reuse_previous_connection_peer(make_env, ed_provider, async_client):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    env = make_env(provider=ed_provider, fl="mtls")
    key = make_ec_p256_pair("tls")[0]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    der = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
           .public_key(key.public_key()).serial_number(1)
           .not_valid_before(env.now - datetime.timedelta(days=1))
           .not_valid_after(env.now + datetime.timedelta(days=1))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), critical=False)
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    class SSL:
        def getpeercert(self, binary):
            assert binary is True
            return der

    class Network:
        def get_extra_info(self, name):
            return SSL() if name == "ssl_object" else None

    sent = []
    def handle(request):
        response = wire_response(env, request)
        if not sent:
            response.extensions["network_stream"] = Network()
        sent.append(request)
        return response

    if async_client:
        async with env.client.create_signed_async_http_client(opts=env.opts, transport=httpx.MockTransport(handle)) as client:
            assert (await client.get("https://gateway.example/")).content == b"response"
            with pytest.raises(VerificationError):
                await client.get("https://gateway.example/")
    else:
        with httpx.Client(transport=httpx.MockTransport(handle)) as base:
            with env.client.create_signed_http_client(base, env.opts) as client:
                assert client.get("https://gateway.example/").content == b"response"
                with pytest.raises(VerificationError):
                    client.get("https://gateway.example/")
    assert len(env.dns_calls) == 1 and len(sent) == 2


@pytest.mark.parametrize("method,status", [("HEAD", 200), ("GET", 204), ("GET", 304)])
@pytest.mark.parametrize("streaming", [False, True])
def test_client_no_content_with_representation_coding(env, method, status, streaming):
    body = SyncBody(b"")
    def handle(request):
        _, response = signed(env, wire_request(request), status=status, body=None,
                             headers={"content-encoding": "gzip"})
        if streaming:
            return httpx.Response(status, headers=response.headers, stream=body)
        return httpx.Response(status, headers=response.headers, content=b"")
    with httpx.Client(transport=httpx.MockTransport(handle)) as base:
        with env.client.create_signed_http_client(base, env.opts) as client:
            assert client.request(method, "https://gateway.example/").content == b""
    assert body.closed or not streaming
