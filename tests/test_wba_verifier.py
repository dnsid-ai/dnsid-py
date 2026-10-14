"""DNSid WBA verification, discovery, binding, and replay policy tests."""

import datetime
from unittest.mock import MagicMock

import httpx
import pytest

from dnsid import (
    JWKS,
    HttpRequest,
    TLSCertificate,
    VerifiedDomain,
    WBAHttpSigner,
    WBAHttpVerifier,
    WebBotAuthVerificationOptions,
)
from dnsid._utils import b64_std_encode
from dnsid.enums import DNSSECState, VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.http_signatures import _build_signature_base
from dnsid.local_key_provider import LocalKeyProvider
from dnsid.models import SignatureParams
from dnsid.wba_signer import WBAVariant, serve_http_message_signatures_directory

DOMAIN = "agent.example.com"


@pytest.fixture
def setup():
    provider = LocalKeyProvider.generate()
    resolver = MagicMock()
    now = datetime.datetime.now(datetime.UTC)
    resolver.verify_domain.return_value = VerifiedDomain(
        domain=DOMAIN, record=MagicMock(v="dnsid-draft-01", ka=""),
        jwks=JWKS(keys=[provider.signing_key()]), signing_key=provider.signing_key(),
        tls_cert=TLSCertificate(), registry_status=MagicMock(), verified_at=now,
        dns_ttl=300, key_bound_at=now, last_status_check_at=now,
        dnssec_state=DNSSECState.UNKNOWN, log_reader=MagicMock(),
    )
    directory_hook = MagicMock(side_effect=lambda response: response)
    fetched = []

    def handler(request):
        fetched.append(str(request.url))
        req = HttpRequest(method="GET", url=str(request.url))
        response = directory_hook(serve_http_message_signatures_directory(req, provider))
        return httpx.Response(response.status, headers=response.headers, content=response.body)

    verifier = WBAHttpVerifier(resolver, transport=httpx.MockTransport(handler))
    req = HttpRequest(method="POST", url="https://service.example/api", body=b"hello",
                      headers={"authorization": "Bearer existing"})
    WBAHttpSigner(provider, DOMAIN, label="bot2").sign(req)
    opts = WebBotAuthVerificationOptions(signer_domain=DOMAIN)
    return provider, resolver, verifier, req, opts, directory_hook, fetched


def test_success_non_default_label_and_peer(setup):
    _, resolver, verifier, req, opts, _, fetched = setup
    opts.peer_cert = TLSCertificate()
    assert req.get_header("authorization") == "Bearer existing"
    assert verifier.verify_web_bot_auth_signed_request(req, opts) is resolver.verify_domain.return_value
    resolver.verify_domain.assert_called_once_with(DOMAIN, peer_cert=opts.peer_cert)
    assert fetched == [f"https://{DOMAIN}/.well-known/http-message-signatures-directory"]


@pytest.mark.parametrize("variant", [WBAVariant.KEY_MISMATCH, WBAVariant.TAMPERED,
                                     WBAVariant.EXPIRED, WBAVariant.NO_SIG])
def test_broken_requests(setup, variant):
    provider, _, verifier, _, opts, _, _ = setup
    req = HttpRequest(method="POST", url="https://service.example/api", body=b"hello")
    WBAHttpSigner(provider, DOMAIN).sign(req, variant)
    with pytest.raises(VerificationError):
        verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("field,value", [
    ("tag", "http-message-signatures-directory"), ("key_id", "not-a-thumbprint"),
    ("alg", "EdDSA"), ("created", None), ("expires", None),
    ("components", ["@method", 'signature-agent;key="bot2"', "content-digest"]),
    ("components", ["@authority", "content-digest"]),
    ("components", ["@authority", 'signature-agent;key="bot2"']),
])
def test_request_policy(setup, field, value):
    _, _, verifier, req, opts, _, _ = setup
    params = SignatureParams.parse(req.get_header("signature-input"))
    setattr(params, field, value)
    req.set_header("signature-input", params.serialize())
    with pytest.raises(VerificationError):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_ambiguous_complete_wba_signatures(setup):
    _, _, verifier, req, opts, _, _ = setup
    params = SignatureParams.parse(req.get_header("signature-input"))
    params.label = "other"
    req.set_header("signature-input", req.get_header("signature-input") + ", " + params.serialize())
    req.set_header("signature", req.get_header("signature") + ", other=:YWJj:")
    with pytest.raises(VerificationError, match="exactly one"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("mutation", ["signature", "digest", "coverage", "tag", "expired",
                                       "thumbprint", "private", "status", "media", "depth",
                                       "size", "keys"])
def test_invalid_directory(setup, mutation):
    _, _, verifier, req, opts, hook, _ = setup

    def corrupt(response):
        if mutation == "signature":
            response.headers["signature"] = "sig1=:YWJj:"
        elif mutation == "digest":
            response.body += b" "
        elif mutation in {"coverage", "tag", "expired"}:
            params = SignatureParams.parse(response.headers["signature-input"])
            if mutation == "coverage":
                params.components.remove("cache-control")
            elif mutation == "tag":
                params.tag = "web-bot-auth"
            else:
                params.created -= 1000
                params.expires -= 1000
            response.headers["signature-input"] = params.serialize()
        elif mutation == "thumbprint":
            response.body = response.body.replace(b'"kid":"', b'"kid":"wrong')
        elif mutation == "private":
            response.body = response.body.replace(b'"kty":', b'"d":"private","kty":')
        elif mutation == "status":
            response.status = 404
        elif mutation == "media":
            response.headers["content-type"] = "application/json"
        elif mutation == "depth":
            response.body = b"[" * 17 + b"0" + b"]" * 17
        elif mutation == "size":
            response.body = b" " * (1024 * 1024 + 1)
        elif mutation == "keys":
            response.body = b'{"keys":[' + b"{}," * 32 + b"{}]}"
        return response

    hook.side_effect = corrupt
    with pytest.raises(VerificationError):
        verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("reason", ["missing identity", "acceptance denied", "missing mtls peer"])
def test_dnsid_failure_never_falls_back(setup, reason):
    _, resolver, verifier, req, opts, _, _ = setup
    resolver.verify_domain.side_effect = VerificationError(VerificationCode.SIGNATURE_INVALID, reason)
    with pytest.raises(VerificationError, match=reason):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_each_invocation_rechecks_acceptance_and_key_state(setup):
    _, resolver, verifier, req, opts, _, fetched = setup
    verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.verify_domain.return_value.jwks = JWKS(keys=[LocalKeyProvider.generate().signing_key()])
    with pytest.raises(VerificationError, match="ku signing key"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.verify_domain.side_effect = VerificationError(VerificationCode.SIGNATURE_INVALID, "denied")
    with pytest.raises(VerificationError, match="denied"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert len(fetched) == 3


def test_final_freshness_check(setup):
    _, resolver, verifier, req, opts, _, _ = setup
    resolver.verify_domain.return_value.dns_expires_at = datetime.datetime.now(datetime.UTC)
    with pytest.raises(VerificationError, match="evidence expired"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_expiry_during_network_work(setup):
    from unittest.mock import patch

    _, _, verifier, req, opts, hook, _ = setup
    now = datetime.datetime.now(datetime.UTC)

    def advance_clock(response):
        clock.return_value = now + datetime.timedelta(minutes=10)
        return response

    hook.side_effect = advance_clock
    with patch("dnsid.wba_verifier._now", return_value=now) as clock:
        with pytest.raises(VerificationError, match="timestamps"):
            verifier.verify_web_bot_auth_signed_request(req, opts)


def test_replay_policy_and_store_failure(setup):
    _, _, verifier, req, opts, _, _ = setup
    seen = set()

    def replay(domain, keyid, nonce, retain_until):
        assert retain_until >= datetime.datetime.now(datetime.UTC).timestamp()
        identity = (domain, keyid, nonce)
        if identity in seen:
            return False
        seen.add(identity)
        return True

    opts.replay_policy = replay
    verifier.verify_web_bot_auth_signed_request(req, opts)
    with pytest.raises(VerificationError, match="nonce replay"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    opts.replay_policy = MagicMock(side_effect=RuntimeError("offline"))
    with pytest.raises(VerificationError, match="store failed"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_empty_nonce_with_replay_policy(setup):
    provider, _, verifier, req, opts, _, _ = setup
    params = SignatureParams.parse(req.get_header("signature-input"))
    params.nonce = ""
    req.set_header("signature-input", params.serialize())
    signature = provider.sign(_build_signature_base(req, params))
    req.set_header("signature", f"{params.label}=:{b64_std_encode(signature)}:")
    opts.replay_policy = MagicMock(return_value=True)
    with pytest.raises(VerificationError, match="non-empty nonce"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    opts.replay_policy.assert_not_called()


def test_discovery_requires_explicit_policy(setup):
    _, _, verifier, req, opts, _, _ = setup
    opts.signer_domain = ""
    with pytest.raises(VerificationError, match="not permitted"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    opts.allow_signature_agent_domain = True
    verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("uri,kind,path", [
    (f"https://{DOMAIN}/discard?query#fragment", "directory",
     "/.well-known/http-message-signatures-directory"),
    (f"https://{DOMAIN}/direct?query", "jwks_uri", "/direct?query"),
])
def test_discovery_types_and_out_of_band(setup, uri, kind, path):
    provider, _, verifier, req, opts, _, fetched = setup
    from dnsid import WebBotAuthSigningOptions

    req.headers.pop("signature-agent")
    WBAHttpSigner(provider, DOMAIN).sign(
        req, options=WebBotAuthSigningOptions(signature_agent=False)
    )
    opts.discovery_uri, opts.discovery_type = uri, kind
    verifier.verify_web_bot_auth_signed_request(req, opts)
    assert fetched == [f"https://{DOMAIN}{path}"]


@pytest.mark.parametrize("location", ["http://agent.example.com/", "https://127.0.0.1/",
                                        "https://other.example/", "https://localhost/"])
def test_unsafe_redirects(setup, location):
    _, resolver, _, req, opts, _, _ = setup
    transport = httpx.MockTransport(lambda request: httpx.Response(302, headers={"location": location}))
    verifier = WBAHttpVerifier(resolver, transport=transport)
    with pytest.raises(VerificationError):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_default_transport_rejects_private_resolution(setup, monkeypatch):
    _, resolver, _, req, opts, _, _ = setup
    monkeypatch.setattr("dnsid.safe_transport._resolve_addresses", lambda *args: ["10.0.0.1"])
    verifier = WBAHttpVerifier(resolver)
    with pytest.raises(VerificationError, match="fetch failed"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.verify_domain.assert_not_called()


@pytest.mark.parametrize("member", [
    '"http://agent.example.com";type=directory',
    '"https://other.example";type=directory',
    '"https://agent.example.com";type=unknown',
    '"https://agent.example.com";type="directory"',
    '"https://user@agent.example.com";type=directory',
    '"https://[";type=directory',
])
def test_rejects_untrusted_signature_agent(setup, member):
    provider, _, verifier, req, opts, _, _ = setup
    req.set_header("signature-agent", "bot2=" + member)
    params = SignatureParams.parse(req.get_header("signature-input"))
    req.set_header("signature", "bot2=:" + b64_std_encode(
        provider.sign(_build_signature_base(req, params))
    ) + ":")
    with pytest.raises(VerificationError):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_absent_discovery_type_defaults_to_directory(setup):
    provider, _, verifier, req, opts, _, _ = setup
    req.set_header("signature-agent", f'bot2="https://{DOMAIN}"')
    params = SignatureParams.parse(req.get_header("signature-input"))
    req.set_header("signature", "bot2=:" + b64_std_encode(
        provider.sign(_build_signature_base(req, params))
    ) + ":")
    verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("mode", ["success", "zero-ttl", "denied", "mtls", "directory-only"])
def test_real_dnsid_resolver_policy(ec_pair, mode):
    from dnsid import VerificationConfig
    from tests.conftest import MockDNSResolver
    from tests.test_counterparty_acceptance import DOMAIN as signer_domain
    from tests.test_counterparty_acceptance import _verifier
    from tests.test_verify_domain import _make_signed_txt_record

    manager, counters, _, patches = _verifier(
        ec_pair, VerificationConfig(trusted_entities=[] if mode == "denied" else None)
    )
    if mode == "mtls":
        private, entity = ec_pair
        manager._dns_resolver.txt = _make_signed_txt_record(
            private, entity, signer_domain, fl="mtls"
        )
    elif mode == "directory-only":
        manager._dns_resolver = MockDNSResolver()
    elif mode == "zero-ttl":
        original_lookup = manager._dns_resolver.fetch_txt

        def zero_ttl_lookup(name):
            records, state = original_lookup(name)
            for record in records:
                record.ttl = 0
            return records, state

        manager._dns_resolver.fetch_txt = zero_ttl_lookup
    provider = LocalKeyProvider.generate()

    def handler(request):
        response = serve_http_message_signatures_directory(
            HttpRequest(method="GET", url=str(request.url)), provider
        )
        return httpx.Response(response.status, headers=response.headers, content=response.body)

    verifier = WBAHttpVerifier(manager, transport=httpx.MockTransport(handler))
    req = HttpRequest(method="GET", url="https://target.example/")
    WBAHttpSigner(provider, signer_domain).sign(req)
    opts = WebBotAuthVerificationOptions(signer_domain=signer_domain)
    with patches[0] as fetch, patches[1]:
        original = fetch.side_effect

        def fetch_runtime(uri, allowed_host, **kwargs):
            jwks, cert = original(uri, allowed_host, **kwargs)
            if uri.startswith(f"https://{signer_domain}/"):
                jwks = JWKS(keys=[provider.signing_key()])
            return jwks, cert

        fetch.side_effect = fetch_runtime
        if mode in {"success", "zero-ttl"}:
            assert verifier.verify_web_bot_auth_signed_request(req, opts).domain == signer_domain
            if mode == "zero-ttl":
                assert verifier.verify_web_bot_auth_signed_request(req, opts).domain == signer_domain
                assert counters["dns"] == 2
        else:
            with pytest.raises(VerificationError) as error:
                verifier.verify_web_bot_auth_signed_request(req, opts)
            if mode == "denied":
                assert error.value.code == VerificationCode.COUNTERPARTY_NOT_ACCEPTED
            elif mode == "mtls":
                assert error.value.code == VerificationCode.TLS_ERROR


def test_deadline_covers_directory_read(setup):
    import time

    _, resolver, _, req, opts, _, _ = setup

    def slow(request):
        time.sleep(0.02)
        return httpx.Response(200, content=b"{}")

    verifier = WBAHttpVerifier(resolver, transport=httpx.MockTransport(slow))
    opts.timeout = 0.01
    with pytest.raises(VerificationError, match="deadline"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate", "gzip, identity", "identity", ""])
def test_compressed_directory_rejected_before_read(setup, encoding):
    _, resolver, _, req, opts, _, _ = setup

    class UnreadStream(httpx.SyncByteStream):
        def __iter__(self):
            pytest.fail("compressed directory must not be read or decompressed")
            yield b""  # Make this a streaming iterator without reading any bytes.

    def handler(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers={"content-encoding": encoding}, stream=UnreadStream())

    verifier = WBAHttpVerifier(resolver, transport=httpx.MockTransport(handler))
    with pytest.raises(VerificationError, match="compressed directory"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.verify_domain.assert_not_called()


@pytest.mark.parametrize("uri", ["https://bad_host.example", "https://example..com"])
def test_invalid_discovery_host_returns_verification_error(setup, uri):
    provider, resolver, verifier, req, opts, _, fetched = setup
    WBAHttpSigner(provider, DOMAIN, signature_agent=uri).sign(req)
    with pytest.raises(VerificationError, match="invalid discovery URI"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert fetched == []
    resolver.verify_domain.assert_not_called()


@pytest.mark.parametrize("uri,out_of_band", [
    (f"https://{DOMAIN}.", False),
    (f"https://{DOMAIN}.", True),
    ("https://münchen.example", True),
])
def test_discovery_host_normalization(setup, uri, out_of_band):
    from urllib.parse import urlsplit

    from dnsid import WebBotAuthSigningOptions
    from dnsid._utils import normalize_fqdn

    provider, resolver, verifier, req, opts, _, fetched = setup
    domain = normalize_fqdn(urlsplit(uri).hostname)
    resolver.verify_domain.return_value.domain = opts.signer_domain = domain
    if out_of_band:
        # Structured Fields Strings are ASCII; IDNA U-labels are tested out of band.
        req.headers.pop("signature-agent")
        WBAHttpSigner(provider, domain).sign(
            req, options=WebBotAuthSigningOptions(signature_agent=False)
        )
        opts.discovery_uri = uri
    else:
        WBAHttpSigner(provider, domain, signature_agent=uri).sign(req)
    verifier.verify_web_bot_auth_signed_request(req, opts)
    assert len(fetched) == 1
    resolver.verify_domain.assert_called_once_with(domain, peer_cert=None)


def test_injected_transport_remains_open_on_reuse_concurrency_and_failure(setup, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    _, resolver, verifier, req, opts, hook, _ = setup
    transport = verifier._transport
    close = MagicMock()
    monkeypatch.setattr(transport, "close", close)
    for _ in range(2):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    close.assert_not_called()

    barrier = Barrier(2)
    original = transport.handle_request

    def concurrent_handler(request):
        barrier.wait(timeout=5)
        return original(request)

    monkeypatch.setattr(transport, "handle_request", concurrent_handler)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: verifier.verify_web_bot_auth_signed_request(req, opts),
                                range(2)))
    assert results == [resolver.verify_domain.return_value] * 2
    close.assert_not_called()

    monkeypatch.setattr(transport, "handle_request", original)

    def corrupt(response):
        response.status = 404
        return response

    hook.side_effect = corrupt
    with pytest.raises(VerificationError):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    close.assert_not_called()


@pytest.mark.parametrize("failure", [False, True])
def test_owned_transport_is_closed(setup, monkeypatch, failure):
    _, resolver, verifier, req, opts, hook, _ = setup
    transport = verifier._transport
    close = MagicMock()
    monkeypatch.setattr(transport, "close", close)
    monkeypatch.setattr("dnsid.wba_verifier.make_ssrf_safe_transport", lambda: transport)
    owned_verifier = WBAHttpVerifier(resolver)
    if failure:
        def corrupt(response):
            response.status = 404
            return response

        hook.side_effect = corrupt
        with pytest.raises(VerificationError):
            owned_verifier.verify_web_bot_auth_signed_request(req, opts)
    else:
        owned_verifier.verify_web_bot_auth_signed_request(req, opts)
    close.assert_called_once_with()
