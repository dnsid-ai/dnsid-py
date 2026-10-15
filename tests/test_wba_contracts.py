"""Updated cross-SDK WBA policy and evidence contracts."""

import datetime
import hashlib
import json
import ssl
from unittest.mock import MagicMock

import httpx
import pytest

from dnsid import HttpRequest, WBAHttpSigner, WBAHttpVerifier, WebBotAuthSigningOptions
from dnsid._utils import b64_std_encode
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.http_signatures import _build_signature_base
from dnsid.local_key_provider import LocalKeyProvider
from dnsid.models import SignatureParams
from dnsid.wba_signer import (
    WBAVariant,
    WebBotAuthConfig,
    serve_http_message_signatures_directory,
)
from tests.test_wba_verifier import DOMAIN
from tests.test_wba_verifier import setup as setup


def _resign_directory(response, provider, *, status_component=False):
    response.headers["content-digest"] = (
        "sha-256=:" + b64_std_encode(hashlib.sha256(response.body).digest()) + ":"
    )
    params = SignatureParams.parse(response.headers["signature-input"])
    if status_component:
        params.components.append("@status")
        # Build independently of the production status extractor.
        lines = [
            f'"@authority";req: {DOMAIN}',
            '"content-type": ' + response.headers["content-type"],
            '"cache-control": ' + response.headers["cache-control"],
            '"content-digest": ' + response.headers["content-digest"],
            f'"@status": {response.status}',
            '"@signature-params": ' + params.value_string(),
        ]
        base = "\n".join(lines).encode()
    else:
        request = HttpRequest(method="GET", url=f"https://{DOMAIN}/")
        message = HttpRequest(method="GET", url=request.url, headers=response.headers,
                              body=response.body, status=response.status)
        base = _build_signature_base(message, params, request)
    response.headers["signature-input"] = params.serialize()
    response.headers["signature"] = "sig1=:" + b64_std_encode(provider.sign(base)) + ":"
    return response


@pytest.mark.parametrize("field", ["signature_ttl", "directory_signature_ttl", "clock_skew"])
@pytest.mark.parametrize("value", [True, False, float("nan"), float("inf"), float("-inf"),
                                  "5", None, 10 ** 400])
def test_invalid_numeric_configuration(field, value):
    with pytest.raises(ArgumentError):
        WebBotAuthConfig(**{field: value})


@pytest.mark.parametrize("ttl", [0, -1, 0.5, 1.5, 301, True, float("nan"), float("inf"), "5"])
def test_invalid_signing_overrides_leave_request_unchanged(setup, ttl):
    provider, _, _, req, _, _, _ = setup
    before = req.headers.copy()
    signer = WBAHttpSigner(provider, DOMAIN)
    with pytest.raises(ArgumentError):
        signer.sign(req, options=WebBotAuthSigningOptions(ttl=ttl))
    assert req.headers == before
    with pytest.raises(ArgumentError):
        WBAHttpSigner(provider, DOMAIN, expires_in_seconds=ttl)


@pytest.mark.parametrize("uri", ["https://@agent.example", "https://user:pass@agent.example",
                               "https://agent.example:bad", "https://agent.example:99999",
                               "https://[broken", "https://agent.example/",
                               "https://agent.example/custom", "https://agent.example?keys=1",
                               "https://agent.example#keys", "https://agent.example?",
                               "https://agent.example#", "https://AGENT.example",
                               "https://agent.example:443", "https://münchen.example",
                               " https://agent.example", "https://agent.example\n"])
def test_invalid_signer_discovery_uri_is_argument_error(setup, uri):
    provider, _, _, _, _, _, _ = setup
    with pytest.raises(ArgumentError):
        WBAHttpSigner(provider, DOMAIN, signature_agent=uri)


def test_verifier_snapshots_configuration_before_caller_mutation(setup):
    provider, resolver, original, req, opts, _, fetched = setup
    config = WebBotAuthConfig(clock_skew=0)
    verifier = WBAHttpVerifier(resolver, config=config, transport=original._transport)
    verifier.verify_web_bot_auth_signed_request(req, opts)
    config.clock_skew = float("nan")
    verifier.verify_web_bot_auth_signed_request(req, opts)
    WBAHttpSigner(provider, DOMAIN).sign(req, WBAVariant.EXPIRED)
    with pytest.raises(VerificationError, match="timestamps"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert len(fetched) == 2
    assert resolver.verify_domain.call_count == 2


def test_invalid_configuration_rejects_before_creating_default_pool(setup, monkeypatch):
    _, resolver, _, _, _, _, _ = setup
    factory = MagicMock()
    monkeypatch.setattr("dnsid.wba_verifier.make_ssrf_safe_transport", factory)
    config = WebBotAuthConfig()
    config.clock_skew = float("nan")
    with pytest.raises(ArgumentError):
        WBAHttpVerifier(resolver, config=config)
    factory.assert_not_called()
    resolver.verify_domain.assert_not_called()


def test_signer_snapshots_configuration_before_caller_mutation(setup):
    provider, _, verifier, req, opts, _, _ = setup
    config = WebBotAuthConfig(signature_ttl=60, signature_agent_type="directory")
    signer = WBAHttpSigner(provider, DOMAIN, config=config)
    config.clock_skew = float("nan")
    config.signature_ttl = 301
    config.signature_agent_type = "invalid"
    config.include_signature_agent = False
    signer.sign(req)
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert params.expires - params.created == 60
    assert ";type=directory" in req.get_header("signature-agent")
    verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("entry_point", ["verifier", "signer", "directory"])
@pytest.mark.parametrize("field,value", [("clock_skew", float("nan")), ("signature_ttl", 301),
                                         ("directory_signature_ttl", True),
                                         ("include_signature_agent", False)])
def test_mutated_invalid_configuration_rejects_before_work(setup, entry_point, field, value):
    provider, resolver, original, req, _, _, fetched = setup
    config = WebBotAuthConfig()
    setattr(config, field, value)
    provider = MagicMock(wraps=provider)
    with pytest.raises(ArgumentError):
        if entry_point == "verifier":
            WBAHttpVerifier(resolver, config=config, transport=original._transport)
        elif entry_point == "signer":
            WBAHttpSigner(provider, DOMAIN, config=config)
        else:
            serve_http_message_signatures_directory(req, provider, config=config)
    assert fetched == []
    resolver.verify_domain.assert_not_called()
    provider.signing_key.assert_not_called()
    provider.sign.assert_not_called()


def test_zero_skew_and_integral_numeric_ttl(setup):
    provider, _, verifier, req, opts, _, _ = setup
    config = WebBotAuthConfig(signature_ttl=60.0, directory_signature_ttl=120.0, clock_skew=0)
    WBAHttpSigner(provider, DOMAIN, config=config).sign(req)
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert type(params.expires) is int
    assert params.expires - params.created == 60
    verifier._config = config
    verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("policy", [None, "@method", [1], ["@unknown"], ["@status"],
                                    ["@authority", "@authority"], ["@method;req"],
                                    ['signature-agent;key=?1']])
def test_invalid_coverage_policy_is_argument_error_before_discovery(setup, policy):
    _, resolver, verifier, req, opts, _, fetched = setup
    opts.required_components = policy
    with pytest.raises(ArgumentError):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert fetched == []
    resolver.verify_domain.assert_not_called()


@pytest.mark.parametrize("component", ["@method", "@target-uri", "signature-agent",
                                       'signature-agent;key="other"'])
def test_missing_exact_coverage_rejects_before_discovery(setup, component):
    _, resolver, verifier, req, opts, _, fetched = setup
    opts.required_components = [component]
    with pytest.raises(VerificationError, match="required component"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert fetched == []
    resolver.verify_domain.assert_not_called()


def test_keyed_digest_cannot_skip_content_verification(setup):
    provider, resolver, verifier, req, opts, _, fetched = setup
    req.body = None
    req.set_header("content-digest", "sha-256=:YWJj:")
    WBAHttpSigner(provider, DOMAIN).sign(
        req, options=WebBotAuthSigningOptions(additional_components=['content-digest;key="sha-256"'])
    )
    with pytest.raises(VerificationError, match="requires supplied content"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert fetched == []
    resolver.verify_domain.assert_not_called()


def test_operation_coverage_is_opt_in(setup):
    provider, _, verifier, req, opts, _, _ = setup
    verifier.verify_web_bot_auth_signed_request(req, opts)
    req.url += "?a!=v!"
    required = ["@method", "@target-uri", '@query-param;name="a%21"']
    WBAHttpSigner(provider, DOMAIN).sign(
        req, options=WebBotAuthSigningOptions(additional_components=required)
    )
    opts.required_components = required + ['signature-agent;key="sig1"']
    verifier.verify_web_bot_auth_signed_request(req, opts)
    req.method = "DELETE"
    with pytest.raises(VerificationError, match="invalid WBA request signature"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("operations", [None, "verify", [], ["sign"], ["encrypt"],
                                        ["verify", "encrypt"], ["verify", "verify"], [1]])
def test_invalid_directory_key_operations_reject(setup, operations):
    provider, resolver, verifier, req, opts, hook, _ = setup

    def mutate(response):
        data = json.loads(response.body)
        data["keys"][0]["key_ops"] = operations
        response.body = json.dumps(data).encode()
        return _resign_directory(response, provider)

    hook.side_effect = mutate
    with pytest.raises(VerificationError, match="key_ops"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.verify_domain.assert_not_called()


@pytest.mark.parametrize("operations", [["verify"], ["sign", "verify"], ["verify", "sign"]])
def test_valid_directory_key_operations(setup, operations):
    provider, _, verifier, req, opts, hook, _ = setup

    def mutate(response):
        data = json.loads(response.body)
        data["keys"][0]["key_ops"] = operations
        response.body = json.dumps(data).encode()
        return _resign_directory(response, provider)

    hook.side_effect = mutate
    verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("field,value", [("use", "enc"), ("use", None), ("use", True),
                                         ("alg", "EdDSA"), ("alg", None), ("alg", True)])
def test_directory_key_metadata_is_not_discarded(setup, field, value):
    provider, resolver, verifier, req, opts, hook, _ = setup

    def mutate(response):
        data = json.loads(response.body)
        data["keys"][0][field] = value
        response.body = json.dumps(data).encode()
        return _resign_directory(response, provider)

    hook.side_effect = mutate
    with pytest.raises(VerificationError, match="invalid public directory JWK"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.verify_domain.assert_not_called()


def test_auxiliary_key_has_no_operational_authority(setup):
    provider, resolver, verifier, req, opts, _, _ = setup
    auxiliary = resolver.verify_domain.return_value.jwks.keys[0]
    assert auxiliary.thumbprint() == provider.signing_key().thumbprint()
    auxiliary.use = "enc"
    resolver.verify_domain.return_value.jwks.keys.append(LocalKeyProvider.generate().signing_key())
    with pytest.raises(VerificationError, match="current DNSid ku signing key"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_ambiguous_same_key_directory_signature_rejected(setup):
    _, _, verifier, req, opts, hook, _ = setup

    def mutate(response):
        params = SignatureParams.parse(response.headers["signature-input"])
        params.label = "other"
        response.headers["signature-input"] += ", " + params.serialize()
        response.headers["signature"] += ", other=:YWJj:"
        return response

    hook.side_effect = mutate
    with pytest.raises(VerificationError, match="exactly one matching directory signature"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_zero_ttl_acquisition_still_checks_dnsid_each_time(setup):
    _, resolver, verifier, req, opts, _, fetched = setup
    verified = resolver.verify_domain.return_value
    verified.dns_ttl = 0
    assert verified.expiry() <= datetime.datetime.now(datetime.UTC)
    verifier.verify_web_bot_auth_signed_request(req, opts)
    resolver.verify_domain.side_effect = VerificationError(VerificationCode.DNS_RESOLUTION, "no DNS")
    with pytest.raises(VerificationError, match="no DNS"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert resolver.verify_domain.call_count == len(fetched) == 2


@pytest.mark.parametrize("ttl", [0, 300])
@pytest.mark.parametrize("bound", ["tls_cert", "record_signing_tls_cert", "ka"])
def test_final_identity_bounds_include_zero_ttl(setup, ttl, bound):
    _, resolver, verifier, req, opts, _, _ = setup
    verified = resolver.verify_domain.return_value
    verified.dns_ttl = ttl
    expired = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1)
    if bound == "ka":
        verified.record.ka = "24h"
        verified.key_bound_at = expired - datetime.timedelta(days=1)
        code = VerificationCode.KEY_AGE_EXCEEDED
    else:
        from dnsid import TLSCertificate

        setattr(verified, bound, TLSCertificate(not_after=expired))
        code = VerificationCode.TLS_ERROR
    with pytest.raises(VerificationError) as error:
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert error.value.code == code
    assert not error.value.transient


def test_final_bounds_checked_after_replay_callback(setup):
    _, resolver, verifier, req, opts, _, _ = setup

    def replay(*args):
        resolver.verify_domain.return_value.tls_cert.not_after = datetime.datetime.now(datetime.UTC)
        return True

    opts.replay_policy = replay
    with pytest.raises(VerificationError) as error:
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert error.value.code == VerificationCode.TLS_ERROR


def test_fractional_skew_replay_retention_rounds_up(setup):
    _, _, verifier, req, opts, _, _ = setup
    verifier._config = WebBotAuthConfig(clock_skew=0.5)
    opts.replay_policy = MagicMock(return_value=True)
    verifier.verify_web_bot_auth_signed_request(req, opts)
    params = SignatureParams.parse(req.get_header("signature-input"))
    assert opts.replay_policy.call_args.args[-1] == params.expires + 1


@pytest.mark.parametrize("future", ["request", "directory"])
def test_future_creation_only_allows_request_skew(setup, monkeypatch, future):
    provider, resolver, verifier, req, opts, hook, _ = setup
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    monkeypatch.setattr("dnsid.wba_signer._now", lambda: now)
    monkeypatch.setattr("dnsid.wba_verifier._now", lambda: now)

    def advance(response):
        params = SignatureParams.parse(response.headers["signature-input"])
        params.created = int(now.timestamp()) + 1
        params.expires = params.created + 300
        response.headers["signature-input"] = params.serialize()
        return _resign_directory(response, provider)

    if future == "directory":
        hook.side_effect = advance
        with pytest.raises(VerificationError, match="timestamps"):
            verifier.verify_web_bot_auth_signed_request(req, opts)
        resolver.verify_domain.assert_not_called()
    else:
        WBAHttpSigner(provider, DOMAIN).sign(req)
        params = SignatureParams.parse(req.get_header("signature-input"))
        params.created += 1
        params.expires += 1
        req.set_header("signature-input", params.serialize())
        req.set_header("signature", "sig1=:" + b64_std_encode(
            provider.sign(_build_signature_base(req, params))
        ) + ":")
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_valid_directory_covers_actual_status(setup):
    provider, _, verifier, req, opts, hook, _ = setup
    hook.side_effect = lambda response: _resign_directory(response, provider, status_component=True)
    verifier.verify_web_bot_auth_signed_request(req, opts)


@pytest.mark.parametrize("status,transient", [(503, True), (500, True), (429, True), (404, False)])
def test_directory_http_error_classification(setup, status, transient):
    _, resolver, _, req, opts, _, _ = setup
    verifier = WBAHttpVerifier(resolver, transport=httpx.MockTransport(
        lambda request: httpx.Response(status)
    ))
    with pytest.raises(VerificationError) as error:
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert error.value.transient is transient
    resolver.verify_domain.assert_not_called()


@pytest.mark.parametrize("kind,transient", [("timeout", True), ("connect", True),
                                          ("tls", False), ("ssrf", False), ("protocol", False)])
def test_directory_transport_error_classification(setup, kind, transient):
    from dnsid.safe_transport import SSRF_BLOCK_MARKER

    _, resolver, _, req, opts, _, _ = setup

    def fail(request):
        if kind == "timeout":
            raise httpx.ReadTimeout("offline")
        if kind == "connect":
            raise httpx.ConnectError("unreachable")
        if kind == "tls":
            raise httpx.ConnectError("TLS handshake failed") from ssl.SSLCertVerificationError("bad TLS")
        if kind == "ssrf":
            raise httpx.ConnectError(SSRF_BLOCK_MARKER)
        raise httpx.RemoteProtocolError("malformed response")

    verifier = WBAHttpVerifier(resolver, transport=httpx.MockTransport(fail))
    with pytest.raises(VerificationError) as error:
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert error.value.transient is transient
    resolver.verify_domain.assert_not_called()


def test_distinct_directory_key_signatures_are_not_ambiguous(setup):
    from dnsid.wba_signer import wba_directory_jwk

    provider, _, verifier, req, opts, hook, _ = setup
    other = LocalKeyProvider.generate()

    def mutate(response):
        data = json.loads(response.body)
        data["keys"].append(wba_directory_jwk(other.signing_key()))
        response.body = json.dumps(data).encode()
        _resign_directory(response, provider)
        params = SignatureParams.parse(response.headers["signature-input"])
        params.label = "other"
        params.key_id = other.signing_key().thumbprint()
        response.headers["signature-input"] += ", " + params.serialize()
        response.headers["signature"] += ", other=:YWJj:"
        return response

    hook.side_effect = mutate
    verifier.verify_web_bot_auth_signed_request(req, opts)


def test_directory_signature_must_cover_received_status(setup):
    provider, _, verifier, req, opts, hook, _ = setup

    def mutate(response):
        response.status = 201
        _resign_directory(response, provider, status_component=True)
        response.status = 200
        return response

    hook.side_effect = mutate
    with pytest.raises(VerificationError, match="invalid directory signature"):
        verifier.verify_web_bot_auth_signed_request(req, opts)


def test_directory_read_uses_raw_representation(setup, monkeypatch):
    from dnsid.wba_signer import serve_http_message_signatures_directory

    provider, resolver, _, req, opts, _, _ = setup

    def handle(request):
        directory = serve_http_message_signatures_directory(
            HttpRequest(method="GET", url=str(request.url)), provider
        )
        response = httpx.Response(directory.status, headers=directory.headers,
                                  stream=httpx.ByteStream(directory.body))
        monkeypatch.setattr(response, "iter_bytes", MagicMock(
            side_effect=AssertionError("directory must not use transparent decoding")
        ))
        return response

    verifier = WBAHttpVerifier(resolver, transport=httpx.MockTransport(handle))
    verifier.verify_web_bot_auth_signed_request(req, opts)


def test_header_name_bytes_count_toward_input_limit(setup):
    _, resolver, verifier, req, opts, _, fetched = setup
    req.headers["x" * 65536] = ""
    with pytest.raises(VerificationError, match="input limit"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert fetched == []
    resolver.verify_domain.assert_not_called()
