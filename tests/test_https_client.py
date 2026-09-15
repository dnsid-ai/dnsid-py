"""Tests for _https_client redirect handling."""

from __future__ import annotations

import json
import threading

import httpx
import pytest

from dnsid._https_client import (
    _MAX_STATUS_BODY_BYTES,
    _assert_same_host_https_redirect,
    _parse_agent_status_from_dict,
    fetch_agent_status,
    fetch_jwks,
)
from dnsid.enums import VerificationCode
from dnsid.exceptions import ValidationError, VerificationError


def _status_body() -> bytes:
    return json.dumps({"state": "ACTIVE", "lastTransitionAt": "2026-01-01T00:00:00Z"}).encode()


@pytest.mark.parametrize(
    "state",
    ["PENDING", "PROVISIONING", "VERIFYING", "ACTIVE", "RETIRED"],
)
def test_protocol_agent_status_accepts_exact_canonical_state(state: str):
    status = _parse_agent_status_from_dict(
        {"state": state, "lastTransitionAt": "2026-01-01T00:00:00Z"}
    )

    status.validate()
    assert status.state == state


def test_protocol_agent_status_uses_nested_registry_protocol_status():
    status = _parse_agent_status_from_dict(
        {
            "status": "READY",
            "updated_at": "2025-01-01T00:00:00Z",
            "protocolStatus": {
                "state": "ACTIVE",
                "lastTransitionAt": "2026-01-01T00:00:00Z",
            },
        }
    )

    status.validate()
    assert status.state == "ACTIVE"
    assert status.last_transition_at.year == 2026


def test_protocol_agent_status_accepts_exact_revoked_state_with_reason():
    status = _parse_agent_status_from_dict(
        {
            "state": "REVOKED",
            "lastTransitionAt": "2026-01-01T00:00:00Z",
            "revocationReason": "keyCompromise",
        }
    )

    status.validate()
    assert status.state == "REVOKED"


@pytest.mark.parametrize(
    "state",
    [
        "READY",
        "PUBLISHED",
        "READY_FOR_PUBLICATION",
        "VERIFICATION",
        "VERIFIED",
        "PUBLISHING",
        "active",
    ],
)
def test_protocol_agent_status_does_not_reinterpret_workflow_or_normalized_state(state: str):
    status = _parse_agent_status_from_dict(
        {"state": state, "lastTransitionAt": "2026-01-01T00:00:00Z"}
    )

    assert status.state == state
    with pytest.raises(ValidationError, match="unknown agent status state"):
        status.validate()


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"state": {"malformed": True}, "lastTransitionAt": "2026-01-01T00:00:00Z"},
        {"state": "ACTIVE", "lastTransitionAt": {"malformed": True}},
        {
            "state": "REVOKED",
            "lastTransitionAt": "2026-01-01T00:00:00Z",
            "revocationReason": {"malformed": True},
        },
    ],
)
def test_protocol_agent_status_malformed_types_raise_validation_error(document: object):
    with pytest.raises(ValidationError):
        _parse_agent_status_from_dict(document).validate()


class _SequentialTransport(httpx.BaseTransport):
    """Returns pre-configured responses in order."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = iter(responses)
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return next(self._responses)


class TestRelativeRedirect:
    def test_relative_location_resolves_against_current_url(self):
        transport = _SequentialTransport(
            [
                httpx.Response(301, headers={"location": "/new/status.json"}),
                httpx.Response(200, content=_status_body()),
            ]
        )
        status = fetch_agent_status("https://agent.example.com/status", transport=transport)
        assert status.state == "ACTIVE"
        assert len(transport.requests) == 2
        assert str(transport.requests[1].url) == "https://agent.example.com/new/status.json"

    def test_relative_location_with_query_string(self):
        transport = _SequentialTransport(
            [
                httpx.Response(302, headers={"location": "/status/v2?fmt=json"}),
                httpx.Response(200, content=_status_body()),
            ]
        )
        status = fetch_agent_status("https://agent.example.com/status", transport=transport)
        assert status.state == "ACTIVE"
        assert str(transport.requests[1].url) == "https://agent.example.com/status/v2?fmt=json"

    def test_absolute_same_host_redirect_still_works(self):
        transport = _SequentialTransport(
            [
                httpx.Response(301, headers={"location": "https://agent.example.com/other"}),
                httpx.Response(200, content=_status_body()),
            ]
        )
        status = fetch_agent_status("https://agent.example.com/status", transport=transport)
        assert status.state == "ACTIVE"

    def test_cross_host_https_redirect_works(self):
        transport = _SequentialTransport(
            [
                httpx.Response(301, headers={"location": "https://api.example.com/status"}),
                httpx.Response(200, content=_status_body()),
            ]
        )
        status = fetch_agent_status("https://app.example.com/status", transport=transport)
        assert status.state == "ACTIVE"
        assert str(transport.requests[1].url) == "https://api.example.com/status"

    def test_http_redirect_raises(self):
        transport = _SequentialTransport(
            [
                httpx.Response(301, headers={"location": "http://agent.example.com/status"}),
            ]
        )
        with pytest.raises(VerificationError) as exc_info:
            fetch_agent_status("https://agent.example.com/status", transport=transport)
        assert exc_info.value.code == VerificationCode.TLS_ERROR

    @pytest.mark.parametrize(
        "location",
        [
            "https://user:pass@agent.example.com/status",
            "https://agent.example.com/status#fragment",
        ],
    )
    def test_unsafe_redirect_raises(self, location):
        transport = _SequentialTransport(
            [httpx.Response(301, headers={"location": location})]
        )
        with pytest.raises(VerificationError) as exc_info:
            fetch_agent_status("https://agent.example.com/status", transport=transport)
        assert exc_info.value.code == VerificationCode.TLS_ERROR
        assert len(transport.requests) == 1

    @pytest.mark.parametrize(
        "url",
        [
            "https://user:pass@agent.example.com/status",
            "https://agent.example.com/status#fragment",
        ],
    )
    def test_unsafe_initial_url_raises_before_fetch(self, url):
        transport = _SequentialTransport([])
        with pytest.raises(VerificationError) as exc_info:
            fetch_agent_status(url, transport=transport)
        assert exc_info.value.code == VerificationCode.TLS_ERROR
        assert transport.requests == []

    def test_domain_boundary_allows_subdomain(self):
        _assert_same_host_https_redirect(
            "https://keys.example.com/jwks", "example.com", domain_boundary=True
        )


class _ChunkStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


def test_status_body_exact_limit_succeeds():
    body = b'{"state":"ACTIVE"}'
    body += b" " * (_MAX_STATUS_BODY_BYTES - len(body))
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))

    assert fetch_agent_status("https://agent.example/status", transport=transport).state == "ACTIVE"


def test_status_body_one_byte_over_fails_while_streaming():
    body = b'{"state":"ACTIVE"}'
    body += b" " * (_MAX_STATUS_BODY_BYTES - len(body))
    stream = _ChunkStream([body, b"x", b"unread"])
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=stream)
    )

    with pytest.raises(VerificationError, match="too large") as exc_info:
        fetch_agent_status("https://agent.example/status", transport=transport)

    assert exc_info.value.code is VerificationCode.STATUS_NOT_ACTIVE
    assert stream.yielded == 2
    assert stream.closed


@pytest.mark.parametrize("status_code", [201, 204, 206])
def test_status_requires_exact_http_200(status_code: int):
    transport = httpx.MockTransport(
        lambda request: httpx.Response(status_code, content=_status_body())
    )

    with pytest.raises(VerificationError) as exc_info:
        fetch_agent_status("https://agent.example/status", transport=transport)

    assert exc_info.value.code is VerificationCode.STATUS_NOT_ACTIVE


def test_jwks_requires_exact_http_200():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(201, json={"keys": []})
    )

    with pytest.raises(VerificationError) as exc_info:
        fetch_jwks("https://agent.example/jwks", "agent.example", transport=transport)

    assert exc_info.value.code is VerificationCode.TLS_ERROR


def test_redirect_response_body_is_closed():
    redirect_stream = _ChunkStream([b"ignored"])
    transport = _SequentialTransport(
        [
            httpx.Response(
                302, headers={"location": "/new-status"}, stream=redirect_stream
            ),
            httpx.Response(200, content=_status_body()),
        ]
    )

    assert fetch_agent_status("https://agent.example/status", transport=transport).state == "ACTIVE"
    assert redirect_stream.closed


def test_shared_client_handles_concurrent_status_requests():
    barrier = threading.Barrier(32)

    def handle(request: httpx.Request) -> httpx.Response:
        barrier.wait(timeout=5)
        return httpx.Response(200, content=_status_body())

    client = httpx.Client(transport=httpx.MockTransport(handle), timeout=10)
    results: list[str] = []
    errors: list[BaseException] = []

    def fetch() -> None:
        try:
            results.append(
                fetch_agent_status(
                    "https://agent.example/status", client=client
                ).state
            )
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=fetch) for _ in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    client.close()

    assert not errors
    assert results == ["ACTIVE"] * 32


class _FakeStream:
    def __init__(self, ssl_obj):
        self._ssl_obj = ssl_obj

    def get_extra_info(self, name):
        return self._ssl_obj if name == "ssl_object" else None


class _FakeSSLObject:
    def __init__(self, der: bytes):
        self._der = der

    def getpeercert(self, binary_form=False, /):
        # Mirrors ``_ssl._SSLSocket``: the argument is positional-only.
        return self._der if binary_form else {}


def _self_signed_der(san: str) -> tuple[bytes, object]:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)])
    not_after = datetime.datetime.now(datetime.UTC).replace(microsecond=0) + datetime.timedelta(
        days=3
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - datetime.timedelta(days=4))
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER), not_after


class TestExtractTlsCert:
    """httpx exposes the TLS socket via ``extensions["network_stream"]``, not a
    top-level ``ssl_object`` extension (dropped in httpcore 0.14).  Reading the
    wrong key silently yields an empty certificate, which the freshness check
    then treats as expired, so every real-world verification failed with
    ``TLS_ERROR``."""

    def test_reads_peer_cert_from_network_stream(self):
        from dnsid._https_client import _extract_tls_cert

        der, not_after = _self_signed_der("agent.example.com")
        response = httpx.Response(
            200, extensions={"network_stream": _FakeStream(_FakeSSLObject(der))}
        )
        cert = _extract_tls_cert(response)
        assert cert.der == der
        assert cert.not_after == not_after
        assert cert.san_dns_names == ["agent.example.com"]

    def test_legacy_ssl_object_extension_still_honoured(self):
        from dnsid._https_client import _extract_tls_cert

        der, _ = _self_signed_der("agent.example.com")
        response = httpx.Response(200, extensions={"ssl_object": _FakeSSLObject(der)})
        assert _extract_tls_cert(response).der == der

    def test_transport_without_tls_yields_unknown_expiry(self):
        from dnsid._https_client import _extract_tls_cert
        from dnsid.models import TLSCertificate

        response = httpx.Response(200, extensions={"network_stream": _FakeStream(None)})
        assert _extract_tls_cert(response) == TLSCertificate()
        assert _extract_tls_cert(httpx.Response(200)) == TLSCertificate()

    def test_real_tls_connection_exposes_certificate(self, tmp_path):
        """End to end through httpx against a local TLS server."""
        import datetime
        import ssl
        from http.server import BaseHTTPRequestHandler, HTTPServer

        # Build a self-signed cert + key on disk for the server.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        from dnsid._https_client import _extract_tls_cert

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        cert_pem = tmp_path / "cert.pem"
        key_pem = tmp_path / "key.pem"
        cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_pem.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        server_ctx.load_cert_chain(cert_pem, key_pem)
        server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client_ctx = ssl.create_default_context(cafile=str(cert_pem))
            with httpx.Client(verify=client_ctx) as client:
                with client.stream(
                    "GET", f"https://localhost:{server.server_address[1]}/"
                ) as response:
                    extracted = _extract_tls_cert(response)
        finally:
            server.shutdown()
            server.server_close()

        assert extracted.der == cert.public_bytes(serialization.Encoding.DER)
        assert extracted.san_dns_names == ["localhost"]
        assert extracted.not_after == cert.not_valid_after_utc
