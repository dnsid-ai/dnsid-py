"""Async DNS and transport enforce the synchronous address policy without workers."""

import asyncio
import datetime
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
import httpcore
import pytest

from dnsid import verification_budget
from dnsid._https_client import async_fetch_agent_status, async_fetch_jwks
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.models import TransportConfig
from dnsid.safe_transport import (
    SSRF_BLOCK_MARKER,
    _async_resolve_addresses,
    _AsyncBudgetStream,
    _AsyncCheckedResolveBackend,
    async_resolve_checked_address,
    make_ssrf_safe_async_transport,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("host,addresses,allow,accepted", [
    ("agent.test", ["93.184.216.34"], (), True),
    ("agent.test", ["127.0.0.1"], (), False),
    ("agent.test", ["93.184.216.34", "169.254.169.254"], (), False),
    ("agent.test", ["127.0.0.1", "10.0.0.1"], ("agent.test",), True),
    ("agent.test", ["93.184.216.34", "10.0.0.1"], ("agent.test",), False),
    ("agent.test", ["10.0.0.1", "169.254.169.254"], (".test",), False),
    ("deep.agent.test", ["10.0.0.1"], (".agent.test",), True),
    ("agent.test.attacker.test", ["10.0.0.1"], (".agent.test",), False),
    ("127.0.0.1", ["127.0.0.1"], ("127.0.0.1",), False),
    ("agent.test", ["::ffff:127.0.0.1"], (), False),
])
async def test_checked_resolution_matches_sync_policy(host, addresses, allow, accepted):
    with patch("dnsid.safe_transport._async_resolve_addresses", return_value=addresses):
        if accepted:
            assert await async_resolve_checked_address(host, private_address_hosts=allow) == addresses[0]
        else:
            with pytest.raises(httpcore.ConnectError, match=SSRF_BLOCK_MARKER):
                await async_resolve_checked_address(host, private_address_hosts=allow)


@pytest.mark.asyncio
async def test_backend_connects_to_checked_ip_without_resolving_again():
    backend = _AsyncCheckedResolveBackend("192.0.2.53", 5353, (), None)
    stream = AsyncMock(spec=httpcore.AsyncNetworkStream)
    with (
        patch("dnsid.safe_transport._async_resolve_addresses", return_value=["93.184.216.34"]) as dns_read,
        patch.object(backend._delegate, "connect_tcp", return_value=stream) as connect,
    ):
        with verification_budget(2):
            wrapped = await backend.connect_tcp("agent.test", 443, timeout=10)
        dns_read.assert_awaited_once_with("agent.test", "192.0.2.53", 5353)
        args = connect.await_args.args
        assert args[:2] == ("93.184.216.34", 443)
        assert 0 < args[2] <= 2
        await wrapped.start_tls(ssl.create_default_context(), "agent.test", 10)
        assert stream.start_tls.await_args.args[1] == "agent.test"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [dns.exception.Timeout(), dns.resolver.NXDOMAIN()])
async def test_partial_dns_failure_never_uses_only_one_family(failure):
    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=[["93.184.216.34"], failure])
    with patch("dns.asyncresolver.Resolver", return_value=resolver):
        with pytest.raises(httpcore.ConnectError):
            await _async_resolve_addresses("agent.test", "192.0.2.53", 5353)
    assert resolver.nameservers == ["192.0.2.53"]
    assert resolver.port == 5353
    assert [call.args[1] for call in resolver.resolve.await_args_list] == ["A", "AAAA"]


@pytest.mark.asyncio
async def test_dns_noanswer_is_allowed_but_empty_resolution_fails():
    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=[["93.184.216.34", "93.184.216.34"], dns.resolver.NoAnswer()])
    with patch("dns.asyncresolver.Resolver", return_value=resolver):
        assert await _async_resolve_addresses("agent.test", "", 53) == ["93.184.216.34"]
        resolver.resolve.side_effect = [dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
        with pytest.raises(httpcore.ConnectError):
            await _async_resolve_addresses("agent.test", "", 53)


@pytest.mark.asyncio
async def test_resolver_configuration_failure_is_a_connection_error():
    with patch("dns.asyncresolver.Resolver", side_effect=dns.resolver.NoResolverConfiguration()):
        with pytest.raises(httpcore.ConnectError):
            await _async_resolve_addresses("agent.test", "", 53)


@pytest.mark.asyncio
async def test_custom_routing_uses_async_dns_and_never_falls_back():
    from dnsid.manager import _AsyncDnsRoutingBackend

    backend = _AsyncDnsRoutingBackend("192.0.2.53", 5353)
    with (
        patch("dnsid.manager._async_resolve_addresses", return_value=["2606:4700:4700::1111"]) as lookup,
        patch.object(backend._delegate, "connect_tcp", new_callable=AsyncMock) as connect,
    ):
        await backend.connect_tcp("agent.test", 443, timeout=3)
        lookup.assert_awaited_once_with("agent.test", "192.0.2.53", 5353)
        assert connect.await_args.args == ("2606:4700:4700::1111", 443, 3, None, None)
        lookup.side_effect = httpcore.ConnectError("DNS failed")
        with pytest.raises(httpcore.ConnectError):
            await backend.connect_tcp("agent.test", 443)
        assert connect.await_count == 1


@pytest.mark.asyncio
async def test_real_udp_dns_lookup_uses_both_families_without_workers():
    class Server(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport
            self.types = []

        def datagram_received(self, data, peer):
            query = dns.message.from_wire(data)
            question = query.question[0]
            record_type = dns.rdatatype.to_text(question.rdtype)
            self.types.append(record_type)
            response = dns.message.make_response(query)
            response.answer.append(dns.rrset.from_text(
                question.name, 60, "IN", record_type,
                "93.184.216.34" if record_type == "A" else "2606:4700:4700::1111",
            ))
            self.transport.sendto(response.to_wire(), peer)

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(Server, local_addr=("127.0.0.1", 0))
    try:
        port = transport.get_extra_info("sockname")[1]
        with patch.object(loop, "run_in_executor", side_effect=AssertionError("unexpected worker")):
            with verification_budget(2):
                result = await _async_resolve_addresses("agent.test", "127.0.0.1", port)
        assert result == ["93.184.216.34", "2606:4700:4700::1111"]
        assert protocol.types == ["A", "AAAA"]
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_stream_recomputes_deadlines_and_preserves_tls_metadata():
    stream = AsyncMock(spec=httpcore.AsyncNetworkStream)
    stream.start_tls.return_value = stream
    stream.get_extra_info = MagicMock(return_value="tls metadata")
    wrapped = _AsyncBudgetStream(stream)
    with verification_budget(0.2):
        await wrapped.read(64, 10)
        await wrapped.write(b"request", 10)
        tls = await wrapped.start_tls(ssl.create_default_context(), "agent.test", 10)
        assert 0 < stream.read.await_args.args[1] <= 0.2
        assert 0 < stream.write.await_args.args[1] <= stream.read.await_args.args[1]
        assert 0 < stream.start_tls.await_args.args[2] <= stream.write.await_args.args[1]
        assert tls.get_extra_info("ssl_object") == "tls metadata"
        await tls.aclose()
        stream.aclose.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("trusted,host", [(True, "agent.test"), (False, "agent.test"), (True, "other.test")])
@pytest.mark.parametrize("kind", ["status", "jwks"])
async def test_real_tls_preserves_hostname_and_custom_trust(tmp_path, trusted, host, kind):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent.test")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("agent.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    names = []
    context.set_servername_callback(lambda socket, name, ctx: names.append(name))
    finished = asyncio.Event()

    async def handle(reader, writer):
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            assert b"Host: agent.test:" in headers
            body = b'{"state":"ACTIVE"}' if kind == "status" else b'{"keys":[]}'
            writer.write(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            finished.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    async with server:
        port = server.sockets[0].getsockname()[1]
        config = TransportConfig(
            ca_bundle_path=str(cert_file) if trusted else "", private_address_hosts=frozenset({host})
        )
        transport = make_ssrf_safe_async_transport(config)
        with (
            patch("dnsid.safe_transport._async_resolve_addresses", return_value=["127.0.0.1"]),
            patch.object(asyncio.get_running_loop(), "run_in_executor",
                         side_effect=AssertionError("unexpected worker")),
        ):
            call = (
                async_fetch_agent_status(f"https://{host}:{port}/status", transport=transport)
                if kind == "status" else async_fetch_jwks(
                    f"https://{host}:{port}/jwks", host, transport=transport,
                )
            )
            if trusted and host == "agent.test":
                result = await call
                if kind == "status":
                    assert result.state == "ACTIVE"
                else:
                    jwks, cert = result
                    assert jwks.keys == []
                    assert cert.der == certificate.public_bytes(serialization.Encoding.DER)
                    assert cert.san_dns_names == ["agent.test"]
                    assert cert.not_after == certificate.not_valid_after_utc
                await asyncio.wait_for(finished.wait(), 2)
            else:
                with pytest.raises(VerificationError) as error:
                    await call
                assert error.value.code == VerificationCode.TLS_ERROR
                assert not finished.is_set()
    assert names == [host]
