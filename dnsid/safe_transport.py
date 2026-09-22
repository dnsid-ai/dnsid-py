"""Reusable SSRF-resistant HTTP transport for SDK-managed public reads.

The transport resolves every address for a destination, rejects the entire
resolution when any address is non-public, and connects to one of the exact
validated addresses.  This keeps validation and connection in the same layer
so a second DNS lookup cannot introduce a rebinding race.
"""

from __future__ import annotations

import ipaddress
import ssl
from collections.abc import Collection, Iterable

import httpcore
import httpx
from httpcore._backends.base import SOCKET_OPTION

from ._verification_budget import remaining_seconds
from .models import TransportConfig

SSRF_BLOCK_MARKER = "dnsid-ssrf-blocked"
"""Marker included in connection errors caused by destination policy."""


def is_disallowed_ip(ip_text: str) -> bool:
    """Return whether *ip_text* is unsafe for an SDK-managed public read."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(
        not ip.is_global
        or ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_private_or_loopback_ip(ip_text: str) -> bool:
    """Return whether *ip_text* is loopback or private-use (RFC 1918/4193).

    These are the only non-public classes a ``private_address_hosts`` match may
    resolve to; link-local, multicast, reserved, and unspecified stay rejected.
    """
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip.is_loopback:
        return True
    if ip.version == 4:
        return any(ip in net for net in _RFC1918)
    return ip in _RFC4193


_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_RFC4193 = ipaddress.ip_network("fc00::/7")


def resolve_checked_address(
    host: str,
    dns_host: str = "",
    dns_port: int = 53,
    *,
    private_address_hosts: Collection[str] = (),
    allow_loopback_host: str | None = None,
) -> str:
    """Resolve and validate every address, then return one validated address.

    Resolution failure never falls back to returning the hostname because that
    would make the network stack perform a second, unchecked lookup.
    """
    addresses = _resolve_addresses(host, dns_host, dns_port)
    if not addresses:
        raise httpcore.ConnectError(f"unable to resolve {host!r}")

    allow_private = not _is_ip_literal(host) and _matches_private_allowlist(
        host, private_address_hosts
    )
    if allow_private and any(is_disallowed_ip(address) for address in addresses):
        # A matching host may resolve non-publicly only to loopback/private-use,
        # and then every address must be: a public+private mix is rejected.
        unsafe = [a for a in addresses if not is_private_or_loopback_ip(a)]
    else:
        unsafe = [
            address
            for address in addresses
            if is_disallowed_ip(address)
            and not _is_allowed_loopback_resolution(host, address, allow_loopback_host)
        ]
    if unsafe:
        raise httpcore.ConnectError(
            f"{SSRF_BLOCK_MARKER}: {host!r} resolves to disallowed "
            f"address {unsafe[0]}"
        )
    return addresses[0]


def make_ssrf_safe_transport(
    config: TransportConfig | None = None,
    *,
    allow_loopback_host: str | None = None,
) -> httpx.BaseTransport:
    """Build an HTTP transport that connects only to validated DNS results."""
    private_address_hosts = config.private_address_hosts if config else frozenset()
    ssl_context: ssl.SSLContext | None = None
    dns_host = ""
    dns_port = 53
    if config is not None:
        if config.ca_bundle_path:
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(cafile=config.ca_bundle_path)
        dns_server = config.dns_server or ""
        if dns_server and not dns_server.startswith("http"):
            raw_host, _, port_text = dns_server.rpartition(":")
            dns_host = raw_host or dns_server
            dns_port = int(port_text) if port_text else 53

    backend = _CheckedResolveBackend(
        dns_host, dns_port, private_address_hosts, allow_loopback_host
    )
    pool = httpcore.ConnectionPool(
        ssl_context=ssl_context,
        network_backend=backend,
    )
    return _HttpcoreTransport(pool)


class _CheckedResolveBackend(httpcore.SyncBackend):
    def __init__(
        self,
        dns_host: str,
        dns_port: int,
        private_address_hosts: Collection[str],
        allow_loopback_host: str | None,
    ) -> None:
        self._dns_host = dns_host
        self._dns_port = dns_port
        self._private_address_hosts = frozenset(private_address_hosts)
        self._allow_loopback_host = allow_loopback_host

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        address = resolve_checked_address(
            host,
            self._dns_host,
            self._dns_port,
            private_address_hosts=self._private_address_hosts,
            allow_loopback_host=self._allow_loopback_host,
        )
        return _BudgetStream(super().connect_tcp(
            address, port, remaining_seconds(timeout if timeout is not None else 30.0),
            local_address, socket_options
        ))


class _BudgetStream(httpcore.NetworkStream):
    """Recompute the remaining deadline for every socket/TLS operation."""

    def __init__(self, stream: httpcore.NetworkStream) -> None:
        self._stream = stream

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._stream.read(
            max_bytes, remaining_seconds(timeout if timeout is not None else 30.0)
        )

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._stream.write(buffer, remaining_seconds(timeout if timeout is not None else 30.0))

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                  timeout: float | None = None) -> httpcore.NetworkStream:
        return _BudgetStream(self._stream.start_tls(
            ssl_context, server_hostname,
            remaining_seconds(timeout if timeout is not None else 30.0),
        ))

    def close(self) -> None:
        self._stream.close()

    def get_extra_info(self, info: str) -> object:
        return self._stream.get_extra_info(info)


class _HttpcoreTransport(httpx.BaseTransport):
    def __init__(self, pool: httpcore.ConnectionPool) -> None:
        self._pool = pool

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        from httpx._transports.default import ResponseStream, map_httpcore_exceptions

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with map_httpcore_exceptions():
            response = self._pool.handle_request(core_request)
        stream: Iterable[bytes] = response.stream  # type: ignore[assignment]
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=ResponseStream(stream),
            extensions=response.extensions,
        )

    def close(self) -> None:
        self._pool.close()


def _matches_private_allowlist(host: str, private_address_hosts: Collection[str]) -> bool:
    """Match *host* against exact entries and leading-dot suffix entries.

    ``".example.test"`` matches ``example.test`` and every name beneath it,
    label-bounded and case-insensitive. There is no built-in exemption.
    """
    normalized = _normalize_host(host)
    for entry in private_address_hosts:
        if entry.startswith("."):
            suffix = _normalize_host(entry[1:])
            if normalized == suffix or normalized.endswith("." + suffix):
                return True
        elif normalized == _normalize_host(entry):
            return True
    return False


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _normalize_host(host: str) -> str:
    """Normalize one hostname or IP literal for exact policy comparison."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host.rstrip(".").encode("idna").decode("ascii").lower()


def _resolve_addresses(host: str, dns_host: str, dns_port: int) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    if dns_host:
        return _resolve_with_dns_server(host, dns_host, dns_port)
    return _resolve_with_system(host)


def _resolve_with_system(host: str) -> list[str]:
    # dnspython honors a finite lifetime; libc getaddrinfo has no cancellation API.
    if host.rstrip(".").lower() == "localhost":
        return ["127.0.0.1", "::1"]
    return _resolve_with_dns_server(host, "", 53)


def _resolve_with_dns_server(host: str, dns_host: str, dns_port: int) -> list[str]:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=not bool(dns_host))
    if dns_host:
        resolver.nameservers = [dns_host]
        resolver.port = dns_port
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            addresses.extend(str(answer) for answer in resolver.resolve(
                host, record_type, lifetime=remaining_seconds(10.0)
            ))
        except dns.resolver.NoAnswer:
            # A hostname may legitimately have only one address family.
            continue
        except dns.exception.DNSException as exc:
            # Do not accept one family's answer when the other lookup failed:
            # that would claim to have validated every resolution result
            # without obtaining a complete DNS view.
            raise httpcore.ConnectError(f"unable to resolve {host!r}") from exc
    result = _unique_addresses(addresses)
    if result:
        return result
    raise httpcore.ConnectError(f"unable to resolve {host!r}")


def _unique_addresses(addresses: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        normalized = str(ipaddress.ip_address(address))
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _is_allowed_loopback_resolution(
    host: str,
    resolved_ip: str,
    allow_loopback_host: str | None,
) -> bool:
    if allow_loopback_host is None or host.lower() != allow_loopback_host.lower():
        return False
    try:
        return ipaddress.ip_address(resolved_ip).is_loopback
    except ValueError:
        return False
