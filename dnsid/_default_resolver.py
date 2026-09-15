"""Default DNS resolver: DoH via explicit dns_server, or system resolver via dnspython."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ._verification_budget import remaining_seconds, verification_operation
from .enums import DNSSECState, VerificationCode
from .interfaces import DNSResolver
from .models import TXTRecord

if TYPE_CHECKING:
    pass


class DefaultDNSResolver(DNSResolver):
    """Default DNSResolver used when none is supplied to IdentityManager.

    - When dns_server is an HTTP(S) URL: queries its provider-specific JSON DNS API.
      Over HTTPS, returns VALID when the AD bit is true in the response and UNKNOWN
      otherwise. Over plain HTTP, always returns UNKNOWN because the AD bit is not
      trustworthy without an authenticated channel.
      DNS response errors, including SERVFAIL, are reported as resolution errors
      because the status code alone is not proof of DNSSEC validation failure.
    - Otherwise: uses the host language/runtime resolver via dnspython. Always returns
      UNKNOWN because the system resolver does not reliably expose the AD bit. SERVFAIL
      is mapped to a transient VerificationError so verify_domain aborts rather than
      proceeding with an unvalidated answer.

    registry_url MUST NOT influence DNS resolution — it is a control-plane API URL only.
    This behavior is an SDK convenience and is not part of the DNSid protocol.
    """

    def __init__(self, dns_server: str = "") -> None:
        self._dns_server = dns_server.rstrip("/") if dns_server else ""

    @verification_operation
    def fetch_txt(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        if self._dns_server:
            if self._dns_server.startswith("http://") or self._dns_server.startswith("https://"):
                return self._fetch_via_doh(name)
            return self._fetch_via_standard_dns(name)
        return self._fetch_via_system(name)

    # ------------------------------------------------------------------
    # Standard DNS path (host:port address)
    # ------------------------------------------------------------------

    def _fetch_via_standard_dns(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        try:
            import dns.exception
            import dns.resolver
        except ImportError as exc:
            raise ImportError(
                "dnspython is required for the standard DNS resolver path. "
                "Install it with: pip install dnspython"
            ) from exc

        from .exceptions import VerificationError

        raw = self._dns_server
        host, _, port_str = raw.rpartition(":")
        dns_host = host or raw
        dns_port = int(port_str) if port_str else 53

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_host]
        resolver.port = dns_port

        try:
            answers = resolver.resolve(name, "TXT", lifetime=remaining_seconds(10.0))
            txt_records: list[TXTRecord] = [
                TXTRecord(strings=list(rdata.strings), ttl=int(answers.ttl)) for rdata in answers
            ]
            return txt_records, DNSSECState.UNKNOWN
        except dns.resolver.NXDOMAIN:
            return [], DNSSECState.UNKNOWN
        except dns.resolver.NoAnswer:
            return [], DNSSECState.UNKNOWN
        except dns.exception.Timeout as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DNS timeout for {name!r}",
                transient=True,
            ) from exc
        except Exception as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DNS error for {name!r}: {exc}",
                transient=True,
            ) from exc

    # ------------------------------------------------------------------
    # Provider-specific JSON DNS path
    # ------------------------------------------------------------------

    def _fetch_via_doh(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        import httpx

        from .exceptions import VerificationError

        url = f"{self._dns_server}/dns-query?name={name}&type=TXT"
        from urllib.parse import urlparse

        from .models import TransportConfig
        from .safe_transport import make_ssrf_safe_transport

        config = TransportConfig(private_address_hosts=frozenset([urlparse(url).hostname or ""]))
        try:
            with httpx.Client(transport=make_ssrf_safe_transport(config)) as client:
                with client.stream("GET", url, headers={"Accept": "application/dns-json"},
                                   timeout=remaining_seconds(10.0)) as response:
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        remaining_seconds()
                        if len(body) + len(chunk) > 64 * 1024:
                            raise VerificationError(VerificationCode.DNS_RESOLUTION,
                                                    "DoH response body too large")
                        body.extend(chunk)
                    resp = httpx.Response(response.status_code, content=bytes(body))
        except httpx.TransportError as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DoH query failed for {name!r}: {exc}",
                transient=True,
            ) from exc

        if not resp.is_success:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DoH query returned HTTP {resp.status_code} for {name!r}",
                transient=resp.status_code >= 500,
            )

        _MAX_DOH_BODY = 64 * 1024
        if len(resp.content) > _MAX_DOH_BODY:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DoH response body too large for {name!r}",
            )

        data: dict[str, Any] = resp.json()

        status = data.get("Status", 0)
        if status != 0:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DoH query returned DNS status {status} for {name!r}",
                transient=status == 2,
            )

        dnssec_state = (
            DNSSECState.VALID
            if self._dns_server.startswith("https://") and data.get("AD")
            else DNSSECState.UNKNOWN
        )

        txt_records: list[TXTRecord] = []
        for answer in data.get("Answer", []):
            if answer.get("type") == 16:  # DNS TXT record type number
                strings = _parse_doh_txt_strings(answer.get("data", ""))
                txt_records.append(
                    TXTRecord(
                        strings=[s.encode("ascii") for s in strings],
                        ttl=answer.get("TTL", 300),
                    )
                )

        return txt_records, dnssec_state

    # ------------------------------------------------------------------
    # System resolver path (dnspython)
    # ------------------------------------------------------------------

    def _fetch_via_system(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        try:
            import dns.exception
            import dns.resolver
        except ImportError as exc:
            raise ImportError(
                "dnspython is required for the system DNS resolver path. "
                "Install it with: pip install dnspython"
            ) from exc

        from .exceptions import VerificationError

        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=remaining_seconds(10.0))
            txt_records: list[TXTRecord] = [
                TXTRecord(strings=list(rdata.strings), ttl=int(answers.ttl)) for rdata in answers
            ]
            # System resolver does not expose the AD bit — always UNKNOWN.
            return txt_records, DNSSECState.UNKNOWN

        except dns.resolver.NXDOMAIN:
            return [], DNSSECState.UNKNOWN

        except dns.resolver.NoAnswer:
            return [], DNSSECState.UNKNOWN

        except dns.resolver.NoNameservers as exc:
            # NoNameservers covers SERVFAIL; treat conservatively as transient.
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DNS lookup failed for {name!r}: {exc}",
                transient=True,
            ) from exc

        except dns.exception.Timeout as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DNS lookup timed out for {name!r}",
                transient=True,
            ) from exc

        except Exception as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DNS lookup error for {name!r}: {exc}",
                transient=True,
            ) from exc


# ---------------------------------------------------------------------------
# DoH TXT string parsing
# ---------------------------------------------------------------------------

_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _parse_doh_txt_strings(data: str) -> list[str]:
    """Parse DoH JSON TXT RDATA into DNS string components.

    DoH JSON (RFC 8484) represents TXT RDATA as one or more double-quoted strings,
    e.g.: `"v=DNSid1" "more data"` or `"v=DNSid1; gi=example.com"`.
    """
    parts = [
        m.group(1).replace('\\"', '"').replace("\\\\", "\\") for m in _QUOTED_RE.finditer(data)
    ]
    # If no quoted strings were found, treat the whole value as a single unquoted string.
    return parts if parts else [data]
