"""Default DNS resolver: DoH via explicit dns_server, or system resolver via dnspython."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ._verification_budget import (
    async_verification_operation,
    remaining_seconds,
    verification_operation,
)
from .enums import DNSSECState, VerificationCode
from .exceptions import VerificationError
from .interfaces import DNSResolver
from .models import TransportConfig, TXTRecord

if TYPE_CHECKING:
    import httpx

_MAX_DOH_BODY_BYTES = 64 * 1024


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
        if self._dns_server.startswith(("http://", "https://")):
            return self._fetch_via_doh(name)
        return self._fetch_via_dns(name)

    @async_verification_operation
    async def async_fetch_txt(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        """Fetch TXT records with native async DNS or the configured JSON DoH API.

        DNSSEC reporting matches fetch_txt. No search-domain expansion is used.
        Each DoH call owns and closes its async client, including on cancellation.
        """
        if self._dns_server.startswith(("http://", "https://")):
            return await self._async_fetch_via_doh(name)

        import dns.asyncresolver
        import dns.exception
        import dns.resolver

        try:
            resolver = dns.asyncresolver.Resolver(configure=not bool(self._dns_server))
            if self._dns_server:
                host, _, port_str = self._dns_server.rpartition(":")
                resolver.nameservers = [host or self._dns_server]
                resolver.port = int(port_str) if port_str else 53
            answers = await resolver.resolve(
                name, "TXT", lifetime=remaining_seconds(10.0), search=False
            )
            return [
                TXTRecord(strings=list(rdata.strings), ttl=int(answers.ttl)) for rdata in answers
            ], DNSSECState.UNKNOWN
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], DNSSECState.UNKNOWN
        except dns.exception.ValidationFailure:
            return [], DNSSECState.FAILED
        except VerificationError:
            raise
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

    # ------------------------------------------------------------------
    # Standard DNS path (system or host:port resolver)
    # ------------------------------------------------------------------

    def _fetch_via_dns(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        try:
            import dns.exception
            import dns.resolver
        except ImportError as exc:
            raise ImportError(
                "dnspython is required for DNS resolution. "
                "Install it with: pip install dnspython"
            ) from exc

        resolve = dns.resolver.resolve
        if self._dns_server:
            host, _, port_str = self._dns_server.rpartition(":")
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [host or self._dns_server]
            resolver.port = int(port_str) if port_str else 53
            resolve = resolver.resolve

        try:
            answers = resolve(name, "TXT", lifetime=remaining_seconds(10.0), search=False)
            txt_records: list[TXTRecord] = [
                TXTRecord(strings=list(rdata.strings), ttl=int(answers.ttl)) for rdata in answers
            ]
            return txt_records, DNSSECState.UNKNOWN
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], DNSSECState.UNKNOWN
        except dns.exception.ValidationFailure:
            return [], DNSSECState.FAILED
        except VerificationError:
            raise
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

        from .safe_transport import make_ssrf_safe_transport

        url = f"{self._dns_server}/dns-query?name={name}&type=TXT"
        try:
            with httpx.Client(transport=make_ssrf_safe_transport(self._doh_config())) as client:
                with client.stream(
                    "GET",
                    url,
                    headers={"Accept": "application/dns-json"},
                    timeout=remaining_seconds(10.0),
                ) as response:
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        remaining_seconds()
                        if len(body) + len(chunk) > _MAX_DOH_BODY_BYTES:
                            raise VerificationError(
                                VerificationCode.DNS_RESOLUTION, "DoH response body too large"
                            )
                        body.extend(chunk)
                    resp = httpx.Response(response.status_code, content=bytes(body))
        except httpx.TransportError as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DoH query failed for {name!r}: {exc}",
                transient=True,
            ) from exc

        return self._parse_doh_response(resp, name)

    async def _async_fetch_via_doh(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        import httpx

        from ._https_client import _async_read_limited
        from .safe_transport import make_ssrf_safe_async_transport

        url = f"{self._dns_server}/dns-query?name={name}&type=TXT"
        try:
            async with httpx.AsyncClient(
                transport=make_ssrf_safe_async_transport(self._doh_config()),
                follow_redirects=False,
            ) as client:
                async with client.stream(
                    "GET", url, headers={"Accept": "application/dns-json"},
                    timeout=remaining_seconds(10.0),
                ) as response:
                    body = await _async_read_limited(
                        response, _MAX_DOH_BODY_BYTES, VerificationCode.DNS_RESOLUTION,
                        "DoH response body too large",
                    )
                    resp = httpx.Response(response.status_code, content=body)
        except httpx.TransportError as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DoH query failed for {name!r}: {exc}",
                transient=True,
            ) from exc
        return self._parse_doh_response(resp, name)

    def _doh_config(self) -> TransportConfig:
        from .safe_transport import _is_ip_literal

        host = urlparse(self._dns_server).hostname or ""
        # The address guard checks IP literals directly; allowlist entries are hostnames only.
        allow = frozenset() if _is_ip_literal(host) else frozenset([host])
        return TransportConfig(private_address_hosts=allow)

    def _parse_doh_response(
        self, resp: httpx.Response, name: str
    ) -> tuple[list[TXTRecord], DNSSECState]:
        if not resp.is_success:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"DoH query returned HTTP {resp.status_code} for {name!r}",
                transient=resp.status_code >= 500,
            )

        try:
            data = resp.json()
            if not isinstance(data, dict) or type(data.get("Status", 0)) is not int:
                raise ValueError("invalid DNS response")
            status = data.get("Status", 0)
            if status not in (0, 3):
                raise VerificationError(
                    VerificationCode.DNS_RESOLUTION,
                    f"DoH query returned DNS status {status} for {name!r}",
                    transient=status == 2,
                )
            if "AD" in data and type(data["AD"]) is not bool:
                raise ValueError("invalid AD bit")
            state = (
                DNSSECState.VALID
                if self._dns_server.startswith("https://") and data.get("AD") is True
                else DNSSECState.UNKNOWN
            )
            if status == 3:  # NXDOMAIN retains the response's DNSSEC state.
                return [], state
            answers = data.get("Answer", [])
            if not isinstance(answers, list):
                raise ValueError("invalid DNS answers")
            txt_records: list[TXTRecord] = []
            for answer in answers:
                if not isinstance(answer, dict):
                    raise ValueError("invalid DNS answer")
                if answer.get("type") == 16:
                    strings = _parse_doh_txt_strings(answer.get("data", ""))
                    ttl = answer.get("TTL", 0)
                    if type(ttl) is not int or ttl < 0:
                        raise ValueError("invalid DNS TTL")
                    txt_records.append(TXTRecord(
                        strings=[s.encode("ascii") for s in strings], ttl=ttl,
                    ))
        except (ValueError, TypeError, AttributeError) as exc:
            raise VerificationError(
                VerificationCode.DNS_RESOLUTION,
                f"Invalid DoH JSON response for {name!r}: {exc}",
            ) from exc
        return txt_records, state


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
