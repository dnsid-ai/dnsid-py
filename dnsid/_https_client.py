"""HTTPS helpers for bounded JWKS and status endpoint fetching."""

from __future__ import annotations

import datetime
import json
import ssl
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ._verification_budget import remaining_seconds, verification_operation
from .enums import VerificationCode
from .exceptions import VerificationError
from .models import JWKS, AgentStatus, TLSCertificate
from .safe_transport import SSRF_BLOCK_MARKER

_MAX_REDIRECTS = 5
_TIMEOUT = 10.0
_MAX_JWKS_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB
_MAX_STATUS_BODY_BYTES = 64 * 1024  # 64 KiB

_Verify = bool | str | ssl.SSLContext


# ---------------------------------------------------------------------------
# JWKS fetch
# ---------------------------------------------------------------------------


@verification_operation
def fetch_jwks(
    ku: str,
    allowed_host: str,
    verify: _Verify = True,
    transport: httpx.BaseTransport | None = None,
    domain_boundary: bool = False,
    client: httpx.Client | None = None,
) -> tuple[JWKS, TLSCertificate]:
    """Fetch a bounded JWKS with redirects pinned to a host or domain boundary.

    When *client* is supplied it remains caller-owned. Otherwise a finite-timeout
    client is created and closed for this call. A supplied *transport* handles TLS
    and DNS routing, so *verify* is then ignored.
    """
    from ._crypto import jwk_from_dict

    _assert_https_redirect(ku)
    owned_client = client is None
    if client is None:
        client = _create_https_client(verify=verify, transport=transport)

    url = ku
    try:
        for _ in range(_MAX_REDIRECTS + 1):
            try:
                with client.stream("GET", url, follow_redirects=False,
                                   timeout=remaining_seconds(10.0)) as response:
                    if response.is_redirect:
                        location = urljoin(url, response.headers.get("location", ""))
                        _assert_same_host_https_redirect(location, allowed_host, domain_boundary)
                        url = location
                        continue

                    tls_cert = _extract_tls_cert(response)
                    if response.status_code != 200:
                        raise VerificationError(
                            VerificationCode.TLS_ERROR,
                            f"JWKS fetch returned HTTP {response.status_code} for {url!r}",
                        )

                    body = _read_limited(
                        response,
                        _MAX_JWKS_BODY_BYTES,
                        VerificationCode.RECORD_INVALID,
                        f"JWKS response body too large for {url!r}",
                    )
            except VerificationError:
                raise
            except httpx.ConnectError as exc:
                raise VerificationError(
                    VerificationCode.TLS_ERROR,
                    f"TLS/connection error fetching JWKS at {url!r}: {exc}",
                    transient=SSRF_BLOCK_MARKER not in str(exc),
                ) from exc
            except httpx.TransportError as exc:
                raise VerificationError(
                    VerificationCode.DNS_RESOLUTION,
                    f"Network error fetching JWKS at {url!r}: {exc}",
                    transient=True,
                ) from exc

            try:
                data: dict[str, Any] = json.loads(body)
                keys = [jwk_from_dict(k) for k in data.get("keys", [])]
            except Exception as exc:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    f"JWKS response is not valid JSON for {url!r}",
                ) from exc
            return JWKS(keys=keys), tls_cert
    finally:
        if owned_client:
            client.close()

    raise VerificationError(
        VerificationCode.TLS_ERROR,
        f"Too many redirects fetching JWKS at {ku!r}",
    )


# ---------------------------------------------------------------------------
# Status endpoint fetch
# ---------------------------------------------------------------------------


@verification_operation
def fetch_agent_status(
    su: str,
    verify: _Verify = True,
    transport: httpx.BaseTransport | None = None,
    client: httpx.Client | None = None,
) -> AgentStatus:
    """Fetch and parse the bounded agent status endpoint over strict HTTPS.

    HTTPS redirects may change hosts. A supplied *client* remains caller-owned.
    Otherwise this call creates and closes a finite-timeout client.
    """
    _assert_https_redirect(su)
    owned_client = client is None
    if client is None:
        client = _create_https_client(verify=verify, transport=transport)

    url = su
    try:
        for _ in range(_MAX_REDIRECTS + 1):
            try:
                with client.stream(
                    "GET",
                    url,
                    headers={"Accept": "application/json"},
                    follow_redirects=False,
                    timeout=remaining_seconds(10.0),
                ) as response:
                    if response.is_redirect:
                        location = urljoin(url, response.headers.get("location", ""))
                        _assert_https_redirect(location)
                        url = location
                        continue

                    if response.status_code != 200:
                        raise VerificationError(
                            VerificationCode.STATUS_NOT_ACTIVE,
                            f"Status endpoint returned HTTP {response.status_code} for {url!r}",
                            transient=response.status_code >= 500,
                        )

                    body = _read_limited(
                        response,
                        _MAX_STATUS_BODY_BYTES,
                        VerificationCode.STATUS_NOT_ACTIVE,
                        f"Status response body too large for {url!r}",
                    )
            except VerificationError:
                raise
            except httpx.ConnectError as exc:
                if SSRF_BLOCK_MARKER in str(exc):
                    raise VerificationError(
                        VerificationCode.TLS_ERROR,
                        f"status endpoint {url!r} rejected: resolves to a "
                        "non-public address (SSRF guard)",
                        transient=False,
                    ) from exc
                raise VerificationError(
                    VerificationCode.TLS_ERROR,
                    f"TLS/connection error fetching status at {url!r}: {exc}",
                    transient=True,
                ) from exc
            except httpx.TransportError as exc:
                raise VerificationError(
                    VerificationCode.DNS_RESOLUTION,
                    f"Network error fetching status at {url!r}: {exc}",
                    transient=True,
                ) from exc

            try:
                data: dict[str, Any] = json.loads(body)
            except Exception as exc:
                raise VerificationError(
                    VerificationCode.STATUS_NOT_ACTIVE,
                    f"Status endpoint returned non-JSON response for {url!r}",
                ) from exc
            return _parse_agent_status_from_dict(data)
    finally:
        if owned_client:
            client.close()

    raise VerificationError(
        VerificationCode.TLS_ERROR,
        f"Too many redirects fetching status at {su!r}",
    )


def _parse_agent_status_from_dict(data: object) -> AgentStatus:
    """Parse a raw status response dict into an AgentStatus.

    Accepts protocol status documents directly or nested in a registry API
    response's ``protocolStatus`` field.
    """
    if not isinstance(data, dict):
        data = {}
    protocol_status = data.get("protocolStatus")
    if isinstance(protocol_status, dict):
        data = protocol_status
    raw_state = data.get("state") or data.get("status", "")
    last_transition_raw = data.get("lastTransitionAt") or data.get("updated_at", "")
    try:
        last_transition = datetime.datetime.fromisoformat(
            last_transition_raw.replace("Z", "+00:00")
            if isinstance(last_transition_raw, str)
            else ""
        )
    except (ValueError, AttributeError):
        last_transition = datetime.datetime.min.replace(tzinfo=datetime.UTC)

    return AgentStatus(
        state=raw_state,
        last_transition_at=last_transition,
        revocation_reason=data.get("revocationReason") or data.get("revocation_reason", ""),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _create_https_client(
    verify: _Verify = True,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """Create a finite-timeout client; its owner must close it."""
    if transport is not None:
        return httpx.Client(transport=transport, follow_redirects=False, timeout=_TIMEOUT)
    return httpx.Client(verify=verify, follow_redirects=False, timeout=_TIMEOUT)


def _read_limited(
    response: httpx.Response,
    limit: int,
    code: VerificationCode,
    message: str,
) -> bytes:
    """Read at most *limit* decoded bytes without buffering an oversized body."""
    body = bytearray()
    for chunk in response.iter_bytes():
        remaining_seconds()
        if len(body) + len(chunk) > limit:
            raise VerificationError(code, message)
        body.extend(chunk)
    return bytes(body)


def _assert_https_redirect(location: str) -> None:
    """Require an absolute HTTPS URL without credentials or a fragment."""
    try:
        parsed = urlparse(location)
        parsed.port
    except ValueError as exc:
        raise VerificationError(
            VerificationCode.TLS_ERROR,
            f"Invalid HTTPS URL {location!r}: {exc}",
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or "#" in location
    ):
        raise VerificationError(
            VerificationCode.TLS_ERROR,
            f"URL must be absolute HTTPS without credentials or a fragment: {location!r}",
        )


def _assert_same_host_https_redirect(
    location: str, allowed_host: str, domain_boundary: bool = False
) -> None:
    """Reject redirects outside the selected HTTPS host boundary."""
    from ._utils import normalize_fqdn

    _assert_https_redirect(location)
    parsed = urlparse(location)
    if parsed.hostname:
        try:
            redir_host = normalize_fqdn(parsed.hostname)
        except Exception:
            redir_host = parsed.hostname.lower()
        if redir_host != allowed_host and not (
            domain_boundary and redir_host.endswith("." + allowed_host)
        ):
            raise VerificationError(
                VerificationCode.TLS_ERROR,
                f"Redirect changes host from {allowed_host!r} to {redir_host!r}",
            )


def _peer_ssl_object(response: httpx.Response) -> Any:
    """Return the TLS socket behind *response*, or None when there is none.

    httpx exposes the socket through the ``network_stream`` extension
    (``get_extra_info("ssl_object")``); it has not published a top-level
    ``ssl_object`` extension since httpcore 0.14.  The legacy key is still
    honoured so a custom transport can hand the socket over directly.
    """
    stream = response.extensions.get("network_stream")
    if stream is not None:
        try:
            ssl_obj = stream.get_extra_info("ssl_object")
        except Exception:
            ssl_obj = None
        if ssl_obj is not None:
            return ssl_obj
    return response.extensions.get("ssl_object")


def _extract_tls_cert(response: httpx.Response) -> TLSCertificate:
    """Extract TLS certificate details from an httpx response, if available."""
    try:
        ssl_obj = _peer_ssl_object(response)
        if ssl_obj is None:
            return TLSCertificate()

        # Positional on purpose: httpx hands back the low-level
        # ``_ssl._SSLSocket``, whose getpeercert() rejects keyword arguments.
        cert_der: bytes | None = ssl_obj.getpeercert(True)
        if not cert_der:
            return TLSCertificate()

        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = [n.value for n in san_ext.value if isinstance(n, x509.DNSName)]
        except x509.ExtensionNotFound:
            dns_names = []

        return TLSCertificate(
            not_after=cert.not_valid_after_utc,
            san_dns_names=dns_names,
            der=cert_der,
        )
    except Exception:
        return TLSCertificate()
