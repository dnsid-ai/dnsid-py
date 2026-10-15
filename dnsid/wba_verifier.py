"""DNSid WBA verification for draft-ietf-webbotauth-httpsig-protocol-00.

Directory self-signatures are never a substitute for DNSid verification and
configured entity acceptance. No directory evidence is cached. Without a replay
policy, valid requests can be reused until their signatures expire.
"""

from __future__ import annotations

import json
import math
import re
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit

import http_sf
import httpx

from ._https_client import _assert_same_host_https_redirect, _read_limited
from ._utils import b64url_decode, b64url_encode, normalize_fqdn
from ._verification_budget import remaining_seconds, verification_budget
from .enums import VerificationCode
from .exceptions import ArgumentError, ParseError, ValidationError, VerificationError
from .http_signatures import (
    _build_signature_base,
    _check_content_digest,
    _now,
    _parse_signature_dictionary,
)
from .interfaces import RefreshingIdentityResolver
from .models import (
    JWK,
    HttpRequest,
    SignatureParams,
    TLSCertificate,
    VerifiedDomain,
    _parse_component_identifier,
    _parse_sf_dictionary,
    _validate_component_identifiers,
)
from .safe_transport import SSRF_BLOCK_MARKER, make_ssrf_safe_transport
from .wba_signer import (
    WBA_DIRECTORY_MEDIA_TYPE,
    WBA_DIRECTORY_TAG,
    WBA_DIRECTORY_WELL_KNOWN_PATH,
    WBA_TAG,
    WebBotAuthConfig,
    _is_https_origin,
    _wba_identifier,
)


@dataclass
class WebBotAuthVerificationOptions:
    """Trusted per-invocation WBA policy.

    Without ``signer_domain``, discovery can identify the signer only when
    ``allow_signature_agent_domain`` is explicitly enabled. Discovery must remain
    on that signer's host; redirects and delegation are not supported.
    ``discovery_uri``, when supplied, constrains the signed discovery URL; it
    cannot replace the required covered Signature-Agent member.

    ``required_components`` adds application coverage requirements, defaulting
    to none. Equality compares component names and parameter values. Malformed
    policy raises ArgumentError; missing coverage rejects before discovery.

    ``replay_policy(domain, keyid, nonce, retain_until)`` must atomically record
    an unused tuple through the supplied Unix timestamp and return True, or
    return False for reuse. Exceptions fail closed. Blocking callbacks and
    injected resolvers must honor the shared verification budget.
    """

    signer_domain: str = ""
    discovery_uri: str = ""
    discovery_type: str = "directory"
    allow_signature_agent_domain: bool = False
    peer_cert: TLSCertificate | None = None
    timeout: float = 30.0
    replay_policy: Callable[[str, str, str, int], bool] | None = None
    #: Additional exact request components required before discovery.
    required_components: list[str] = field(default_factory=list)


def _component_identity(component: str) -> tuple[str, frozenset[tuple[str, Any]]]:
    name, parameters = _parse_component_identifier(component)
    return name, frozenset(parameters)


def _reject(message: str) -> NoReturn:
    raise VerificationError(VerificationCode.SIGNATURE_INVALID, message)


def _signatures(message: HttpRequest, tag: str) -> list[tuple[SignatureParams, bytes]]:
    if (
        sum(len(name) + len(value) for name, value in message.headers.items()) > 65536
        or (message.body is not None and len(message.body) > 8 * 1024 * 1024)
    ):
        _reject("WBA input limit exceeded")
    inputs = message.get_header("signature-input")
    signatures = message.get_header("signature")
    if not inputs or not signatures:
        _reject("missing WBA signature fields")
    params = SignatureParams.parse_dictionary(inputs)
    raw = _parse_signature_dictionary(signatures)
    if len(params) > 16 or len(raw) > 16 or any(
        len(item.components) > 64 for item in params.values()
    ):
        _reject("WBA signature count or component limit exceeded")
    return [(item, raw[label]) for label, item in params.items()
            if label in raw and item.tag == tag]


def _check_time(params: SignatureParams, skew: int | float, *, directory: bool = False) -> None:
    now = _now().timestamp()
    if (
        type(params.created) is not int or type(params.expires) is not int
        or not 0 <= params.expires - params.created <= 300
        or params.created > now + (0 if directory else skew) or now > params.expires + skew
        or params.alg != "ed25519"
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.key_id)
        or b64url_encode(b64url_decode(params.key_id)) != params.key_id
    ):
        _reject("invalid WBA timestamps, algorithm, or thumbprint")


def _directory_url(uri: str, discovery_type: str) -> str:
    try:
        parsed = urlsplit(uri)
        parsed.port
        host = normalize_fqdn(parsed.hostname or "")
    except (ValueError, ValidationError) as exc:
        raise VerificationError(VerificationCode.TLS_ERROR, "invalid discovery URI") from exc
    if discovery_type == "directory":
        if not _is_https_origin(uri):
            _reject("Signature-Agent directory URI must be an ASCII HTTPS origin")
        uri += WBA_DIRECTORY_WELL_KNOWN_PATH
    elif discovery_type != "jwks_uri":
        _reject("unsupported Signature-Agent discovery type")
    # Validate the original credentials too, including an empty username.
    if parsed.username is not None or parsed.password is not None:
        _reject("Signature-Agent credentials are forbidden")
    _assert_same_host_https_redirect(uri, host)
    return uri


def _bounded_json(body: bytes) -> dict[str, Any]:
    # Bound nesting before decoding to prevent recursive JSON allocation.
    depth = 0
    quoted = escaped = False
    for byte in body:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                _reject("directory JSON depth exceeded")
        elif byte in (93, 125):
            depth -= 1
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise VerificationError(VerificationCode.RECORD_INVALID, "invalid directory JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        _reject("directory must contain a JWKS key array")
    if not 1 <= len(data["keys"]) <= 32:
        _reject("directory key count limit exceeded")
    return cast(dict[str, Any], data)


class _BorrowedTransport(httpx.BaseTransport):
    """Let a temporary client use a caller-owned transport without closing it."""

    def __init__(self, transport: httpx.BaseTransport) -> None:
        self._transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._transport.handle_request(request)


class WBAHttpVerifier:
    """Verify DNSid WBA requests and their signed directories.

    Construction needs no local identity or signing key. The default transport
    validates Web PKI and pins connections to public DNS addresses. An injected
    transport is trusted infrastructure and MUST enforce the same constraints,
    on every connection, reject redirects, and honor remaining_seconds().
    Injected transports must preserve uncoded response bytes and fields, without
    transparent decompression. Directories are fetched unconditionally with
    Cache-Control: no-cache on every invocation; injected caches must revalidate
    and must never serve stale evidence. No local directory cache is maintained.
    A verified key mismatch permits one DNSid refresh per domain per five seconds;
    concurrent retries are suppressed, failures consume the allowance, and at
    most 1024 active/cooldown domains are retained. No stale-key fallback is allowed.
    The default secure transport and its connection pool are reused until close().
    Call close() after all verification operations finish. Injected transports
    remain caller-owned and must support concurrent use when the verifier is
    shared. The caller manages their initialization and closure.

    Requests are buffered: hosts must enforce the 8 MiB body and 64 KiB header
    limits while reading. Directory reads are limited to 1 MiB, 32 keys, JSON
    depth 16, and 16 signatures. Redirects are rejected. Responses with
    any Content-Encoding field are rejected before reading. The complete
    operation has a default 30-second cooperative deadline.
    """

    def __init__(
        self, resolver: RefreshingIdentityResolver, *, config: WebBotAuthConfig | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Set the resolver and transport; copy and validate the configuration."""
        if not isinstance(resolver, RefreshingIdentityResolver):
            raise ArgumentError("WBA requires a RefreshingIdentityResolver")
        self._resolver = resolver
        self._refresh_lock = threading.Lock()
        self._refresh_deadlines: dict[str, float] = {}
        self._config = replace(config) if config is not None else WebBotAuthConfig()
        self._transport = transport if transport is not None else make_ssrf_safe_transport()
        self._owns_transport = transport is None
        self._closed = False

    def close(self) -> None:
        """Release the owned connection pool; never close an injected transport.

        Call only after in-flight verifications finish. Repeated calls are safe;
        verification after closure raises RuntimeError.
        """
        if not self._closed:
            self._closed = True
            if self._owns_transport:
                self._transport.close()

    def verify_web_bot_auth_signed_request(
        self, req: HttpRequest, opts: WebBotAuthVerificationOptions | None = None,
    ) -> VerifiedDomain:
        """Return the signer only after request, directory, and DNSid checks succeed.

        Args:
            req: Buffered application request, including exact supplied content.
            opts: Trusted discovery, application peer, deadline, and replay policy.

        Returns:
            Verified DNSid signer identity, not application authorization.

        Raises:
            ArgumentError: On malformed required-component policy or invalid deadline.
            VerificationError: On invalid evidence, discovery, acceptance, or replay.
            RuntimeError: If the verifier has been closed.
        """
        if self._closed:
            raise RuntimeError("WBA verifier is closed")
        opts = opts or WebBotAuthVerificationOptions()
        with verification_budget(opts.timeout):
            try:
                return self._verify(req, opts)
            except (ParseError, ValidationError, ValueError) as exc:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID, "invalid WBA evidence",
                ) from exc

    def _verify(self, req: HttpRequest, opts: WebBotAuthVerificationOptions) -> VerifiedDomain:
        if not isinstance(opts.required_components, list) or any(
            not isinstance(component, str) for component in opts.required_components
        ):
            raise ArgumentError("required_components must be a list of component identifiers")
        try:
            _validate_component_identifiers(opts.required_components, request_context=False)
        except VerificationError as exc:
            raise ArgumentError(f"invalid required_components policy: {exc}") from exc
        candidates = _signatures(req, WBA_TAG)
        if len(candidates) != 1:
            _reject("expected exactly one complete WBA request signature")
        params, signature = candidates[0]
        _check_time(params, self._config.clock_skew)
        if "@authority" not in params.components:
            _reject("WBA request requires exact @authority coverage")
        covered = {_component_identity(component) for component in params.components}
        if any(
            _component_identity(component) not in covered for component in opts.required_components
        ):
            _reject("WBA request missing required component coverage")
        _check_content_digest(req, params)
        request_base = _build_signature_base(req, params)
        if not req.has_header("signature-agent"):
            _reject("missing required Signature-Agent")
        selected = []
        for component in params.components:
            name, parameters = _parse_component_identifier(component)
            if name == "signature-agent" and set(dict(parameters)) == {"key"}:
                selected.append(dict(parameters)["key"])
        if len(selected) != 1:
            _reject("Signature-Agent requires exactly one covered member")
        try:
            value, attributes = _parse_sf_dictionary(req.get_header("signature-agent"))[selected[0]]
            if type(value) is not str:
                raise ValueError("URI must be a String")
            kind = attributes.get("type", http_sf.Token("directory"))
            if not isinstance(kind, http_sf.Token):
                raise ValueError("type must be a Token")
        except (ValueError, KeyError, TypeError) as exc:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "invalid Signature-Agent member"
            ) from exc
        url = _directory_url(value, str(kind))
        if opts.discovery_uri and _wba_identifier(url) != _wba_identifier(
            _directory_url(opts.discovery_uri, opts.discovery_type)
        ):
            _reject("Signature-Agent does not match trusted discovery URI")
        host = normalize_fqdn(urlsplit(url).hostname or "")
        if not opts.signer_domain and not opts.allow_signature_agent_domain:
            _reject("Signature-Agent signer discovery is not permitted")
        domain = normalize_fqdn(opts.signer_domain) if opts.signer_domain else host
        if domain != host:
            _reject("cross-host WBA delegation is unsupported")
        directory_request, response = self._fetch(url, domain)
        if response.get_header("content-type").split(";", 1)[0].strip().lower() != (
            WBA_DIRECTORY_MEDIA_TYPE
        ):
            _reject("invalid directory media type")
        data = _bounded_json(response.body or b"")
        keys = []
        for raw in data["keys"]:
            if (
                not isinstance(raw, dict) or raw.get("kty") != "OKP"
                or raw.get("crv") != "Ed25519" or "d" in raw
                or raw.get("alg", "ed25519") != "ed25519"
                or raw.get("use", "sig") != "sig"
                or not isinstance(raw.get("x"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", raw["x"])
                or b64url_encode(b64url_decode(raw["x"])) != raw["x"]
            ):
                _reject("invalid public directory JWK")
            if "key_ops" in raw:
                operations = raw["key_ops"]
                if (
                    not isinstance(operations, list)
                    or not all(isinstance(operation, str) for operation in operations)
                    or "verify" not in operations
                    or len(set(operations)) != len(operations)
                    or not set(operations).issubset({"sign", "verify"})
                ):
                    _reject("invalid directory JWK key_ops")
            key = JWK.from_dict({**raw, "alg": "EdDSA"})
            if key.thumbprint() != raw.get("kid"):
                _reject("directory kid does not match its thumbprint")
            if raw["kid"] == params.key_id:
                keys.append(key)
        if len(keys) != 1:
            _reject("expected exactly one matching directory key")
        key = keys[0]
        directory_candidates = [
            (item, raw) for item, raw in _signatures(response, WBA_DIRECTORY_TAG)
            if item.key_id == params.key_id
        ]
        if len(directory_candidates) != 1:
            _reject("expected exactly one matching directory signature")
        directory_params, directory_signature = directory_candidates[0]
        _check_time(directory_params, self._config.clock_skew, directory=True)
        required = {"@authority;req", "content-type", "cache-control", "content-digest"}
        if not required.issubset(directory_params.components):
            _reject("directory signature missing required coverage")
        _check_content_digest(response, directory_params)
        if not key.verify(
            _build_signature_base(response, directory_params, directory_request),
            directory_signature,
        ):
            _reject("invalid directory signature")
        if not key.verify(request_base, signature):
            _reject("invalid WBA request signature")
        verified = self._resolver.verify_domain(domain, peer_cert=opts.peer_cert)
        self._final_check(params, directory_params, verified)
        if not self._current_key(verified, domain, url, params.key_id):
            verified = self._refresh(domain, opts.peer_cert)
            if not self._current_key(verified, domain, url, params.key_id):
                _reject("WBA key is not the verified current DNSid ku signing key")
            self._final_check(params, directory_params, verified)
        if opts.replay_policy is not None:
            if not params.nonce:
                _reject("replay policy requires a non-empty nonce")
            assert params.expires is not None
            try:
                accepted = opts.replay_policy(
                    domain, params.key_id, params.nonce,
                    math.ceil(params.expires + self._config.clock_skew),
                )
            except Exception as exc:
                raise VerificationError(
                    VerificationCode.SIGNATURE_INVALID, "WBA replay store failed", transient=True,
                ) from exc
            if accepted is not True:
                _reject("WBA nonce replay rejected")
            self._final_check(params, directory_params, verified)
        return verified

    def _current_key(self, verified: VerifiedDomain, domain: str, url: str, keyid: str) -> bool:
        if verified.domain != domain:
            _reject("DNSid resolver returned a different signer domain")
        if _wba_identifier(url) == _wba_identifier(verified.record.ku):
            _reject("WBA discovery must not identify the authenticated ku endpoint")
        key = verified.jwks.current_operational_signing_key(verified.record.v)
        return key.signature_alg() == "EdDSA" and key.thumbprint() == keyid

    def _refresh(self, domain: str, peer_cert: TLSCertificate | None) -> VerifiedDomain:
        remaining_seconds()
        now = time.monotonic()
        with self._refresh_lock:
            self._refresh_deadlines = {
                name: deadline for name, deadline in self._refresh_deadlines.items()
                if deadline > now
            }
            if domain in self._refresh_deadlines or len(self._refresh_deadlines) >= 1024:
                _reject("WBA ku signing key mismatch refresh suppressed")
            # In-flight attempts cannot be evicted even if network work exceeds cooldown.
            self._refresh_deadlines[domain] = math.inf
        try:
            return self._resolver.refresh_domain(domain, peer_cert=peer_cert)
        finally:
            with self._refresh_lock:
                self._refresh_deadlines[domain] = now + 5

    def _final_check(
        self, params: SignatureParams, directory: SignatureParams, verified: VerifiedDomain,
    ) -> None:
        remaining_seconds()
        _check_time(params, self._config.clock_skew)
        _check_time(directory, self._config.clock_skew, directory=True)
        # VerifyDomain acquired this invocation's evidence; zero DNS TTL forbids
        # later reuse, not completion of this operation. TLS and ka still apply.
        verified._require_fresh_evidence(_now(), fresh_dns_lookup=True)

    def _fetch(self, url: str, domain: str) -> tuple[HttpRequest, HttpRequest]:
        transport = _BorrowedTransport(self._transport)
        try:
            with httpx.Client(transport=transport, trust_env=False) as client:
                _assert_same_host_https_redirect(url, domain)
                with client.stream(
                    "GET", url,
                    headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"},
                    follow_redirects=False, timeout=remaining_seconds(10)
                ) as response:
                    if response.status_code != 200:
                        raise VerificationError(
                            VerificationCode.TLS_ERROR,
                            "directory response must have status 200, "
                            f"got {response.status_code}",
                            transient=(response.status_code >= 500 or response.status_code == 429),
                        )
                    if "content-encoding" in response.headers:
                        _reject("compressed directory responses are forbidden")
                    body = _read_limited(
                        response, 1024 * 1024, VerificationCode.RECORD_INVALID,
                        "directory response size exceeded", decode_content=False,
                    )
                    return (
                        HttpRequest(method="GET", url=str(response.request.url)),
                        HttpRequest(method="GET", url=url, headers=dict(response.headers),
                                    body=body, status=response.status_code),
                    )
        except httpx.TransportError as exc:
            permanent = SSRF_BLOCK_MARKER in str(exc) or isinstance(exc, httpx.ProtocolError)
            cause: BaseException | None = exc
            while cause is not None:
                if isinstance(cause, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(cause):
                    permanent = True
                cause = cause.__cause__ or cause.__context__
            raise VerificationError(
                VerificationCode.TLS_ERROR, "directory fetch failed", transient=not permanent,
            ) from exc
