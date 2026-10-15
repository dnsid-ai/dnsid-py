"""Web Bot Auth (WBA) HTTP Message Signature signing and directory serving.

Targets published draft-ietf-webbotauth-httpsig-protocol-00 (SDK design 10): RFC 9421
request signing with the ``web-bot-auth`` tag, the ``Signature-Agent``
Dictionary Structured Header (member ``sig1``, covered with ``key="sig1"``),
64-byte nonces, Ed25519-only signing, and HTTP Message Signatures Directory
serving at ``/.well-known/http-message-signatures-directory``.

The WBA ``keyid`` is the RFC 7638 base64url JWK thumbprint of the active
signing key, not the DNSid ``{domain}#{kid}`` compound key ID.  For
DNSid-enabled agents, verifiers bind the WBA directory key back to key
material published by the DNSid ``ku`` endpoint.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from urllib.parse import urlsplit

import httpx

from ._utils import b64_std_encode, b64url_encode, jose_alg_to_http_sig_alg, normalize_fqdn

# Reuse the RFC 9421 signature-base construction unchanged — WBA shares it.
from .exceptions import ArgumentError, VerificationError
from .http_signatures import _build_signature_base, _now
from .interfaces import KeyProvider
from .models import (
    JWK,
    HttpRequest,
    SignatureParams,
    _parse_component_identifier,
    _parse_sf_dictionary,
    _serialize_sf_string,
    _validate_component_identifiers,
)

WBA_TAG = "web-bot-auth"
WBA_DIRECTORY_TAG = "http-message-signatures-directory"
WBA_DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
WBA_DIRECTORY_WELL_KNOWN_PATH = "/.well-known/http-message-signatures-directory"
DEFAULT_LABEL = "sig1"  # profile-owned Signature-Agent dictionary member name
DEFAULT_SIGNATURE_TTL = 60
DEFAULT_DIRECTORY_SIGNATURE_TTL = 300


def _generate_wba_nonce() -> str:
    """64 cryptographically random bytes, base64url without padding."""
    return b64url_encode(os.urandom(64))


def _finite_number(value: int | float) -> bool:
    try:
        return (
            not isinstance(value, bool) and isinstance(value, int | float) and math.isfinite(value)
        )
    except OverflowError:
        return False


def _validate_ttl(ttl: int | float, name: str = "request TTL") -> None:
    if not _finite_number(ttl) or not 1 <= ttl <= 300 or ttl != int(ttl):
        raise ArgumentError(f"Web Bot Auth {name} must be an integer between 1 and 300 seconds")


def _is_https_origin(uri: str) -> bool:
    parsed = urlsplit(uri)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port not in (None, 443) else ""
    return bool(host) and uri.isascii() and uri == f"https://{host}{port}"


def _wba_identifier(uri: str) -> str:
    """Normalize a WBA URL per RFC 3986, excluding query and fragment."""
    def normalize_escape(match: re.Match[str]) -> str:
        char = chr(int(match[0][1:], 16))
        return char if char in (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        ) else match[0].upper()

    uri = re.sub(r"%[0-9a-fA-F]{2}", normalize_escape, uri)
    url = httpx.URL(uri).copy_with(query=None, fragment=None)
    return str(url.copy_with(raw_path=url.raw_path or b"/"))


@dataclass
class WebBotAuthConfig:
    """WBA profile configuration (design doc 10 §Profile Configuration).

    TTLs require integral seconds from 1 through 300. Clock skew must be finite
    and non-negative. Boolean and non-numeric duration values are rejected.
    Signature-Agent is mandatory; its compatibility flag cannot disable it.
    Directory discovery requires an ASCII HTTPS origin without a trailing slash.
    """

    #: Back-compatible alias for the Signature-Agent URI.
    directory_url: str = ""
    #: HTTPS origin for ``directory`` discovery or direct endpoint for
    #: ``jwks_uri`` discovery. Empty defaults to ``https://{domain}``.
    signature_agent_uri: str = ""
    #: Discovery interpretation emitted as an RFC 8941 Token.
    signature_agent_type: str = "directory"
    #: Request signature lifetime in seconds (sets ``expires``).
    signature_ttl: int | float = DEFAULT_SIGNATURE_TTL
    #: Compatibility flag; must be True because Signature-Agent is mandatory.
    include_signature_agent: bool = True
    #: Lifetime for signatures attached to directory responses.
    directory_signature_ttl: int | float = DEFAULT_DIRECTORY_SIGNATURE_TTL
    #: Non-negative verification tolerance in seconds.
    clock_skew: int | float = 5

    def __post_init__(self) -> None:
        """Reject WBA configuration outside the DNSid profile limits."""
        if self.include_signature_agent is not True:
            raise ArgumentError("Web Bot Auth requires Signature-Agent")
        if self.signature_agent_type not in {"directory", "jwks_uri"}:
            raise ArgumentError("Web Bot Auth discovery type must be directory or jwks_uri")
        _validate_ttl(self.signature_ttl, "signature_ttl")
        _validate_ttl(self.directory_signature_ttl, "directory_signature_ttl")
        if not _finite_number(self.clock_skew) or self.clock_skew < 0:
            raise ArgumentError("Web Bot Auth clock_skew must be finite and non-negative")


@dataclass
class WebBotAuthSigningOptions:
    """Per-request overrides for CreateWebBotAuthSignedRequest."""

    additional_components: list[str] = field(default_factory=list)
    #: Compatibility flag; only None or True is accepted.
    signature_agent: bool | None = None
    #: Overrides WebBotAuthConfig.signature_ttl.
    ttl: int | float | None = None


class WBAVariant(StrEnum):
    """Signing variants the test driver toggles (§7)."""

    ACTIVE = "active"  # normal, valid signature
    REVOKED = "revoked"  # valid signature; key is revoked in the directory
    KEY_MISMATCH = "key-mismatch"  # advertised keyid != key that actually signed
    NO_SIG = "no-sig"  # no signature at all
    TAMPERED = "tampered"  # valid sig, but body modified after signing
    EXPIRED = "expired"  # `expires` in the past


class WBAHttpSigner:
    """Sign outbound requests as Web Bot Auth HTTP Message Signatures.

    Web Bot Auth is an application profile layered on top of DNSid identity;
    application profiles are not part of the core DNSid protocol and are not
    required for DNSid conformance.
    """

    def __init__(
        self,
        key_provider: KeyProvider,
        domain: str,
        *,
        config: WebBotAuthConfig | None = None,
        signature_agent: str | None = None,
        ku_url: str = "",
        label: str = DEFAULT_LABEL,
        expires_in_seconds: int | float | None = None,
    ) -> None:
        """Initialize the signer for a local DNSid identity.

        Args:
            key_provider: Provides the Ed25519 signing key.  WBA signing
                requires Ed25519; other key types raise ArgumentError at
                signing time.
            domain: The DNSid FQDN, used to derive the default directory URL.
            config: Optional :class:`WebBotAuthConfig`, copied and validated
                at construction.
            signature_agent: Back-compat override for the directory URL placed
                in Signature-Agent.
            ku_url: Known local operational JWKS URL; rejects matching jwks_uri discovery.
            label: Signature label and Signature-Agent dictionary member name
                (profile default: ``sig1``).
            expires_in_seconds: Back-compat override for the request signature
                TTL.

        Raises:
            ArgumentError: If the discovery URI is invalid, contains credentials,
                is not HTTPS, or the TTL is not an integer from 1 through 300.
        """
        self._key_provider = key_provider
        self._domain = normalize_fqdn(domain)
        self._config = replace(config) if config is not None else WebBotAuthConfig()
        # Back-compat kwargs: signature_agent overrides the directory URL,
        # expires_in_seconds overrides the signature TTL.
        directory_url = (
            signature_agent or self._config.signature_agent_uri or self._config.directory_url
        )
        if not directory_url:
            directory_url = f"https://{self._domain}"
        try:
            parsed_agent = urlsplit(directory_url)
            parsed_agent.port
            if (
                self._config.signature_agent_type == "jwks_uri" and ku_url
                and _wba_identifier(directory_url) == _wba_identifier(ku_url)
            ):
                raise ArgumentError("Web Bot Auth discovery must not identify local ku")
        except (ValueError, httpx.InvalidURL) as exc:
            raise ArgumentError("invalid Web Bot Auth Signature-Agent URI") from exc
        if (
            parsed_agent.scheme != "https" or not parsed_agent.hostname
            or parsed_agent.username is not None or parsed_agent.password is not None
        ):
            raise ArgumentError(
                f"Web Bot Auth Signature-Agent must be https; got {directory_url!r}"
            )
        if self._config.signature_agent_type == "directory":
            if not _is_https_origin(directory_url):
                raise ArgumentError("Web Bot Auth directory URI must be an ASCII HTTPS origin")
        elif parsed_agent.fragment:
            raise ArgumentError("Web Bot Auth jwks_uri must not contain a fragment")
        self._directory_url = directory_url
        self._label = label
        self._expires_in = (
            expires_in_seconds if expires_in_seconds is not None else self._config.signature_ttl
        )
        _validate_ttl(self._expires_in)

    def sign(
        self,
        req: HttpRequest,
        variant: WBAVariant = WBAVariant.ACTIVE,
        options: WebBotAuthSigningOptions | None = None,
    ) -> HttpRequest:
        """Sign *req* in place and return it.

        ``REVOKED`` signs normally — revocation is a directory-state concern
        checked by the verifier, not a property of the signature bytes.

        Args:
            req: The request to sign; headers (and, for ``TAMPERED``, the
                body) are modified in place.
            variant: Signing variant to produce.  ``NO_SIG`` returns *req*
                unmodified; other variants produce deliberately broken
                signatures for verifier testing.
            options: Optional per-request overrides.

        Returns:
            The same request, with Signature-Input, Signature, and Signature-Agent set.

        Raises:
            ArgumentError: If the TTL is invalid, Signature-Agent is disabled,
                the key is not Ed25519, or an additional component is unsupported.
                Also raised if the signing key changes during signing.
                Nested signing is not supported because signature fields are replaced.
        """
        import hashlib

        if variant is WBAVariant.NO_SIG:
            return req

        opts = options or WebBotAuthSigningOptions()
        if opts.signature_agent is not None and opts.signature_agent is not True:
            raise ArgumentError("Web Bot Auth requires Signature-Agent")
        ttl = opts.ttl if opts.ttl is not None else self._expires_in
        _validate_ttl(ttl)
        ttl = int(ttl)
        signing_key = JWK.from_dict(self._key_provider.signing_key().to_dict())
        signing_alg = signing_key.signature_alg()
        if signing_alg != "EdDSA":
            raise ArgumentError("Web Bot Auth signing requires Ed25519")

        components = ["@authority"]
        if req.body is not None:
            digest = hashlib.sha256(req.body).digest()
            req.set_header("content-digest", f"sha-256=:{b64_std_encode(digest)}:")
            components.append("content-digest")

        req.set_header(
            "signature-agent",
            _replace_signature_agent_member(
                req.get_header("signature-agent"),
                self._label,
                self._directory_url,
                self._config.signature_agent_type,
            ),
        )
        components.append(f'signature-agent;key="{self._label}"')

        for component in opts.additional_components:
            if component not in components:
                components.append(component)

        try:
            _validate_component_identifiers(components, request_context=False)
            if any(_parse_component_identifier(c)[0] in {"signature", "signature-input"}
                   for c in components):
                # Signing replaces these fields, so inner signatures cannot be preserved.
                raise ArgumentError("Web Bot Auth nested signing is unsupported")
        except VerificationError as exc:
            raise ArgumentError(f"unknown signature component: {exc}") from exc

        now_ts = int(_now().timestamp())
        created = now_ts
        expires = now_ts + ttl
        if variant is WBAVariant.EXPIRED:
            created = now_ts - ttl - 60
            expires = now_ts - 60

        params = SignatureParams(
            label=self._label,
            key_id=signing_key.thumbprint(),  # RFC 7638 base64url SHA-256
            alg=jose_alg_to_http_sig_alg(signing_alg),
            created=created,
            expires=expires,
            nonce=_generate_wba_nonce(),
            components=components,
            tag=WBA_TAG,
        )

        sig_base = _build_signature_base(req, params)

        if variant is WBAVariant.KEY_MISMATCH:
            # Sign with a different key while advertising the real keyid → the
            # signature cannot verify against the key the verifier resolves.
            from .local_key_provider import LocalKeyProvider

            sig_bytes = LocalKeyProvider.generate().sign(sig_base)
        else:
            sig_bytes = self._key_provider.sign(sig_base)
            if not signing_key.verify(sig_base, sig_bytes):
                raise ArgumentError("Web Bot Auth signing key changed during signing")

        req.set_header("signature-input", params.serialize())
        req.set_header("signature", f"{self._label}=:{b64_std_encode(sig_bytes)}:")

        if variant is WBAVariant.TAMPERED:
            # ponytail: mutate the body after signing so the covered
            # content-digest no longer matches — relies on req having a body.
            req.body = (req.body or b"") + b"-tampered"

        return req


def _replace_signature_agent_member(
    header: str,
    label: str,
    uri: str,
    discovery_type: str,
) -> str:
    """Replace one Signature-Agent dictionary member and preserve the others."""
    import http_sf

    replacement_text = f"{label}={_serialize_sf_string(uri)};type={discovery_type}"
    try:
        members = _parse_sf_dictionary(header) if header else {}
        replacement = _parse_sf_dictionary(replacement_text)
    except ValueError as exc:
        raise ArgumentError(f"malformed Signature-Agent dictionary: {exc}") from exc
    members[label] = replacement[label]
    return http_sf.ser(members)


@dataclass
class WBADirectoryResponse:
    """A signed HTTP Message Signatures Directory response."""

    status: int
    headers: dict[str, str]
    body: bytes


def wba_directory_jwk(signing_key: JWK) -> dict[str, str]:
    """Convert a core public JWK into the WBA directory wire representation.

    ``kid`` is the RFC 7638 thumbprint used as the Signature-Input ``keyid``;
    ``alg`` uses the HTTP Message Signatures name (``ed25519``), not the JOSE
    name.  Only public thumbprint members plus kid/alg are included.

    Args:
        signing_key: The public JWK to convert.

    Returns:
        The directory wire representation of the key.

    Raises:
        ArgumentError: If the key is not Ed25519.
    """
    if signing_key.signature_alg() != "EdDSA":
        raise ArgumentError("Web Bot Auth directory keys require Ed25519")
    raw = signing_key._raw
    return {
        "kty": str(raw.get("kty", "")),
        "crv": str(raw.get("crv", "")),
        "x": str(raw.get("x", "")),
        "kid": signing_key.thumbprint(),
        "alg": jose_alg_to_http_sig_alg("EdDSA"),
        "use": "sig",
    }


def serve_http_message_signatures_directory(
    req: HttpRequest,
    key_provider: KeyProvider,
    config: WebBotAuthConfig | None = None,
) -> WBADirectoryResponse:
    """Return the active public signing key as a signed WBA directory response.

    The body is a JWKS object served with the
    ``application/http-message-signatures-directory+json`` media type and one
    HTTP Message Signature over ``"@authority";req``, ``content-type``,
    ``cache-control``, and ``content-digest`` with
    ``tag="http-message-signatures-directory"``. Signatures are backdated by
    min(5, ttl - 1) seconds without extending their lifetime. Cache-Control caps
    freshness at remaining validity and requires revalidation; disable CDN stale
    serving, stale-while-revalidate, and stale-if-error for this endpoint.

    Args:
        req: The inbound directory request; its authority is covered by the
            response signature.
        key_provider: Provides the Ed25519 signing key to publish and sign
            with.
        config: Optional :class:`WebBotAuthConfig`; controls the directory
            signature TTL.

    Returns:
        A WBADirectoryResponse with status, headers, and JWKS body.

    Raises:
        ArgumentError: If the key is not Ed25519, changes during signing, or the
            signature expires during signing.
    """
    import hashlib
    import json

    cfg = replace(config) if config is not None else WebBotAuthConfig()
    signing_key = JWK.from_dict(key_provider.signing_key().to_dict())
    signing_alg = signing_key.signature_alg()
    if signing_alg != "EdDSA":
        raise ArgumentError("Web Bot Auth directory signing requires Ed25519")

    directory_key = wba_directory_jwk(signing_key)
    body = json.dumps({"keys": [directory_key]}, separators=(",", ":")).encode()
    digest = hashlib.sha256(body).digest()
    ttl = int(cfg.directory_signature_ttl)
    backdate = min(5, ttl - 1)

    headers = {
        "content-type": WBA_DIRECTORY_MEDIA_TYPE,
        "cache-control": f"max-age={ttl - backdate}, must-revalidate",
        "content-digest": f"sha-256=:{b64_std_encode(digest)}:",
    }

    now_ts = int(_now().timestamp())
    params = SignatureParams(
        label=DEFAULT_LABEL,
        key_id=signing_key.thumbprint(),
        alg=jose_alg_to_http_sig_alg(signing_alg),
        created=now_ts - backdate,
        expires=now_ts - backdate + ttl,
        nonce=_generate_wba_nonce(),
        components=[
            "@authority;req",
            "content-type",
            "cache-control",
            "content-digest",
        ],
        tag=WBA_DIRECTORY_TAG,
    )

    response = HttpRequest(method=req.method, url=req.url, headers=headers, body=body, status=200)
    sig_base = _build_signature_base(response, params, request_context=req)
    sig_bytes = key_provider.sign(sig_base)
    if not signing_key.verify(sig_base, sig_bytes):
        raise ArgumentError("Web Bot Auth directory signing key changed during signing")
    if _now().timestamp() >= now_ts - backdate + ttl:
        raise ArgumentError("directory signature expired during signing")

    headers["signature-input"] = params.serialize()
    headers["signature"] = f"{DEFAULT_LABEL}=:{b64_std_encode(sig_bytes)}:"
    return WBADirectoryResponse(status=200, headers=headers, body=body)
