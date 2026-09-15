"""Web Bot Auth (WBA) HTTP Message Signature signing and directory serving.

Implements the WBA profile from the SDK design (10-web-bot-auth.md): RFC 9421
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

import os
from dataclasses import dataclass, field
from enum import StrEnum

from ._utils import b64_std_encode, b64url_encode, jose_alg_to_http_sig_alg, normalize_fqdn

# Reuse the RFC 9421 signature-base construction unchanged — WBA shares it.
from .exceptions import ArgumentError, VerificationError
from .http_signatures import _build_signature_base, _now
from .interfaces import KeyProvider
from .models import (
    JWK,
    HttpRequest,
    SignatureParams,
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


@dataclass
class WebBotAuthConfig:
    """WBA profile configuration (design doc 10 §Profile Configuration)."""

    #: Back-compatible alias for the Signature-Agent URI.
    directory_url: str = ""
    #: HTTPS origin for ``directory`` discovery or direct endpoint for
    #: ``jwks_uri`` discovery. Empty defaults to ``https://{domain}``.
    signature_agent_uri: str = ""
    #: Discovery interpretation emitted as an RFC 8941 Token.
    signature_agent_type: str = "directory"
    #: Request signature lifetime in seconds (sets ``expires``).
    signature_ttl: int = DEFAULT_SIGNATURE_TTL
    #: Whether to send Signature-Agent.  The WBA draft makes it optional, but
    #: Cloudflare interop requires it.
    include_signature_agent: bool = True
    #: Lifetime for signatures attached to directory responses.
    directory_signature_ttl: int = DEFAULT_DIRECTORY_SIGNATURE_TTL
    #: Non-negative verification tolerance reserved for the verifier API.
    clock_skew: int = 5

    def __post_init__(self) -> None:
        """Reject WBA configuration outside the DNSid profile limits."""
        if self.signature_agent_type not in {"directory", "jwks_uri"}:
            raise ArgumentError("Web Bot Auth discovery type must be directory or jwks_uri")
        if not 0 < self.signature_ttl <= 300:
            raise ArgumentError("Web Bot Auth signature_ttl must be between 1 and 300 seconds")
        if not 0 < self.directory_signature_ttl <= 300:
            raise ArgumentError(
                "Web Bot Auth directory_signature_ttl must be between 1 and 300 seconds"
            )
        if self.clock_skew < 0:
            raise ArgumentError("Web Bot Auth clock_skew must be non-negative")


@dataclass
class WebBotAuthSigningOptions:
    """Per-request overrides for CreateWebBotAuthSignedRequest."""

    additional_components: list[str] = field(default_factory=list)
    #: Overrides WebBotAuthConfig.include_signature_agent.
    signature_agent: bool | None = None
    #: Overrides WebBotAuthConfig.signature_ttl.
    ttl: int | None = None


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
        label: str = DEFAULT_LABEL,
        expires_in_seconds: int | None = None,
    ) -> None:
        """Initialize the signer for a local DNSid identity.

        Args:
            key_provider: Provides the Ed25519 signing key.  WBA signing
                requires Ed25519; other key types raise ArgumentError at
                signing time.
            domain: The DNSid FQDN, used to derive the default directory URL.
            config: Optional :class:`WebBotAuthConfig`.
            signature_agent: Back-compat override for the directory URL placed
                in Signature-Agent.
            label: Signature label and Signature-Agent dictionary member name
                (profile default: ``sig1``).
            expires_in_seconds: Back-compat override for the request signature
                TTL.

        Raises:
            ArgumentError: If the resolved Signature-Agent directory URL is
                not https.
        """
        self._key_provider = key_provider
        self._domain = normalize_fqdn(domain)
        self._config = config or WebBotAuthConfig()
        # Back-compat kwargs: signature_agent overrides the directory URL,
        # expires_in_seconds overrides the signature TTL.
        directory_url = (
            signature_agent or self._config.signature_agent_uri or self._config.directory_url
        )
        if not directory_url:
            directory_url = f"https://{self._domain}"
        from urllib.parse import urlsplit

        parsed_agent = urlsplit(directory_url)
        if parsed_agent.scheme != "https" or not parsed_agent.hostname or parsed_agent.username:
            raise ArgumentError(
                f"Web Bot Auth Signature-Agent must be https; got {directory_url!r}"
            )
        if self._config.signature_agent_type == "directory":
            port = f":{parsed_agent.port}" if parsed_agent.port is not None else ""
            directory_url = f"https://{parsed_agent.hostname}{port}"
        elif parsed_agent.fragment:
            raise ArgumentError("Web Bot Auth jwks_uri must not contain a fragment")
        self._directory_url = directory_url
        self._label = label
        self._expires_in = (
            expires_in_seconds if expires_in_seconds is not None else self._config.signature_ttl
        )

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
            The same request, with Signature-Input, Signature, and (when
            enabled) Signature-Agent headers set.

        Raises:
            ArgumentError: If the signing key is not Ed25519, or an additional
                component is not a known derived component or a lowercase HTTP
                field name.
        """
        import hashlib

        if variant is WBAVariant.NO_SIG:
            return req

        opts = options or WebBotAuthSigningOptions()
        signing_key = self._key_provider.signing_key()
        signing_alg = signing_key.signature_alg()
        if signing_alg != "EdDSA":
            raise ArgumentError("Web Bot Auth signing requires Ed25519")

        components = ["@authority"]
        if req.body is not None:
            digest = hashlib.sha256(req.body).digest()
            req.set_header("content-digest", f"sha-256=:{b64_std_encode(digest)}:")
            components.append("content-digest")

        include_signature_agent = self._config.include_signature_agent
        if opts.signature_agent is not None:
            include_signature_agent = opts.signature_agent
        if include_signature_agent:
            # Signature-Agent is a Dictionary Structured Header; the selected
            # member is covered with the RFC 9421 key component parameter.
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
        except VerificationError as exc:
            raise ArgumentError(f"unknown signature component: {exc}") from exc

        now_ts = int(_now().timestamp())
        ttl = opts.ttl if opts.ttl is not None else self._expires_in
        if not 0 < ttl <= 300:
            raise ArgumentError("Web Bot Auth request TTL must be between 1 and 300 seconds")
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
    ``tag="http-message-signatures-directory"``.

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
        ArgumentError: If the signing key is not Ed25519.
    """
    import hashlib
    import json

    cfg = config or WebBotAuthConfig()
    signing_key = key_provider.signing_key()
    signing_alg = signing_key.signature_alg()
    if signing_alg != "EdDSA":
        raise ArgumentError("Web Bot Auth directory signing requires Ed25519")

    directory_key = wba_directory_jwk(signing_key)
    body = json.dumps({"keys": [directory_key]}, separators=(",", ":")).encode()
    digest = hashlib.sha256(body).digest()
    ttl = min(cfg.directory_signature_ttl, 300)

    headers = {
        "content-type": WBA_DIRECTORY_MEDIA_TYPE,
        "cache-control": f"max-age={ttl}",
        "content-digest": f"sha-256=:{b64_std_encode(digest)}:",
    }

    now_ts = int(_now().timestamp())
    params = SignatureParams(
        label=DEFAULT_LABEL,
        key_id=signing_key.thumbprint(),
        alg=jose_alg_to_http_sig_alg(signing_alg),
        created=now_ts,
        expires=now_ts + ttl,
        nonce=_generate_wba_nonce(),
        components=[
            "@authority;req",
            "content-type",
            "cache-control",
            "content-digest",
        ],
        tag=WBA_DIRECTORY_TAG,
    )

    # Response signature base: @authority comes from the request context
    # (";req"); the remaining components are response fields.
    from .http_signatures import _resolve_authority

    lines = [
        f'"@authority";req: {_resolve_authority(req)}',
        f'"content-type": {headers["content-type"]}',
        f'"cache-control": {headers["cache-control"]}',
        f'"content-digest": {headers["content-digest"]}',
        f'"@signature-params": {params.value_string()}',
    ]
    sig_base = "\n".join(lines).encode("utf-8")
    sig_bytes = key_provider.sign(sig_base)

    headers["signature-input"] = params.serialize()
    headers["signature"] = f"{DEFAULT_LABEL}=:{b64_std_encode(sig_bytes)}:"
    return WBADirectoryResponse(status=200, headers=headers, body=body)
