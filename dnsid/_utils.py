"""Internal utilities: FQDN normalisation, key-ID parsing, algorithm mappings, regex guards."""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Algorithm mappings
# ---------------------------------------------------------------------------

# RFC 9421 §B.2 algorithm identifier mapping — DNSid protocol algorithms only.
JOSE_ALG_TO_HTTP_SIG_ALG: dict[str, str] = {
    "EdDSA": "ed25519",
    "ES256": "ecdsa-p256-sha256",
}

# Application-layer JOSE algorithms for JWT and JWS helpers (EdDSA and ES256 only).
APPLICATION_JOSE_ALGS: frozenset[str] = frozenset({"EdDSA", "ES256"})

# RFC 9421 §2 derived component identifiers (excludes @signature-params, which is implicit).
KNOWN_DERIVED_COMPONENTS: frozenset[str] = frozenset(
    {
        "@method",
        "@authority",
        "@target-uri",
        "@path",
        "@query",
        "@query-param",
        "@status",
        "@request-target",
        "@scheme",
    }
)

# Permitted ka (max key age) values.
PERMITTED_KA_VALUES: frozenset[str] = frozenset({"24h", "7d", "30d", "90d"})

# ---------------------------------------------------------------------------
# Regex guards
# ---------------------------------------------------------------------------

# spec §4.2 ABNF: ALPHA *( ALPHA / DIGIT / "_" )
_TAG_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

# spec §4.2 ABNF: *( %x21-3A / %x3C-7E ) — printable ASCII excluding ';' and ' '
_TAG_VALUE_RE = re.compile(r"^[\x21-\x3A\x3C-\x7E]*$")

# LedgerRef method: [a-z][a-z0-9-]*
_LEDGER_METHOD_RE = re.compile(r"^[a-z][a-z0-9-]*$")

# Lowercase HTTP field name (RFC 7230 token, already lowercased)
_HTTP_FIELD_NAME_RE = re.compile(r"^[a-z][a-z0-9!#$%&'*+\-.^_`|~]*$")


def is_valid_tag_name(name: str) -> bool:
    return bool(_TAG_NAME_RE.match(name))


def is_valid_tag_value(value: str) -> bool:
    return bool(_TAG_VALUE_RE.match(value))


def is_valid_ledger_method(method: str) -> bool:
    return bool(_LEDGER_METHOD_RE.match(method))


def is_lowercase_http_field_name(name: str) -> bool:
    return bool(_HTTP_FIELD_NAME_RE.match(name))


def jose_alg_to_http_sig_alg(alg: str) -> str:
    """Map a JOSE algorithm name to its RFC 9421 HTTP Message Signature identifier.

    Raises ArgumentError for JOSE algorithms with no RFC 9421 registry entry (e.g. RS384, RS512).
    """
    from .exceptions import ArgumentError

    try:
        return JOSE_ALG_TO_HTTP_SIG_ALG[alg]
    except KeyError:
        raise ArgumentError(
            f"JOSE algorithm {alg!r} has no entry in the"
            " RFC 9421 HTTP Message Signatures Algorithm registry"
        )


# ---------------------------------------------------------------------------
# FQDN helpers
# ---------------------------------------------------------------------------

_MAX_FQDN_OCTETS = 253
_MAX_AGENT_FQDN_OCTETS = 246
_MAX_LABEL_OCTETS = 63

# Matches domain-name-form gi values: labels of [a-zA-Z0-9-] separated by dots.
# Excludes URIs (contain "://"), ledger refs (contain ":"), and other non-domain forms.
_DOMAIN_NAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
)


def normalize_fqdn(name: str, agent_fqdn: bool = False) -> str:
    """Normalize a domain name to lowercase IDNA A-label form, no trailing dot.

    Steps per spec §4.1:
      1. Strip exactly one trailing root dot.
      2. Split into labels; IDNA-encode each U-label to A-label punycode via idna library.
      3. Validate label lengths (max 63 octets each) and total length (max 253 octets).
      4. When agent_fqdn=True, enforce the DNSid 246-octet agent FQDN limit.

    Raises ValidationError on empty input, empty labels, or length violations.
    """
    import idna

    from .exceptions import ValidationError

    if not name:
        raise ValidationError("FQDN cannot be empty")

    without_dot = name[:-1] if name.endswith(".") else name
    if not without_dot:
        raise ValidationError("FQDN cannot be empty after removing trailing dot")

    labels = without_dot.split(".")
    normalized: list[str] = []
    for label in labels:
        if not label:
            raise ValidationError(f"FQDN contains empty label: {name!r}")
        try:
            # Lowercase before encoding. uts46=True enables UTS#46 mapping (IDNA2003-compatible),
            # while still applying IDNA2008 validity checks.
            normalized.append(idna.encode(label.lower(), uts46=True).decode("ascii"))
        except (UnicodeError, Exception) as exc:
            raise ValidationError(f"Invalid FQDN label {label!r}: {exc}") from exc

    for label in normalized:
        if len(label.encode("ascii")) > _MAX_LABEL_OCTETS:
            raise ValidationError(f"DNS label exceeds 63 octets: {label!r}")

    # UTS#46 maps dot-equivalents (e.g. U+3002 IDEOGRAPHIC FULL STOP) to ASCII '.'
    # during encoding, which can reintroduce a trailing dot after the pre-strip.
    result = ".".join(normalized).rstrip(".")
    byte_len = len(result.encode("ascii"))

    if byte_len > _MAX_FQDN_OCTETS:
        raise ValidationError(f"FQDN exceeds 253-octet DNS presentation limit: {name!r}")
    if agent_fqdn and byte_len > _MAX_AGENT_FQDN_OCTETS:
        raise ValidationError(f"Agent FQDN exceeds 246-octet DNSid limit: {name!r}")

    return result


def is_domain_name(s: str) -> bool:
    """Return True if *s* is a domain-name-form value (for gi consistency checks).

    Returns False for URIs (contain "://"), ledger refs (contain ":"), or values
    that do not look like dot-separated DNS labels.
    """
    v = s[:-1] if s.endswith(".") else s
    return bool(_DOMAIN_NAME_RE.match(v))


# ---------------------------------------------------------------------------
# Key-ID helpers
# ---------------------------------------------------------------------------


def parse_key_id(key_id: str) -> tuple[str, str]:
    """Split a compound key ID '{domain}#{kid}' into (normalized_domain, kid).

    Splits on the first '#'. Raises ArgumentError if either side is empty or
    if the kid side contains another '#'.
    """
    from .exceptions import ArgumentError

    if "#" not in key_id:
        raise ArgumentError(f"key ID has no '#' separator: {key_id!r}")
    domain_part, _, kid_part = key_id.partition("#")
    if not domain_part:
        raise ArgumentError(f"key ID has empty domain side: {key_id!r}")
    if not kid_part:
        raise ArgumentError(f"key ID has empty kid side: {key_id!r}")
    if "#" in kid_part:
        raise ArgumentError(f"key ID kid side must not contain '#': {key_id!r}")
    domain = normalize_fqdn(domain_part)
    return domain, kid_part


# ---------------------------------------------------------------------------
# Base64url helpers  (used for JWT/JWS compact serialization, DNS record sg tag)
# ---------------------------------------------------------------------------


def b64url_encode(data: bytes, *, padding: bool = False) -> str:
    """Encode bytes as unpadded base64url (RFC 7515 §2)."""
    import base64

    encoded = base64.urlsafe_b64encode(data).decode("ascii")
    return encoded if padding else encoded.rstrip("=")


def b64url_decode(s: str) -> bytes:
    """Decode a padded or unpadded base64url string."""
    import base64

    # Add padding if missing so standard decoder accepts it.
    padding_needed = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * padding_needed)


# Compact-JWS segment alphabet: unpadded base64url only (RFC 7515 §2 / §7.1).
_B64URL_STRICT_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def b64url_decode_strict(s: str) -> bytes:
    """Strict unpadded base64url decode for compact-JWS segments.

    Unlike b64url_decode (which relies on the permissive stdlib decoder that
    silently ignores stray characters), this rejects anything outside the
    unpadded base64url alphabet — including '=' padding and the standard-base64
    '+' / '/' characters — so a segment cannot carry hidden bytes and still
    decode to a valid signature. Raises ValueError on any violation.
    """
    import base64

    if not _B64URL_STRICT_RE.fullmatch(s):
        raise ValueError("not valid unpadded base64url")
    padding_needed = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * padding_needed)


# ---------------------------------------------------------------------------
# Standard base64 helpers  (used for RFC 8941 byte sequences: Signature, Content-Digest)
# ---------------------------------------------------------------------------


def b64_std_encode(data: bytes) -> str:
    """Encode bytes as padded standard base64 (RFC 8941 §4.2.7 byte sequences).

    RFC 8941 structured-field byte sequences MUST use standard base64 (with +/= characters),
    NOT base64url. Used for the Signature and Content-Digest header values.
    """
    import base64

    return base64.b64encode(data).decode("ascii")


def b64_std_decode(s: str) -> bytes:
    """Decode a standard base64 string (padded or unpadded)."""
    import base64

    padding_needed = (4 - len(s) % 4) % 4
    return base64.b64decode(s + "=" * padding_needed)


# ---------------------------------------------------------------------------
# Ledger reference helpers
# ---------------------------------------------------------------------------


def parse_ledger_ref(lr: str) -> tuple[str, str]:
    """Split a LedgerRef string '{method}:{entry_ref}' into (method, entry_ref).

    Raises ParseError if lr is malformed (no colon, empty method, method violates
    [a-z][a-z0-9-]*).
    """
    from .exceptions import ParseError

    if ":" not in lr:
        raise ParseError(f"ledger ref has no ':' separator: {lr!r}")
    method, _, entry_ref = lr.partition(":")
    if not method:
        raise ParseError(f"ledger ref has empty method: {lr!r}")
    if not is_valid_ledger_method(method):
        raise ParseError(f"ledger ref method {method!r} violates [a-z][a-z0-9-]*")
    return method, entry_ref
