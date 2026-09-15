"""Cryptographic operations: JWK thumbprint, signature verification, and key parsing."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import JWK

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ._utils import b64url_decode, b64url_encode

# ---------------------------------------------------------------------------
# RFC 7638 thumbprint
# ---------------------------------------------------------------------------

# Required public members per key type (alphabetical — the spec mandates this order).
_THUMBPRINT_MEMBERS: dict[str, list[str]] = {
    "EC": ["crv", "kty", "x", "y"],
    "RSA": ["e", "kty", "n"],
    "OKP": ["crv", "kty", "x"],
}


def compute_thumbprint(raw: dict[str, Any]) -> str:
    """Return the RFC 7638 JWK thumbprint (SHA-256, unpadded base64url).

    Raises ValueError if the key type is unsupported or required members are missing.
    """
    kty = raw.get("kty", "")
    members = _THUMBPRINT_MEMBERS.get(kty)
    if members is None:
        raise ValueError(f"unsupported kty for thumbprint: {kty!r}")

    missing = [k for k in members if k not in raw]
    if missing:
        raise ValueError(f"JWK missing required thumbprint members: {missing}")

    canonical = {k: raw[k] for k in members}
    canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("ascii")
    digest = hashlib.sha256(canonical_json).digest()
    return b64url_encode(digest)


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

_EC_CURVES: dict[str, ec.EllipticCurve] = {
    "P-256": ec.SECP256R1(),
}

# Number of bytes per integer component (r or s) — ES256 / P-256 only.
_EC_COORD_BYTES: dict[str, int] = {
    "ES256": 32,
}

_EC_HASH: dict[str, type[hashes.HashAlgorithm]] = {
    "ES256": hashes.SHA256,
}

_RSA_HASH: dict[str, type[hashes.HashAlgorithm]] = {
    "RS256": hashes.SHA256,
}

# Supported kty/crv → JOSE alg mappings (EdDSA and ES256 only per DNSid protocol).
_KTY_CRV_TO_ALG: dict[tuple[str, str], str] = {
    ("OKP", "Ed25519"): "EdDSA",
    ("EC", "P-256"): "ES256",
}


def signature_alg_from_raw(raw: dict[str, Any]) -> str:
    """Derive JOSE signature algorithm from kty/crv.

    Raises ValueError if the kty/crv combination is not supported by the DNSid protocol.
    """
    kty = raw.get("kty", "")
    crv = raw.get("crv", "")
    alg = _KTY_CRV_TO_ALG.get((kty, crv))
    if alg is None:
        raise ValueError(
            f"unsupported kty/crv for DNSid signature algorithm: kty={kty!r}, crv={crv!r}"
        )
    return alg


_ALLOWED_ALGS: frozenset[str] = frozenset({"EdDSA", "ES256", "RS256"})


def verify_signature(raw: dict[str, Any], payload: bytes, signature: bytes) -> bool:
    """Return True if *signature* over *payload* is valid for the public key in *raw*.

    Returns False for an invalid signature; never raises for a bad sig value.
    When the JWK has no alg field, the algorithm is derived from kty/crv.
    Only EdDSA and ES256 are accepted; any other algorithm returns False.
    """
    kty = raw.get("kty", "")
    alg = raw.get("alg", "")

    # Derive alg from kty/crv when absent (alg is optional per DNSid design).
    if not alg:
        try:
            alg = signature_alg_from_raw(raw)
        except ValueError:
            return False

    if alg not in _ALLOWED_ALGS:
        return False

    try:
        if kty == "EC":
            return _verify_ec(raw, alg, payload, signature)
        if kty == "OKP":
            return _verify_okp(raw, payload, signature)
        if kty == "RSA":
            return _verify_rsa(raw, alg, payload, signature)
        return False
    except InvalidSignature:
        return False
    except Exception:
        return False


def _verify_ec(raw: dict[str, Any], alg: str, payload: bytes, sig: bytes) -> bool:
    crv = raw.get("crv", "")
    curve = _EC_CURVES.get(crv)
    if not curve:
        raise ValueError(f"unsupported EC curve: {crv!r}")

    hash_cls = _EC_HASH.get(alg)
    if not hash_cls:
        raise ValueError(f"unsupported EC alg: {alg!r}")

    x = int.from_bytes(b64url_decode(raw["x"]), "big")
    y = int.from_bytes(b64url_decode(raw["y"]), "big")
    pub_key = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve).public_key()

    # JWT/JWS/RFC 9421 use IEEE P1363 (r || s); cryptography expects DER.
    coord = _EC_COORD_BYTES.get(alg)
    if coord and len(sig) == 2 * coord:
        r = int.from_bytes(sig[:coord], "big")
        s = int.from_bytes(sig[coord:], "big")
        der_sig = encode_dss_signature(r, s)
    else:
        der_sig = sig  # fall through and let the library reject it

    pub_key.verify(der_sig, payload, ec.ECDSA(hash_cls()))
    return True


def _verify_okp(raw: dict[str, Any], payload: bytes, sig: bytes) -> bool:
    crv = raw.get("crv", "")
    if crv != "Ed25519":
        raise ValueError(f"unsupported OKP curve: {crv!r}")
    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(raw["x"]))
    pub_key.verify(sig, payload)
    return True


def _verify_rsa(raw: dict[str, Any], alg: str, payload: bytes, sig: bytes) -> bool:
    hash_cls = _RSA_HASH.get(alg)
    if not hash_cls:
        raise ValueError(f"unsupported RSA alg: {alg!r}")
    n = int.from_bytes(b64url_decode(raw["n"]), "big")
    e = int.from_bytes(b64url_decode(raw["e"]), "big")
    pub_key = rsa.RSAPublicNumbers(e=e, n=n).public_key()
    pub_key.verify(sig, payload, padding.PKCS1v15(), hash_cls())
    return True


# ---------------------------------------------------------------------------
# JWK construction from wire format
# ---------------------------------------------------------------------------


def jwk_from_dict(d: dict[str, Any]) -> JWK:
    """Build a JWK dataclass from a raw dict (e.g. from a parsed JWKS JSON response)."""
    from .models import JWK  # lazy import — models imports _utils, not _crypto

    return JWK(
        kty=d.get("kty", ""),
        alg=d.get("alg", ""),
        kid=d.get("kid", ""),
        use=d.get("use", ""),
        _raw=dict(d),
    )


# ---------------------------------------------------------------------------
# Helpers for building a JWK dict from a cryptography private/public key
# (used in tests to produce valid _raw dicts)
# ---------------------------------------------------------------------------


def ec_public_jwk_dict(
    private_key: ec.EllipticCurvePrivateKey, kid: str, alg: str
) -> dict[str, Any]:
    """Produce a public JWK dict from a cryptography EC private key (ES256/P-256 only)."""
    pub = private_key.public_key()
    numbers = pub.public_numbers()
    crv = {"secp256r1": "P-256"}[pub.curve.name]
    coord_len = _EC_COORD_BYTES[alg]
    return {
        "kty": "EC",
        "kid": kid,
        "alg": alg,
        "use": "sig",
        "crv": crv,
        "x": b64url_encode(numbers.x.to_bytes(coord_len, "big")),
        "y": b64url_encode(numbers.y.to_bytes(coord_len, "big")),
    }


def ed25519_public_jwk_dict(private_key: ed25519.Ed25519PrivateKey, kid: str) -> dict[str, Any]:
    """Produce a public JWK dict from a cryptography Ed25519 private key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "kty": "OKP",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
        "crv": "Ed25519",
        "x": b64url_encode(pub_bytes),
    }


def ec_sign(private_key: ec.EllipticCurvePrivateKey, alg: str, payload: bytes) -> bytes:
    """Sign *payload* with an EC private key; return IEEE P1363 (r||s) bytes."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    hash_cls = _EC_HASH[alg]
    der_sig = private_key.sign(payload, ec.ECDSA(hash_cls()))
    r, s = decode_dss_signature(der_sig)
    coord = _EC_COORD_BYTES[alg]
    return r.to_bytes(coord, "big") + s.to_bytes(coord, "big")


def ed25519_sign(private_key: ed25519.Ed25519PrivateKey, payload: bytes) -> bytes:
    """Sign *payload* with an Ed25519 private key."""
    return private_key.sign(payload)
