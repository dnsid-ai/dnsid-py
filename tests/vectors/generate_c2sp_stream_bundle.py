"""Regenerate the deterministic portable C2SP stream-bundle vector."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog import (
    C2spChain,
    C2spSignerRole,
    C2spVerificationContext,
    c2sp_event_id,
    canonical_bytes,
    entry_bytes,
    leaf_hash,
    merkle_root_from_entries,
    prepare_event,
    sign_prepared_event,
    state_hash,
)
from dnsid.models import IssuanceEvent, KeyRotationEvent

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "c2sp-stream-bundle-v1.json"
DOMAIN = "agent.example.com"
STREAM_ID = "EREREREREREREREREREREQ"
LR = f"c2sp-tlog:public:https://log.example#{STREAM_ID}"
WITNESS_TIME = 1_782_345_700


class _Provider:
    def __init__(self, raw: dict[str, str], private: ed25519.Ed25519PrivateKey):
        self.key = jwk_from_dict(raw)
        self.private = private

    def jwk(self, kid: str):
        assert kid == self.key.kid
        return self.key

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        assert kid == self.key.kid
        return self.private.sign(payload)


def _private(seed: int) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _raw_jwk(kid: str, private: ed25519.Ed25519PrivateKey) -> dict[str, str]:
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kid": kid,
        "kty": "OKP",
        "x": b64url_encode(public),
    }


def _verifier(name: str, private: ed25519.Ed25519PrivateKey, kind: int) -> tuple[str, bytes]:
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = bytes([kind]) + public
    key_hash = hashlib.sha256(name.encode() + b"\n" + encoded).digest()[:4]
    return (
        f"{name}+{key_hash.hex()}+{base64.b64encode(encoded).decode()}",
        key_hash,
    )


def _note_signature(
    name: str,
    key_hash: bytes,
    private: ed25519.Ed25519PrivateKey,
    signed_text: str,
) -> str:
    return "— " + name + " " + base64.b64encode(
        key_hash + private.sign(signed_text.encode())
    ).decode()


def _cosignature(
    name: str,
    key_hash: bytes,
    private: ed25519.Ed25519PrivateKey,
    signed_text: str,
) -> str:
    message = f"cosignature/v1\ntime {WITNESS_TIME}\n{signed_text}".encode()
    value = key_hash + WITNESS_TIME.to_bytes(8, "big") + private.sign(message)
    return "— " + name + " " + base64.b64encode(value).decode()


def build_vector() -> dict[str, object]:
    entity_private, old_private, new_private = _private(1), _private(2), _private(3)
    entity_raw = _raw_jwk("entity-1", entity_private)
    old_raw = _raw_jwk("operational-1", old_private)
    new_raw = _raw_jwk("operational-2", new_private)
    entity, old, new = map(jwk_from_dict, (entity_raw, old_raw, new_raw))

    issuance = IssuanceEvent(
        domain=DOMAIN,
        governance_id="example.com",
        timestamp=datetime.datetime.fromtimestamp(1_782_172_800, tz=datetime.UTC),
        entity_key=entity,
        operational_key=old,
    )
    issuance_prepared = sign_prepared_event(
        prepare_event(issuance, LR),
        C2spSignerRole.ENTITY,
        _Provider(entity_raw, entity_private),
    )
    issuance_prepared = sign_prepared_event(
        issuance_prepared,
        C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
        _Provider(old_raw, old_private),
        C2spVerificationContext(
            fqdn=DOMAIN,
            gi="example.com",
            entity_key=entity,
            operational_key=old,
        ),
    )
    issuance_bytes = entry_bytes(issuance_prepared)

    rotation = KeyRotationEvent(
        domain=DOMAIN,
        previous_kid=old.kid,
        previous_thumbprint=old.thumbprint(),
        new_kid=new.kid,
        new_thumbprint=new.thumbprint(),
        new_public_key=new,
        timestamp=datetime.datetime.fromtimestamp(1_782_259_200, tz=datetime.UTC),
    )
    previous_state = {
        "fqdn": DOMAIN,
        "status": "ACTIVE",
        "entity_thumb": entity.thumbprint(),
        "operational_thumb": old.thumbprint(),
    }
    chain = C2spChain(
        sequence=1,
        previous_event_id=c2sp_event_id(issuance_bytes),
        previous_state_hash=state_hash(previous_state),
    )
    rotation_prepared = prepare_event(rotation, LR, chain)
    rotation_context = C2spVerificationContext(previous_operational_key=old)
    rotation_prepared = sign_prepared_event(
        rotation_prepared,
        C2spSignerRole.PREVIOUS_OPERATIONAL,
        _Provider(old_raw, old_private),
        rotation_context,
    )
    rotation_prepared = sign_prepared_event(
        rotation_prepared,
        C2spSignerRole.NEW_OPERATIONAL,
        _Provider(new_raw, new_private),
        rotation_context,
    )
    rotation_bytes = entry_bytes(rotation_prepared, rotation_context)
    entries = [issuance_bytes, rotation_bytes]

    log_private, witness_private, bundle_private = _private(4), _private(5), _private(6)
    log_verifier, log_hash = _verifier("log.example", log_private, 1)
    witness_verifier, witness_hash = _verifier(
        "witness.example", witness_private, 4
    )
    bundle_verifier, bundle_hash = _verifier(
        "bundle.example", bundle_private, 1
    )
    policy = (
        f"log {log_verifier}\n"
        f"witness primary {witness_verifier}\n"
        "quorum primary\n"
    ).encode()
    root = merkle_root_from_entries(entries)
    signed_text = f"log.example\n2\n{base64.b64encode(root).decode()}\n"
    checkpoint = (
        signed_text
        + "\n"
        + _note_signature("log.example", log_hash, log_private, signed_text)
        + "\n"
        + _cosignature(
            "witness.example", witness_hash, witness_private, signed_text
        )
        + "\n"
    ).encode()

    proofs = [[leaf_hash(rotation_bytes)], [leaf_hash(issuance_bytes)]]
    unsigned: dict[str, object] = {
        "v": 1,
        "type": "dnsid-c2sp-stream-bundle",
        "fqdn": DOMAIN,
        "lr": LR,
        "checkpoint": b64url_encode(checkpoint),
        "policy_hash": b64url_encode(hashlib.sha256(policy).digest()),
        "complete_through_size": 2,
        "completeness_mode": "trusted-index",
        "events": [
            {
                "index": index,
                "entry": b64url_encode(entry),
                "proof": b64url_encode(b"".join(proofs[index])),
            }
            for index, entry in enumerate(entries)
        ],
        "state": {
            "event_count": 2,
            "last_event_type": "KEY_ROTATION",
            "logged_state": "ACTIVE",
        },
        "expires": WITNESS_TIME + 300,
    }
    unsigned_bytes = canonical_bytes(unsigned)
    bundle = dict(unsigned)
    bundle["sig"] = {
        "alg": "EdDSA",
        "kid": f"bundle.example+{bundle_hash.hex()}",
        "value": b64url_encode(bundle_private.sign(unsigned_bytes)),
    }
    bundle_bytes = canonical_bytes(bundle)
    return {
        "format": "dnsid-c2sp-stream-bundle@v1",
        "bundle": bundle_bytes.decode(),
        "unsigned_bundle": unsigned_bytes.decode(),
        "policy": policy.decode(),
        "trust": {
            "bundle_verifier_key": bundle_verifier,
            "entity_jwk": entity_raw,
            "now": WITNESS_TIME + 60,
            "checkpoint_freshness_ms": 120000,
            "max_bundle_lifetime_ms": 300000,
        },
        "expected": {
            "status": "ACTIVE",
            "event_count": 2,
            "active_operational_thumbprint": new.thumbprint(),
            "bundle_signer_kid": f"bundle.example+{bundle_hash.hex()}",
        },
        "negative_mutations": [
            {"name": "padded-policy-hash", "path": "/policy_hash", "append": "=", "error": "canonical unpadded base64url"},
            {"name": "wrong-state", "path": "/state/logged_state", "value": "REVOKED", "resign": True, "error": "state does not match replay"},
            {"name": "expired", "path": "/expires", "value": WITNESS_TIME, "resign": True, "error": "expired"},
            {"name": "unsupported-completeness", "path": "/completeness_mode", "value": "untrusted-index", "resign": True, "error": "unsupported"},
            {"name": "out-of-order-index", "path": "/events/1/index", "value": 0, "resign": True, "error": "indexes"},
            {"name": "proof-length", "path": "/events/0/proof", "value": "AA", "resign": True, "error": "proof length"},
        ],
    }


if __name__ == "__main__":
    OUTPUT.write_text(json.dumps(build_vector(), indent=2, sort_keys=True) + "\n")
