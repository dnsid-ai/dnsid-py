"""Deterministically re-sign local fixtures under the corrected C2SP contract."""

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog.canonical import canonical_bytes
from dnsid.c2sp_tlog.event_codec import c2sp_event_id
from dnsid.c2sp_tlog.stream_verifier import state_hash


def correct_entries(entries, lr, keys=None):
    from dnsid.c2sp_tlog.lr import parse_c2sp_tlog_lr

    reference = parse_c2sp_tlog_lr(lr)
    keys = keys or {
        "ae": Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32),
        "op": Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32),
        "new_op": Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32),
    }
    result = []
    state = None
    for index, entry in enumerate(entries):
        obj = json.loads(entry)
        obj.update(
            method="c2sp-tlog",
            log_origin=reference.origin,
            stream_id=reference.stream_id,
            lr=lr,
            seq=index,
        )
        obj.pop("prev_index", None)
        obj.pop("prev_leaf_hash", None)
        if index:
            obj.update(prev_event_id=c2sp_event_id(result[-1]), prev_state_hash=state_hash(state))
        sigs = obj.pop("sigs")
        for role, member in (("ae", "ek"), ("op", "ku"), ("new_op", "new_ku")):
            if member in obj:
                obj[member]["x"] = b64url_encode(
                    keys[role].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                )
        if obj["type"] == "ISSUANCE":
            state = {
                "fqdn": obj["fqdn"],
                "status": "ACTIVE",
                "entity_thumb": jwk_from_dict(obj["ek"]).thumbprint(),
                "operational_thumb": jwk_from_dict(obj["ku"]).thumbprint(),
            }
        elif obj["type"] == "KEY_ROTATION":
            obj["prev_thumb"] = state["operational_thumb"]
            obj["new_thumb"] = jwk_from_dict(obj["new_ku"]).thumbprint()
            state["operational_thumb"] = obj["new_thumb"]
        elif obj["type"] in ("RETIREMENT", "REVOCATION"):
            state["status"] = "RETIRED" if obj["type"] == "RETIREMENT" else "REVOKED"
        signed = canonical_bytes(obj)
        for role, sig in sigs.items():
            sig["sig"] = b64url_encode(keys["op" if role == "prev_op" else role].sign(signed))
        obj["sigs"] = sigs
        result.append(canonical_bytes(obj))
    return result
