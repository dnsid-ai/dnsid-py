"""ENTITY_KEY_ROTATION: entity-key continuity for the c2sp-tlog binding."""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from dnsid import EntityKeyRotationEvent
from dnsid._crypto import ed25519_public_jwk_dict, jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog import (
    C2spChain,
    C2spEventContext,
    C2spSignerRole,
    C2spTlogParseError,
    C2spTlogVerificationError,
    C2spTlogVerificationOptions,
    C2spVerificationContext,
    IndexedEntry,
    StreamVerifierOptions,
    canonical_bytes,
    create_c2sp_tlog_verification_registry,
    encode_entry_bundle,
    entry_bytes,
    leaf_hash,
    merkle_root_from_entries,
    parse_c2sp_event_entry,
    parse_c2sp_tlog_lr,
    prepare_event,
    sign_prepared_event,
    verify_lifecycle,
    verify_stream_lifecycle,
)
from dnsid.c2sp_tlog.errors import C2spLifecycleErrorCategory
from dnsid.c2sp_tlog.event_codec import (
    c2sp_event_id,
    event_to_c2sp_envelope,
    required_c2sp_signature_names,
)
from dnsid.c2sp_tlog.merkle import node_hash
from dnsid.c2sp_tlog.prepared import required_signer_roles
from dnsid.c2sp_tlog.stream_verifier import state_hash
from dnsid.enums import EventType, LogSignerRole
from dnsid.exceptions import ArgumentError, LifecycleVerificationError, VerificationError
from dnsid.manager import _required_log_signatures, sign_event_with_provider
from dnsid.models import DomainLog, IssuanceEvent, KeyRotationEvent, MigrationEvent
from tests.conftest import RealKeyProvider
from tests.test_c2sp_migration import _bundle_key, _checkpoint, _Fetcher, _verifier_key

DOMAIN = "agent.example"
LR = "c2sp-tlog:testnet:https://log.example#identity-instance"
CONTEXT = C2spEventContext(
    scope="testnet", log_origin="log.example", stream_id="identity-instance", lr=LR
)
NOW = datetime.datetime.now(datetime.UTC).replace(microsecond=0)


@dataclass
class _Signer:
    kid: str
    private: ed25519.Ed25519PrivateKey
    jwk: Any

    def sign(self, data: bytes) -> str:
        return b64url_encode(self.private.sign(data))


def _key(kid: str) -> _Signer:
    private = ed25519.Ed25519PrivateKey.generate()
    return _Signer(kid, private, jwk_from_dict(ed25519_public_jwk_dict(private, kid)))


def _impostor(kid: str) -> _Signer:
    """A different key that claims *kid*."""
    return replace(_key("impostor"), kid=kid)


class _Stream:
    """Builds correctly chained public lifecycle entries for one stream."""

    def __init__(self, lr: str = LR, start: int | None = None) -> None:
        reference = parse_c2sp_tlog_lr(lr)
        self.base = dict(
            v=1, kind="dnsid.lifecycle", fqdn=DOMAIN, method="c2sp-tlog",
            log_origin=reference.origin, stream_id=reference.stream_id, lr=lr,
        )
        self.entries: list[bytes] = []
        self.last: bytes | None = None
        self.state: dict[str, str] | None = None
        self.ts = start if start is not None else int(NOW.timestamp()) - 600
        self.entity: _Signer | None = None
        self.operational: _Signer | None = None

    def _payload(self, type_: str, fields: dict[str, Any]) -> dict[str, Any]:
        self.ts += 1
        obj = dict(self.base, type=type_, ts=self.ts, **fields)
        if self.last is None:
            obj["seq"] = 0
        else:
            obj.update(
                seq=json.loads(self.last)["seq"] + 1,
                prev_event_id=c2sp_event_id(self.last),
                prev_state_hash=state_hash(self.state),
            )
        return obj

    def _emit(self, obj: dict[str, Any], sigs: dict[str, _Signer | None], apply: bool,
              state: dict[str, str] | None) -> bytes:
        signed = canonical_bytes(obj)
        data = canonical_bytes(dict(obj, sigs={
            role: {"kid": signer.kid, "sig": signer.sign(signed)}
            for role, signer in sigs.items() if signer is not None
        }))
        self.entries.append(data)
        if apply:
            self.last, self.state = data, state
        return data

    def _active(self, entity: _Signer, operational: _Signer, status: str = "ACTIVE"):
        return {
            "fqdn": DOMAIN, "status": status,
            "entity_thumb": entity.jwk.thumbprint(),
            "operational_thumb": operational.jwk.thumbprint(),
        }

    def issuance(self, entity: _Signer, operational: _Signer, *, apply: bool = True) -> bytes:
        obj = self._payload("ISSUANCE", dict(gi="example", ek=entity.jwk._raw,
                                             ku=operational.jwk._raw))
        data = self._emit(obj, {"ae": entity, "op": operational}, apply,
                          self._active(entity, operational))
        if apply:
            self.entity, self.operational = entity, operational
        return data

    def entity_rotation(self, new: _Signer, *, prev_signer: _Signer | None = None,
                        new_signer: _Signer | None | str = "default",
                        prev_thumb: str | None = None, apply: bool = True) -> bytes:
        assert self.entity is not None and self.operational is not None
        obj = self._payload("ENTITY_KEY_ROTATION", dict(
            prev_ek_thumb=prev_thumb or self.entity.jwk.thumbprint(),
            new_ek=new.jwk._raw,
            new_ek_thumb=new.jwk.thumbprint(),
        ))
        signer = new if new_signer == "default" else new_signer
        assert signer is None or isinstance(signer, _Signer)
        data = self._emit(obj, {"prev_ae": prev_signer or self.entity, "new_ae": signer},
                          apply, self._active(new, self.operational))
        if apply:
            self.entity = new
        return data

    def key_rotation(self, new: _Signer, *, apply: bool = True) -> bytes:
        assert self.entity is not None and self.operational is not None
        obj = self._payload("KEY_ROTATION", dict(
            prev_thumb=self.operational.jwk.thumbprint(),
            new_ku=new.jwk._raw,
            new_thumb=new.jwk.thumbprint(),
        ))
        data = self._emit(obj, {"prev_op": self.operational, "new_op": new}, apply,
                          self._active(self.entity, new))
        if apply:
            self.operational = new
        return data

    def terminal(self, type_: str, *, signer: _Signer | None = None, apply: bool = True) -> bytes:
        assert self.entity is not None and self.operational is not None
        fields = {"reason": "keyCompromise"} if type_ == "REVOCATION" else {}
        status = "REVOKED" if type_ == "REVOCATION" else "RETIRED"
        obj = self._payload(type_, fields)
        return self._emit(obj, {"ae": signer or self.entity}, apply,
                          self._active(self.entity, self.operational, status))


def _verify(entries: list[bytes], record_ek: Any, **kwargs: Any):
    return verify_stream_lifecycle(
        [IndexedEntry(i, e) for i, e in enumerate(entries)],
        DOMAIN,
        StreamVerifierOptions(
            context=CONTEXT, signer_key=record_ek,
            checkpoint_integration_time_ms=4_000_000_000_000, **kwargs,
        ),
    )


def _types(selected) -> list[str]:
    return [str(item.event.event_type) for item in selected]


@pytest.fixture
def keys() -> SimpleNamespace:
    return SimpleNamespace(
        e1=_key("entity-1"), e2=_key("entity-2"), e3=_key("entity-3"),
        o1=_key("operational-1"), o2=_key("operational-2"), o3=_key("operational-3"),
        attacker=_key("attacker"),
    )


# ---------------------------------------------------------------------------
# Wire format and structural validation
# ---------------------------------------------------------------------------


def _rotation_event(keys: SimpleNamespace, **overrides: Any) -> EntityKeyRotationEvent:
    values: dict[str, Any] = dict(
        domain=DOMAIN,
        previous_entity_kid=keys.e1.kid,
        previous_entity_thumbprint=keys.e1.jwk.thumbprint(),
        new_entity_kid=keys.e2.kid,
        new_entity_thumbprint=keys.e2.jwk.thumbprint(),
        new_entity_public_key=keys.e2.jwk,
        timestamp=datetime.datetime.fromtimestamp(1_700_000_000, datetime.UTC),
    )
    values.update(overrides)
    return EntityKeyRotationEvent(**values)


def test_wire_names_roles_and_round_trip(keys):
    assert EventType.ENTITY_KEY_ROTATION == "ENTITY_KEY_ROTATION"
    assert required_c2sp_signature_names("ENTITY_KEY_ROTATION") == ["prev_ae", "new_ae"]
    assert required_signer_roles("ENTITY_KEY_ROTATION") == [
        C2spSignerRole.PREVIOUS_ENTITY, C2spSignerRole.NEW_ENTITY,
    ]
    assert _required_log_signatures(EntityKeyRotationEvent()) == [
        LogSignerRole.PREVIOUS_ENTITY, LogSignerRole.NEW_ENTITY,
    ]
    context = replace(CONTEXT, seq=1, prev_event_id=b64url_encode(bytes(32)),
                      prev_state_hash=b64url_encode(bytes(32)))
    unsigned = event_to_c2sp_envelope(_rotation_event(keys), context, include_sigs=False)
    assert {"prev_ek_thumb", "new_ek_thumb", "new_ek"} <= unsigned.keys()
    signed = canonical_bytes(unsigned)
    event = _rotation_event(keys, signing_kid=keys.e1.kid, sig=keys.e1.sign(signed),
                            new_entity_proof=keys.e2.sign(signed))
    envelope = event_to_c2sp_envelope(event, context)
    assert envelope["sigs"] == {
        "prev_ae": {"kid": keys.e1.kid, "sig": event.sig},
        "new_ae": {"kid": keys.e2.kid, "sig": event.new_entity_proof},
    }
    parsed = parse_c2sp_event_entry(canonical_bytes(envelope), context)
    assert isinstance(parsed, EntityKeyRotationEvent)
    assert parsed == event
    assert parsed.new_entity_public_key.thumbprint() == keys.e2.jwk.thumbprint()


def _envelope(keys: SimpleNamespace, mutate) -> bytes:
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    obj = json.loads(stream.entity_rotation(keys.e2))
    mutate(obj)
    return canonical_bytes(obj)


@pytest.mark.parametrize(
    ("name", "mutate", "message"),
    [
        ("thumb mismatch", lambda o: o.update(new_ek_thumb=o["prev_ek_thumb"][::-1]),
         "new_ek_thumb does not match"),
        ("private new_ek", lambda o: o["new_ek"].update(d="AAAA"), "must be public"),
        ("missing kid", lambda o: o["new_ek"].pop("kid"), "new_ek.kid"),
        ("missing alg", lambda o: o["new_ek"].pop("alg"), "new_ek.alg"),
        ("encryption use", lambda o: o["new_ek"].update(use="enc"), "for signatures"),
        ("unsupported alg", lambda o: o["new_ek"].update(alg="ES256"), "EdDSA with Ed25519"),
        ("unsupported kty", lambda o: o["new_ek"].update(kty="RSA"), "unsupported key type"),
        ("same thumbprints", lambda o: o.update(prev_ek_thumb=o["new_ek_thumb"]),
         "must differ"),
        ("missing new_ek", lambda o: o.pop("new_ek"), "missing new_ek"),
        ("missing prev_ek_thumb", lambda o: o.pop("prev_ek_thumb"), "prev_ek_thumb"),
        ("missing new_ek_thumb", lambda o: o.pop("new_ek_thumb"), "new_ek_thumb"),
        ("new_ae kid", lambda o: o["sigs"]["new_ae"].update(kid="other"),
         "new_ae kid does not match"),
        ("missing new_ae", lambda o: o["sigs"].pop("new_ae"), "sigs.new_ae"),
    ],
)
def test_structural_validation_rejects(keys, name, mutate, message):
    with pytest.raises(C2spTlogParseError, match=message):
        parse_c2sp_event_entry(_envelope(keys, mutate), CONTEXT)


def test_envelope_signature_members_for_entity_rotation():
    from dnsid.c2sp_tlog.event_codec import parse_c2sp_signatures

    sig = {"kid": "k", "sig": b64url_encode(bytes(64))}
    parsed = parse_c2sp_signatures({"prev_ae": sig, "new_ae": sig}, "ENTITY_KEY_ROTATION")
    assert set(parsed) == {"prev_ae", "new_ae"}
    for extra in ("ae", "prev_op", "new_op", "op"):
        with pytest.raises(C2spTlogParseError, match="unexpected signature role"):
            parse_c2sp_signatures(
                {"prev_ae": sig, "new_ae": sig, extra: sig}, "ENTITY_KEY_ROTATION",
            )
    with pytest.raises(C2spTlogParseError, match="unexpected signature role"):
        parse_c2sp_signatures({"prev_op": sig, "new_ae": sig}, "KEY_ROTATION")


def test_encoder_applies_the_same_structural_rules(keys):
    context = replace(CONTEXT, seq=1, prev_event_id=b64url_encode(bytes(32)),
                      prev_state_hash=b64url_encode(bytes(32)))
    private = jwk_from_dict(dict(keys.e2.jwk._raw, d="AAAA"))
    for event, message in (
        (_rotation_event(keys, new_entity_public_key=private), "must be public"),
        (_rotation_event(keys, new_entity_thumbprint="wrong"), "does not match"),
        (_rotation_event(keys, previous_entity_thumbprint=keys.e2.jwk.thumbprint()),
         "must differ"),
        (_rotation_event(keys, new_entity_public_key=None), "missing"),
        (_rotation_event(keys, new_entity_kid="other"), "new_entity_kid"),
    ):
        with pytest.raises(C2spTlogParseError, match=message):
            event_to_c2sp_envelope(event, context, include_sigs=False)


def test_es256_new_entity_key_is_accepted(keys):
    from tests.conftest import make_ec_p256_pair

    _private, ec_jwk = make_ec_p256_pair("entity-ec")
    obj = json.loads(_envelope(keys, lambda o: None))
    obj.update(new_ek=ec_jwk._raw, new_ek_thumb=ec_jwk.thumbprint())
    obj["sigs"]["new_ae"]["kid"] = "entity-ec"
    event = parse_c2sp_event_entry(canonical_bytes(obj), CONTEXT)
    assert isinstance(event, EntityKeyRotationEvent)
    assert event.new_entity_public_key.kty == "EC"


# ---------------------------------------------------------------------------
# Conformance cases (contract section "Conformance")
# ---------------------------------------------------------------------------


def test_case1_rotation_moves_the_record_binding(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    selected = _verify(stream.entries, keys.e2.jwk)
    assert _types(selected) == ["ISSUANCE", "ENTITY_KEY_ROTATION"]
    assert selected[-1].post_keys[0].thumbprint() == keys.e2.jwk.thumbprint()
    with pytest.raises(C2spTlogVerificationError,
                       match="current entity key does not match record ek for agent.example"):
        _verify(stream.entries, keys.e1.jwk)


def test_case2_chained_rotations_end_at_the_latest_key(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    stream.entity_rotation(keys.e3)
    selected = _verify(stream.entries, keys.e3.jwk)
    assert _types(selected) == ["ISSUANCE", "ENTITY_KEY_ROTATION", "ENTITY_KEY_ROTATION"]
    for stale in (keys.e1, keys.e2):
        with pytest.raises(C2spTlogVerificationError, match="does not match record ek"):
            _verify(stream.entries, stale.jwk)


@pytest.mark.parametrize("bad_signer", ["wrong-key-same-kid", "new-key", "attacker"])
def test_case3_bad_prev_ae_is_skipped(keys, bad_signer):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    prev = {
        "wrong-key-same-kid": _impostor(keys.e1.kid),
        "new-key": keys.e2,
        "attacker": keys.attacker,
    }[bad_signer]
    stream.entity_rotation(keys.e2, prev_signer=prev, apply=False)
    assert _types(_verify(stream.entries, keys.e1.jwk)) == ["ISSUANCE"]
    with pytest.raises(C2spTlogVerificationError, match="does not match record ek"):
        _verify(stream.entries, keys.e2.jwk)


@pytest.mark.parametrize("new_ae", ["wrong-key-same-kid", "previous-key", "missing"])
def test_case4_bad_or_missing_new_ae_is_skipped(keys, new_ae):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    signer = {
        "wrong-key-same-kid": _impostor(keys.e2.kid),
        "previous-key": replace(keys.e1, kid=keys.e2.kid),
        "missing": None,
    }[new_ae]
    stream.entity_rotation(keys.e2, new_signer=signer, apply=False)
    assert _types(_verify(stream.entries, keys.e1.jwk)) == ["ISSUANCE"]
    with pytest.raises(C2spTlogVerificationError):
        _verify(stream.entries, keys.e2.jwk)


@pytest.mark.parametrize("record", ["e1", "e2"])
def test_case5_prev_ek_thumb_must_continue_from_the_active_key(keys, record):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2, prev_thumb=keys.e3.jwk.thumbprint(), apply=False)
    with pytest.raises(C2spTlogVerificationError) as exc:
        _verify(stream.entries, getattr(keys, record).jwk)
    assert exc.value.category == C2spLifecycleErrorCategory.KEY_CONTINUITY
    assert "does not continue from the active entity key" in str(exc.value.__cause__)
    assert exc.value.failing_candidate_index == 1


def test_case6_new_entity_key_may_not_be_the_operational_key(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.o1, apply=False)
    with pytest.raises(C2spTlogVerificationError) as exc:
        _verify(stream.entries, keys.e1.jwk)
    assert exc.value.category == C2spLifecycleErrorCategory.KEY_CONTINUITY
    assert "new key binding is invalid" in str(exc.value.__cause__)


def test_case7_terminal_events_bind_to_the_rotated_entity_key(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    stream.terminal("REVOCATION", signer=keys.e1, apply=False)
    stream.terminal("RETIREMENT", signer=keys.e1, apply=False)
    assert _types(_verify(stream.entries, keys.e2.jwk)) == ["ISSUANCE", "ENTITY_KEY_ROTATION"]
    stream.terminal("REVOCATION")
    selected = _verify(stream.entries, keys.e2.jwk)
    assert _types(selected) == ["ISSUANCE", "ENTITY_KEY_ROTATION", "REVOCATION"]
    assert selected[-1].event.signing_kid == keys.e2.kid


def test_case8_operational_and_entity_continuity_interleave(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.key_rotation(keys.o2)
    stream.entity_rotation(keys.e2)
    stream.key_rotation(keys.o3)
    selected = _verify(stream.entries, keys.e2.jwk)
    assert _types(selected) == [
        "ISSUANCE", "KEY_ROTATION", "ENTITY_KEY_ROTATION", "KEY_ROTATION",
    ]
    entity, operational = selected[-1].post_keys
    assert entity.thumbprint() == keys.e2.jwk.thumbprint()
    assert operational.thumbprint() == keys.o3.jwk.thumbprint()
    # KEY_ROTATION may not install the (rotated) current entity key.
    stream.key_rotation(keys.e2, apply=False)
    with pytest.raises(C2spTlogVerificationError) as exc:
        _verify(stream.entries, keys.e2.jwk)
    assert exc.value.category == C2spLifecycleErrorCategory.KEY_CONTINUITY


def test_case9_rotation_cannot_start_a_stream(keys):
    stream = _Stream()
    stream.entity = keys.e1
    stream.operational = keys.o1
    stream.state = stream._active(keys.e1, keys.o1)
    obj = stream._payload("ENTITY_KEY_ROTATION", dict(
        prev_ek_thumb=keys.e1.jwk.thumbprint(), new_ek=keys.e2.jwk._raw,
        new_ek_thumb=keys.e2.jwk.thumbprint(),
    ))
    stream._emit(obj, {"prev_ae": keys.e1, "new_ae": keys.e2}, True, None)
    for record in (keys.e1, keys.e2):
        with pytest.raises(C2spTlogVerificationError, match="no ISSUANCE"):
            _verify(stream.entries, record.jwk)


def test_case10_rotation_after_retirement_is_terminal_state(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.terminal("RETIREMENT")
    stream.entity_rotation(keys.e2, apply=False)
    for record in (keys.e1, keys.e2):
        with pytest.raises(C2spTlogVerificationError) as exc:
            _verify(stream.entries, record.jwk)
        assert exc.value.category == C2spLifecycleErrorCategory.TERMINAL_STATE


def _resigned_rotation(keys: SimpleNamespace, mutate, *, new_signer: _Signer | None = None):
    """ISSUANCE plus a rotation mutated after signing, then signed by E1 and E2."""
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    rotation = json.loads(stream.entity_rotation(keys.e2, apply=False))
    original_sigs = rotation.pop("sigs")
    mutate(rotation)
    signed = canonical_bytes(rotation)
    signer = new_signer or keys.e2
    authenticated = canonical_bytes(dict(rotation, sigs={
        "prev_ae": {"kid": keys.e1.kid, "sig": keys.e1.sign(signed)},
        "new_ae": {"kid": signer.kid, "sig": signer.sign(signed)},
    }))
    unauthenticated = canonical_bytes(dict(rotation, sigs=original_sigs))
    return stream.entries[0], authenticated, unauthenticated


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: o.update(new_ek_thumb=o["prev_ek_thumb"][::-1]),
        lambda o: o.update(prev_ek_thumb=o["new_ek_thumb"]),
        lambda o: o["new_ek"].pop("alg"),
        lambda o: o["new_ek"].update(alg="ES256"),
        lambda o: o["new_ek"].update(use="enc"),
    ],
    ids=["thumb-mismatch", "same-thumb", "missing-alg", "wrong-alg", "enc-use"],
)
def test_case11_authenticated_malformed_rotation_is_fatal(keys, mutate):
    genesis, authenticated, unauthenticated = _resigned_rotation(keys, mutate)
    assert _types(_verify([genesis, unauthenticated], keys.e1.jwk)) == ["ISSUANCE"]
    with pytest.raises(C2spTlogVerificationError) as exc:
        _verify([genesis, authenticated], keys.e1.jwk)
    assert exc.value.category == C2spLifecycleErrorCategory.INVALID_EVIDENCE
    assert exc.value.failing_candidate_index == 1


@pytest.mark.parametrize(
    ("mutate", "new_ae_kid"),
    [
        (lambda o: o["new_ek"].pop("kid"), "entity-2"),
        (lambda o: o["new_ek"].update(kid=""), "entity-2"),
        (lambda o: None, "other-kid"),
    ],
    ids=["missing-kid", "empty-kid", "new-ae-names-other-kid"],
)
def test_new_ek_kid_problems_are_noise_even_when_both_signatures_verify(
    keys, mutate, new_ae_kid,
):
    genesis, authenticated, _ = _resigned_rotation(
        keys, mutate, new_signer=replace(keys.e2, kid=new_ae_kid),
    )
    assert _types(_verify([genesis, authenticated], keys.e1.jwk)) == ["ISSUANCE"]
    with pytest.raises(C2spTlogVerificationError):
        _verify([genesis, authenticated], keys.e2.jwk)


@pytest.mark.parametrize("member", ["d", "p", "q", "dp", "dq", "qi", "k", "oth"])
def test_case11_private_new_ek_is_noise_even_when_both_signatures_verify(keys, member):
    genesis, authenticated, _ = _resigned_rotation(
        keys, lambda o: o["new_ek"].update({member: b64url_encode(bytes(32))}),
    )
    with pytest.raises(C2spTlogParseError, match="must be public"):
        parse_c2sp_event_entry(authenticated, CONTEXT)
    assert _types(_verify([genesis, authenticated], keys.e1.jwk)) == ["ISSUANCE"]
    with pytest.raises(C2spTlogVerificationError):
        _verify([genesis, authenticated], keys.e2.jwk)


def test_malformed_rotation_by_a_non_active_key_is_skipped(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    rotation = json.loads(stream.entity_rotation(keys.e2, apply=False))
    rotation.pop("sigs")
    rotation["new_ek_thumb"] = rotation["prev_ek_thumb"][::-1]
    signed = canonical_bytes(rotation)
    forged = canonical_bytes(dict(rotation, sigs={
        "prev_ae": {"kid": keys.e1.kid, "sig": keys.attacker.sign(signed)},
        "new_ae": {"kid": keys.e2.kid, "sig": keys.e2.sign(signed)},
    }))
    assert _types(_verify([stream.entries[0], forged], keys.e1.jwk)) == ["ISSUANCE"]


# ---------------------------------------------------------------------------
# Amendment 1: genesis selection anchored on the end-of-history entity key
# ---------------------------------------------------------------------------


def _spam_issuance(stream: _Stream, keys: SimpleNamespace) -> bytes:
    """A self-authenticated ISSUANCE for the same identity under another ek."""
    spam = _Stream()
    spam.ts = stream.ts
    return spam.issuance(keys.attacker, _key("attacker-op"))


@pytest.mark.parametrize("rotate", [False, True])
def test_spam_genesis_ahead_of_the_real_one_is_still_skipped(keys, rotate):
    real = _Stream()
    spam = _spam_issuance(real, keys)
    real.issuance(keys.e1, keys.o1)
    if rotate:
        real.entity_rotation(keys.e2)
    record = keys.e2 if rotate else keys.e1
    selected = _verify([spam, *real.entries], record.jwk)
    assert [item.index for item in selected] == list(range(1, len(real.entries) + 1))
    assert selected[0].event.entity_key.thumbprint() == keys.e1.jwk.thumbprint()


def test_attacker_genesis_cannot_reach_the_record_key_without_new_ae(keys):
    real = _Stream()
    real.issuance(keys.e1, keys.o1)
    legit_rotation = json.loads(real.entity_rotation(keys.e2))
    attacker = _Stream()
    attacker.issuance(keys.attacker, _key("attacker-op"))
    # Claims the record key, but new_ae is the attacker's own signature.
    attacker.entity_rotation(keys.e2, new_signer=replace(keys.attacker, kid=keys.e2.kid))
    # Replays the legitimate new_ae: it covers different chain-bound bytes.
    obj = json.loads(attacker.entity_rotation(keys.e3, apply=False))
    copied = dict(obj, new_ek=keys.e2.jwk._raw, new_ek_thumb=keys.e2.jwk.thumbprint())
    copied["sigs"] = dict(obj["sigs"], new_ae=legit_rotation["sigs"]["new_ae"])
    attacker.entries[-1] = canonical_bytes(copied)
    with pytest.raises(C2spTlogVerificationError, match="no ISSUANCE"):
        _verify(attacker.entries, keys.e2.jwk)
    stream = [*attacker.entries, *real.entries]
    selected = _verify(stream, keys.e2.jwk)
    first_real = len(attacker.entries)
    assert [item.index for item in selected] == [first_real, first_real + 1]


def test_end_of_history_mismatch_reports_the_record_ek_error(keys):
    first = _Stream()
    first.issuance(keys.e1, keys.o1)
    first.entity_rotation(keys.e2)
    first.entity_rotation(keys.e3)
    # Record still names E2; the only genesis replays to E3.
    with pytest.raises(C2spTlogVerificationError, match="does not match record ek"):
        _verify(first.entries, keys.e2.jwk)


def test_forged_genesis_claiming_the_record_key_is_not_replayed(keys, monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as verifier

    real = _Stream()
    real.issuance(keys.e1, keys.o1)
    real.entity_rotation(keys.e2)
    forged = []
    for _ in range(5):
        obj = json.loads(_Stream().issuance(keys.attacker, _key("forged-op")))
        obj["ek"] = keys.e2.jwk._raw
        obj["sigs"]["ae"]["kid"] = keys.e2.kid
        forged.append(canonical_bytes(obj))
    trials = []
    original = verifier._select_lifecycle

    def counting(*args, **kwargs):
        trials.append(args[3])
        return original(*args, **kwargs)

    monkeypatch.setattr(verifier, "_select_lifecycle", counting)
    selected = _verify([*forged, *real.entries], keys.e2.jwk)
    assert [item.index for item in selected] == [5, 6]
    assert trials == [5]


def test_stale_record_key_cannot_select_a_copied_genesis(keys):
    stream = _Stream()
    genesis = stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    stream.terminal("REVOCATION")
    entries = [*stream.entries, genesis]
    with pytest.raises(C2spTlogVerificationError, match="does not match record ek"):
        _verify(entries, keys.e1.jwk)
    selected = _verify(entries, keys.e2.jwk)
    assert _types(selected) == ["ISSUANCE", "ENTITY_KEY_ROTATION", "REVOCATION"]


def test_superseded_key_cannot_start_a_fresh_history_under_a_stale_record(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    stream.terminal("REVOCATION")
    fresh = _Stream()
    fresh.ts = stream.ts
    entries = [*stream.entries, fresh.issuance(keys.e1, keys.o1)]
    with pytest.raises(C2spTlogVerificationError, match="does not match record ek"):
        _verify(entries, keys.e1.jwk)
    assert _types(_verify(entries, keys.e2.jwk))[-1] == "REVOCATION"


def test_delegation_binds_to_the_rotated_entity_key(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)

    def delegation(signer: _Signer, apply: bool) -> bytes:
        obj = stream._payload("DELEGATION", dict(
            delegatee="helper.example", scope="read", expiry=stream.ts + 3600,
        ))
        return stream._emit(obj, {"ae": signer}, apply, stream.state)

    delegation(keys.e1, False)
    assert _types(_verify(stream.entries, keys.e2.jwk)) == ["ISSUANCE", "ENTITY_KEY_ROTATION"]
    delegation(keys.e2, True)
    assert _types(_verify(stream.entries, keys.e2.jwk))[-1] == "DELEGATION"


def test_rotating_back_to_an_earlier_entity_key(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    stream.entity_rotation(keys.e1)
    selected = _verify(stream.entries, keys.e1.jwk)
    assert _types(selected) == ["ISSUANCE", "ENTITY_KEY_ROTATION", "ENTITY_KEY_ROTATION"]
    with pytest.raises(C2spTlogVerificationError, match="does not match record ek"):
        _verify(stream.entries, keys.e2.jwk)


def test_entity_keys_may_share_a_kid(keys):
    shared = replace(_key("entity-1"), kid=keys.e1.kid)
    shared.jwk = jwk_from_dict(ed25519_public_jwk_dict(shared.private, keys.e1.kid))
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(shared)
    stream.terminal("RETIREMENT", signer=keys.e1, apply=False)
    selected = _verify(stream.entries, shared.jwk)
    assert _types(selected) == ["ISSUANCE", "ENTITY_KEY_ROTATION"]
    stream.terminal("RETIREMENT")
    assert _types(_verify(stream.entries, shared.jwk))[-1] == "RETIREMENT"


def test_prepared_new_entity_signing_rejects_a_malformed_new_ek(keys):
    stream = _Stream()
    genesis = stream.issuance(keys.e1, keys.o1)
    chain = C2spChain(sequence=1, previous_event_id=c2sp_event_id(genesis),
                      previous_state_hash=state_hash(stream.state))
    prepared = prepare_event(_rotation_event(keys), LR, chain)
    prepared.envelope["new_ek_thumb"] = prepared.envelope["prev_ek_thumb"][::-1]
    prepared = replace(prepared, signed_bytes=canonical_bytes(
        {k: v for k, v in prepared.envelope.items() if k != "sigs"}
    ))
    with pytest.raises(C2spTlogParseError, match="new_ek_thumb"):
        sign_prepared_event(prepared, C2spSignerRole.NEW_ENTITY, _provider(keys.e2))


def _malformed_issuance(entity: _Signer, operational: _Signer) -> bytes:
    """An ISSUANCE authenticated by both keys whose payload fails parsing."""
    obj = json.loads(_Stream().issuance(entity, operational))
    obj.pop("sigs")
    obj["gi"] = 7
    signed = canonical_bytes(obj)
    return canonical_bytes(dict(obj, sigs={
        "ae": {"kid": entity.kid, "sig": entity.sign(signed)},
        "op": {"kid": operational.kid, "sig": operational.sign(signed)},
    }))


def test_malformed_genesis_authenticated_by_the_root_key_is_fatal(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    malformed = _malformed_issuance(keys.e1, keys.o1)
    for record in (keys.e1, keys.e2):
        with pytest.raises(C2spTlogVerificationError) as exc:
            _verify([malformed, *stream.entries], record.jwk)
        assert exc.value.category == C2spLifecycleErrorCategory.INVALID_EVIDENCE
        assert exc.value.failing_candidate_index == 0
    # The same malformed genesis under an unrelated key stays noise.
    spam = _malformed_issuance(keys.attacker, _key("attacker-op"))
    assert _types(_verify([spam, *stream.entries], keys.e2.jwk)) == [
        "ISSUANCE", "ENTITY_KEY_ROTATION",
    ]


def test_fresh_genesis_by_an_intermediate_key_after_chained_rotations(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    stream.entity_rotation(keys.e3)
    stream.terminal("REVOCATION")
    fresh = _Stream()
    fresh.ts = stream.ts
    entries = [*stream.entries, fresh.issuance(keys.e2, keys.o1)]
    with pytest.raises(C2spTlogVerificationError, match="does not match record ek"):
        _verify(entries, keys.e2.jwk)


# ---------------------------------------------------------------------------
# Regression: streams without ENTITY_KEY_ROTATION behave as before
# ---------------------------------------------------------------------------


def test_streams_without_entity_rotation_keep_pinned_behaviour(keys):
    real = _Stream()
    spam = _spam_issuance(real, keys)
    real.issuance(keys.e1, keys.o1)
    real.key_rotation(keys.o2)
    real.terminal("REVOCATION")
    selected = _verify([spam, *real.entries], keys.e1.jwk)
    assert [item.index for item in selected] == [1, 2, 3]
    assert all(item.post_keys[0].thumbprint() == keys.e1.jwk.thumbprint() for item in selected)
    # A mismatched trusted key selects nothing, with the historical errors.
    with pytest.raises(C2spTlogVerificationError, match="lifecycle contains no ISSUANCE event"):
        _verify(real.entries, keys.e2.jwk)
    with pytest.raises(C2spTlogVerificationError,
                       match="ISSUANCE entity key does not match trusted entity key"):
        verify_lifecycle(selected, StreamVerifierOptions(
            signer_key=keys.e2.jwk, checkpoint_integration_time_ms=4_000_000_000_000,
        ))
    # Unanchored low-level selection is unchanged: the first genesis wins.
    unanchored = _verify([spam, *real.entries], None)
    assert [item.index for item in unanchored] == [0]


def test_domain_log_tracks_the_current_entity_key(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    events = [parse_c2sp_event_entry(entry) for entry in stream.entries]
    end = max(event.timestamp for event in events)
    snapshot = DomainLog(DOMAIN, events).snapshot_at(end)
    assert snapshot.entity_key.thumbprint() == keys.e2.jwk.thumbprint()
    assert snapshot.historical_state == "ACTIVE"
    before = DomainLog(DOMAIN, events).snapshot_at(events[0].timestamp)
    assert before.entity_key.thumbprint() == keys.e1.jwk.thumbprint()
    broken = replace(events[1], previous_entity_thumbprint=keys.e3.jwk.thumbprint())
    with pytest.raises(LifecycleVerificationError, match="does not continue"):
        DomainLog(DOMAIN, [events[0], broken]).snapshot_at(end)
    to_operational = replace(events[1], new_entity_public_key=keys.o1.jwk,
                             new_entity_thumbprint=keys.o1.jwk.thumbprint())
    with pytest.raises(LifecycleVerificationError, match="new key binding is invalid"):
        DomainLog(DOMAIN, [events[0], to_operational]).snapshot_at(end)


# ---------------------------------------------------------------------------
# Writers: prepared events and the manager signing facade
# ---------------------------------------------------------------------------


class _Provider(RealKeyProvider):
    def sign_key(self, kid: str, payload: bytes) -> bytes:
        return self._keys[kid][0].sign(payload)


def _provider(signer: _Signer) -> RealKeyProvider:
    return _Provider(signer.kid, {signer.kid: (signer.private, signer.jwk)})


def test_prepared_rotation_collects_previous_then_new_entity_signatures(keys):
    stream = _Stream()
    genesis = stream.issuance(keys.e1, keys.o1)
    chain = C2spChain(sequence=1, previous_event_id=c2sp_event_id(genesis),
                      previous_state_hash=state_hash(stream.state))
    event = _rotation_event(keys, timestamp=datetime.datetime.fromtimestamp(
        stream.ts + 1, datetime.UTC))
    prepared = prepare_event(event, LR, chain)
    assert prepared.required_signatures == [
        C2spSignerRole.PREVIOUS_ENTITY, C2spSignerRole.NEW_ENTITY,
    ]
    trusted = C2spVerificationContext(entity_key=keys.e1.jwk, fqdn=DOMAIN)
    with pytest.raises(C2spTlogVerificationError, match="trusted current entity key"):
        sign_prepared_event(prepared, C2spSignerRole.PREVIOUS_ENTITY, _provider(keys.e1),
                            C2spVerificationContext(fqdn=DOMAIN))
    with pytest.raises(C2spTlogVerificationError, match="expected fqdn"):
        sign_prepared_event(prepared, C2spSignerRole.PREVIOUS_ENTITY, _provider(keys.e1),
                            C2spVerificationContext(entity_key=keys.e1.jwk))
    with pytest.raises(C2spTlogVerificationError, match="prev_ek_thumb"):
        sign_prepared_event(prepared, C2spSignerRole.PREVIOUS_ENTITY, _provider(keys.e2),
                            C2spVerificationContext(entity_key=keys.e2.jwk, fqdn=DOMAIN))
    with pytest.raises(C2spTlogVerificationError, match="does not match"):
        sign_prepared_event(prepared, C2spSignerRole.NEW_ENTITY, _provider(_impostor("entity-2")))
    signed = sign_prepared_event(prepared, C2spSignerRole.PREVIOUS_ENTITY,
                                 _provider(keys.e1), trusted)
    assert signed.missing_signatures() == [C2spSignerRole.NEW_ENTITY]
    # Existing signatures are re-verified, so prev_ae needs the trusted key.
    with pytest.raises(C2spTlogVerificationError, match="trusted current entity key"):
        sign_prepared_event(signed, C2spSignerRole.NEW_ENTITY, _provider(keys.e2))
    signed = sign_prepared_event(signed, C2spSignerRole.NEW_ENTITY, _provider(keys.e2), trusted)
    assert signed.missing_signatures() == []
    data = entry_bytes(signed, trusted)
    selected = _verify([genesis, data], keys.e2.jwk)
    assert _types(selected) == ["ISSUANCE", "ENTITY_KEY_ROTATION"]
    with pytest.raises(C2spTlogParseError, match="missing sigs.prev_ae"):
        entry_bytes(sign_prepared_event(prepared, C2spSignerRole.NEW_ENTITY, _provider(keys.e2)))


def test_prepared_rotation_requires_chain_metadata(keys):
    with pytest.raises(C2spTlogParseError, match="chain metadata"):
        prepare_event(_rotation_event(keys), LR)


class _Binding:
    def canonical(self, event: Any) -> bytes:
        return b"canonical-" + str(event.event_type).encode()


def test_manager_signing_facade_signs_both_entity_roles(keys):
    provider = _Provider(keys.e1.kid, {
        keys.e1.kid: (keys.e1.private, keys.e1.jwk),
        keys.e2.kid: (keys.e2.private, keys.e2.jwk),
    })
    event = _rotation_event(keys)
    sign_event_with_provider(event, LogSignerRole.PREVIOUS_ENTITY, provider, _Binding())
    sign_event_with_provider(event, LogSignerRole.NEW_ENTITY, provider, _Binding())
    payload = b"canonical-ENTITY_KEY_ROTATION"
    from dnsid._utils import b64url_decode

    assert event.signing_kid == keys.e1.kid
    assert keys.e1.jwk.verify(payload, b64url_decode(event.sig))
    assert keys.e2.jwk.verify(payload, b64url_decode(event.new_entity_proof))
    with pytest.raises(ArgumentError, match="ENTITY_KEY_ROTATION"):
        sign_event_with_provider(KeyRotationEvent(), LogSignerRole.NEW_ENTITY, provider,
                                 _Binding())
    with pytest.raises(ArgumentError, match="previous_entity_kid"):
        sign_event_with_provider(EntityKeyRotationEvent(), LogSignerRole.PREVIOUS_ENTITY,
                                 provider, _Binding())


# ---------------------------------------------------------------------------
# Reader: bilateral binding, migration and stream bundles
# ---------------------------------------------------------------------------


def _subtree_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return node_hash(_subtree_root(leaves[:split]), _subtree_root(leaves[split:]))


def _audit_path(leaves: list[bytes], index: int) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return _audit_path(leaves[:split], index) + [_subtree_root(leaves[split:])]
    return _audit_path(leaves[split:], index - split) + [_subtree_root(leaves[:split])]


def _bundle(lr: str, entries: list[bytes], checkpoint: bytes, policy: bytes,
            private: ed25519.Ed25519PrivateKey, key: Any) -> bytes:
    leaves = [leaf_hash(entry) for entry in entries]
    final = parse_c2sp_event_entry(entries[-1])
    value: dict[str, Any] = {
        "v": 1,
        "type": "dnsid-c2sp-stream-bundle",
        "fqdn": DOMAIN,
        "lr": lr,
        "checkpoint": b64url_encode(checkpoint),
        "policy_hash": b64url_encode(hashlib.sha256(policy).digest()),
        "complete_through_size": len(entries),
        "completeness_mode": "trusted-index",
        "events": [
            {"index": index, "entry": b64url_encode(entry),
             "proof": b64url_encode(b"".join(_audit_path(leaves, index)))}
            for index, entry in enumerate(entries)
        ],
        "state": {
            "event_count": len(entries),
            "last_event_type": str(final.event_type),
            "logged_state": "ACTIVE",
        },
        "expires": int(NOW.timestamp()) + 30,
    }
    value["sig"] = {
        "alg": "EdDSA",
        "kid": f"{key.name}+{key.key_id.hex()}",
        "value": b64url_encode(private.sign(canonical_bytes(value))),
    }
    return canonical_bytes(value)


def _registry(logs: dict[str, list[bytes]], *, bundles: bool):
    witness = ed25519.Ed25519PrivateKey.generate()
    resources: dict[str, bytes] = {}
    policy_lines: list[str] = []
    checkpoints: dict[str, bytes] = {}
    for lr, entries in logs.items():
        reference = parse_c2sp_tlog_lr(lr)
        log_private = ed25519.Ed25519PrivateKey.generate()
        policy_lines.append("log " + _verifier_key(reference.origin, b"\x01", log_private))
        checkpoints[lr] = _checkpoint(reference.origin, entries, log_private, witness)
        resources[f"{reference.log_prefix}/checkpoint"] = checkpoints[lr]
        resources[f"{reference.log_prefix}/tile/entries/000.p/{len(entries)}"] = (
            encode_entry_bundle(entries)
        )
    policy_lines += [
        "witness migration-witness " + _verifier_key("migration-witness", b"\x04", witness),
        "quorum migration-witness",
    ]
    policy = ("\n".join(policy_lines) + "\n").encode()
    bundle_private = ed25519.Ed25519PrivateKey.generate()
    bundle_key = _bundle_key(bundle_private)
    if bundles:
        for lr, entries in logs.items():
            reference = parse_c2sp_tlog_lr(lr)
            resources[f"{reference.log_prefix}/streams/{DOMAIN}?format=bundle"] = _bundle(
                lr, entries, checkpoints[lr], policy, bundle_private, bundle_key,
            )
    options = C2spTlogVerificationOptions(
        policy_document=policy,
        resource_fetcher=_Fetcher(resources),
        checkpoint_freshness_ms=60_000,
        bundle_verifier_keys=[bundle_key] if bundles else None,
        max_bundle_lifetime_ms=60_000 if bundles else None,
        require_stream_bundle=bundles,
    )
    return create_c2sp_tlog_verification_registry(options)


def _lr(name: str) -> str:
    return f"c2sp-tlog:testnet:https://{name}.example#{name}"


def _record() -> SimpleNamespace:
    return SimpleNamespace(identity_fqdn=DOMAIN, gi="example")


@pytest.mark.parametrize("bundles", [False, True])
def test_reader_binding_requires_the_current_entity_key(keys, bundles):
    lr = _lr("rotated")
    stream = _Stream(lr)
    stream.issuance(keys.e1, keys.o1)
    stream.entity_rotation(keys.e2)
    stream.key_rotation(keys.o2)
    registry = _registry({lr: stream.entries}, bundles=bundles)
    reader = registry.new_reader(lr)
    binding = reader.verify_bilateral_binding(_record(), keys.e2.jwk, keys.o2.jwk)
    assert binding.initial_entity_thumbprint == keys.e1.jwk.thumbprint()
    assert binding.current_entity_thumbprint == keys.e2.jwk.thumbprint()
    assert binding.initial_operational_thumbprint == keys.o1.jwk.thumbprint()
    reader.verify_operational_continuity(
        DOMAIN, binding.initial_operational_thumbprint, keys.o2.jwk.thumbprint()
    )
    stale = _registry({lr: stream.entries}, bundles=bundles).new_reader(lr)
    with pytest.raises(VerificationError, match="current entity key does not match record ek"):
        stale.verify_bilateral_binding(_record(), keys.e1.jwk, keys.o2.jwk)


def test_reader_binding_without_rotation_reports_both_thumbprints(keys):
    lr = _lr("plain")
    stream = _Stream(lr)
    stream.issuance(keys.e1, keys.o1)
    reader = _registry({lr: stream.entries}, bundles=False).new_reader(lr)
    binding = reader.verify_bilateral_binding(_record(), keys.e1.jwk, keys.o1.jwk)
    assert binding.initial_entity_thumbprint == keys.e1.jwk.thumbprint()
    assert binding.current_entity_thumbprint == keys.e1.jwk.thumbprint()


def _migration(stream: _Stream, previous: str, previous_entries: list[bytes],
               signer: _Signer, entity: _Signer, operational: _Signer) -> bytes:
    stream.ts = json.loads(previous_entries[-1])["ts"]
    obj = stream._payload("MIGRATION", dict(
        prev_lr=previous, new_lr=stream.base["lr"],
        prev_ref=f"{previous}@{len(previous_entries) - 1}",
    ))
    data = stream._emit(obj, {"ae": signer}, True, stream._active(entity, operational))
    stream.entity, stream.operational = entity, operational
    return data


@pytest.mark.parametrize("bundles", [False, True])
def test_migration_imports_the_end_of_history_entity_key(keys, bundles):
    first, second = _lr("first"), _lr("second")
    prior = _Stream(first)
    prior.issuance(keys.e1, keys.o1)
    prior.entity_rotation(keys.e2)
    destination = _Stream(second)
    _migration(destination, first, prior.entries, keys.e2, keys.e2, keys.o1)
    registry = _registry({first: prior.entries, second: destination.entries}, bundles=bundles)
    reader = registry.new_reader(second)
    binding = reader.verify_bilateral_binding(_record(), keys.e2.jwk, keys.o1.jwk)
    assert binding.current_entity_thumbprint == keys.e2.jwk.thumbprint()
    assert [str(e.event_type) for e in reader.rebuild_history(DOMAIN)] == [
        "ISSUANCE", "ENTITY_KEY_ROTATION", "MIGRATION",
    ]


@pytest.mark.parametrize("bundles", [False, True])
def test_migration_signed_by_a_superseded_entity_key_is_rejected(keys, bundles):
    first, second = _lr("first"), _lr("second")
    prior = _Stream(first)
    prior.issuance(keys.e1, keys.o1)
    prior.entity_rotation(keys.e2)
    destination = _Stream(second)
    _migration(destination, first, prior.entries, keys.e1, keys.e1, keys.o1)
    registry = _registry({first: prior.entries, second: destination.entries}, bundles=bundles)
    for record in (keys.e1, keys.e2):
        with pytest.raises(VerificationError):
            registry.new_reader(second).verify_bilateral_binding(
                _record(), record.jwk, keys.o1.jwk
            )


@pytest.mark.parametrize("bundles", [False, True])
def test_rotation_after_migration_anchors_the_prior_log_on_the_migration_signer(
    keys, bundles,
):
    first, second = _lr("first"), _lr("second")
    prior = _Stream(first)
    prior.issuance(keys.e1, keys.o1)
    destination = _Stream(second)
    _migration(destination, first, prior.entries, keys.e1, keys.e1, keys.o1)
    destination.entity_rotation(keys.e2)
    registry = _registry({first: prior.entries, second: destination.entries}, bundles=bundles)
    reader = registry.new_reader(second)
    binding = reader.verify_bilateral_binding(_record(), keys.e2.jwk, keys.o1.jwk)
    assert binding.initial_entity_thumbprint == keys.e1.jwk.thumbprint()
    assert binding.current_entity_thumbprint == keys.e2.jwk.thumbprint()
    history = reader.rebuild_history(DOMAIN)
    assert [str(e.event_type) for e in history] == [
        "ISSUANCE", "MIGRATION", "ENTITY_KEY_ROTATION",
    ]
    assert isinstance(history[0], IssuanceEvent) and isinstance(history[1], MigrationEvent)
    with pytest.raises(VerificationError, match="does not match record ek"):
        _registry({first: prior.entries, second: destination.entries},
                  bundles=bundles).new_reader(second).verify_bilateral_binding(
            _record(), keys.e1.jwk, keys.o1.jwk,
        )


def test_root_eligible_merkle_helpers_match_the_library(keys):
    stream = _Stream()
    stream.issuance(keys.e1, keys.o1)
    for signer in (keys.e2, keys.e3):
        stream.entity_rotation(signer)
    leaves = [leaf_hash(entry) for entry in stream.entries]
    assert _subtree_root(leaves) == merkle_root_from_entries(stream.entries)


@pytest.mark.asyncio
@pytest.mark.parametrize("bundles", [False, True])
async def test_async_reader_matches_sync_for_rotation_around_migration(keys, bundles):
    first, second = _lr("first"), _lr("second")
    prior = _Stream(first)
    prior.issuance(keys.e1, keys.o1)
    prior.entity_rotation(keys.e2)
    destination = _Stream(second)
    _migration(destination, first, prior.entries, keys.e2, keys.e2, keys.o1)
    destination.entity_rotation(keys.e3)
    logs = {first: prior.entries, second: destination.entries}
    reader = _registry(logs, bundles=bundles).new_reader(second)
    binding = await reader.async_verify_bilateral_binding(_record(), keys.e3.jwk, keys.o1.jwk)
    assert binding.initial_entity_thumbprint == keys.e1.jwk.thumbprint()
    assert binding.current_entity_thumbprint == keys.e3.jwk.thumbprint()
    history = await reader.async_rebuild_history(DOMAIN)
    assert [str(e.event_type) for e in history] == [
        "ISSUANCE", "ENTITY_KEY_ROTATION", "MIGRATION", "ENTITY_KEY_ROTATION",
    ]
    sync_reader = _registry(logs, bundles=bundles).new_reader(second)
    sync_binding = sync_reader.verify_bilateral_binding(_record(), keys.e3.jwk, keys.o1.jwk)
    assert sync_binding == binding
    for stale in (keys.e1, keys.e2):
        with pytest.raises(VerificationError):
            await _registry(logs, bundles=bundles).new_reader(second).async_verify_bilateral_binding(
                _record(), stale.jwk, keys.o1.jwk,
            )
