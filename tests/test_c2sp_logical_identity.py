"""Corrected logical selection with real randomized ECDSA signatures."""

import datetime
import json
from dataclasses import replace
from pathlib import Path

import pytest

from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog import (
    C2spEventContext,
    C2spTlogVerificationError,
    IndexedEntry,
    StreamVerifierOptions,
    canonical_bytes,
    verify_stream_lifecycle,
)
from dnsid.c2sp_tlog.event_codec import c2sp_event_id
from dnsid.c2sp_tlog.stream_verifier import state_hash, verify_occurrence
from tests.conftest import RealKeyProvider, make_ec_p256_pair

LR = "c2sp-tlog:testnet:https://log.example#identity-instance"


def test_real_signatures_deduplicate_and_authenticate_historical_forks(monkeypatch):
    providers = [
        RealKeyProvider(kid, {kid: make_ec_p256_pair(kid)}) for kid in ("ae", "old", "new", "fork")
    ]
    ae, old, new, fork = providers
    keys = [p.signing_key() for p in providers]
    base = dict(
        v=1,
        kind="dnsid.lifecycle",
        fqdn="agent.example",
        ts=100,
        method="c2sp-tlog",
        log_origin="log.example",
        stream_id="identity-instance",
        lr=LR,
    )
    genesis = dict(base, type="ISSUANCE", gi="example", ek=keys[0]._raw, ku=keys[1]._raw, seq=0)

    def sign(obj, roles):
        signed = canonical_bytes(obj)
        return canonical_bytes(
            dict(
                obj,
                sigs={
                    role: {"kid": p.signing_key().kid, "sig": b64url_encode(p.sign(signed))}
                    for role, p in roles.items()
                },
            )
        )

    first = sign(genesis, {"ae": ae, "op": old})
    first_copy = sign(genesis, {"ae": ae, "op": old})
    assert first != first_copy and c2sp_event_id(first) == c2sp_event_id(first_copy)
    state = {
        "fqdn": "agent.example",
        "status": "ACTIVE",
        "entity_thumb": keys[0].thumbprint(),
        "operational_thumb": keys[1].thumbprint(),
    }
    rotation = dict(
        base,
        type="KEY_ROTATION",
        seq=1,
        ts=101,
        prev_event_id=c2sp_event_id(first),
        prev_state_hash=state_hash(state),
        prev_thumb=keys[1].thumbprint(),
        new_ku=keys[2]._raw,
        new_thumb=keys[2].thumbprint(),
    )
    rotated = sign(rotation, {"prev_op": old, "new_op": new})
    state["operational_thumb"] = keys[2].thumbprint()
    retired_payload = dict(
        base,
        type="RETIREMENT",
        seq=2,
        ts=102,
        prev_event_id=c2sp_event_id(rotated),
        prev_state_hash=state_hash(state),
    )
    retired = sign(retired_payload, {"ae": ae})
    opts = StreamVerifierOptions(
        context=C2spEventContext(
            scope="testnet", log_origin="log.example", stream_id="identity-instance", lr=LR
        ),
        signer_key=keys[0],
        checkpoint_integration_time_ms=200000,
    )

    def verify(raw, options=opts):
        return verify_stream_lifecycle(
            [IndexedEntry(i, e) for i, e in enumerate(raw)], "agent.example", options
        )

    invalid_first_obj = json.loads(sign(genesis, {"ae": ae, "op": new}))
    invalid_first_obj["sigs"]["op"]["kid"] = old.signing_key().kid
    invalid_first = canonical_bytes(invalid_first_obj)
    selected = verify(
        [
            invalid_first,
            first,
            first_copy,
            rotated,
            retired,
            sign(rotation, {"prev_op": old, "new_op": new}),
            invalid_first,
        ]
    )
    assert [i.index for i in selected] == [1, 3, 4]
    assert selected[0].event.timestamp == datetime.datetime.fromtimestamp(100, datetime.UTC)
    assert verify_occurrence(IndexedEntry(2, first_copy), selected, opts).index == 2
    with pytest.raises(C2spTlogVerificationError, match="invalid signed occurrence"):
        verify_occurrence(IndexedEntry(6, invalid_first), selected, opts)
    # Missing or invalid second role cannot reserve an ID or invalidate ACTIVE state.
    assert len(verify([first, sign(rotation, {"prev_op": old}), rotated])) == 2
    assert len(verify([first, sign(rotation, {"prev_op": old, "new_op": old})])) == 1
    # Both valid roles under the now-superseded predecessor make this a fatal fork.
    fork_payload = dict(rotation, new_ku=keys[3]._raw, new_thumb=keys[3].thumbprint())
    with pytest.raises(C2spTlogVerificationError) as exc:
        verify([first, rotated, sign(fork_payload, {"prev_op": old, "new_op": fork})])
    assert exc.value.failing_candidate_index == 2
    for bad in (
        dict(rotation, seq=9),
        dict(rotation, prev_index=0),
        dict(rotation, event_id=c2sp_event_id(rotated)),
        dict(rotation, prev_state_hash="AA"),
    ):
        with pytest.raises(C2spTlogVerificationError):
            verify([first, sign(bad, {"prev_op": old, "new_op": new})])
    with pytest.raises(C2spTlogVerificationError):
        verify([first, sign(dict(genesis, extension="different"), {"ae": ae, "op": old})])
    with pytest.raises(C2spTlogVerificationError):
        verify([first, rotated, retired, sign(dict(retired_payload, extension=1), {"ae": ae})])
    # A signed cutoff may name a valid physical copy, never an invalid copy.
    result = verify([first, first_copy], replace(opts, cutoff_index=1))
    assert result[-1].index == 1
    with pytest.raises(C2spTlogVerificationError):
        verify([first, invalid_first], replace(opts, cutoff_index=1))
    with pytest.raises(C2spTlogVerificationError, match="limit"):
        verify([first, first_copy], replace(opts, max_entries=1))
    with pytest.raises(C2spTlogVerificationError):
        verify([first], replace(opts, unchained=True))
    # Even a malformed-signature payload cannot conceal an ID integrity collision.
    monkeypatch.setattr("dnsid.c2sp_tlog.stream_verifier.c2sp_event_id", lambda _: "collision")
    with pytest.raises(C2spTlogVerificationError, match="ID collision"):
        verify([first, sign(dict(genesis, extension="different"), {"ae": ae})])


def test_committed_event_identity_vectors():
    vector = json.loads((Path(__file__).parent / "vectors/c2sp-event-identity.json").read_text())
    # Inspect the fixture's fixed expected digest, rather than re-deriving an expectation.
    for case in vector["vectors"]:
        data = canonical_bytes(case["value"])
        assert data.decode() == case["canonical"]
        digest = c2sp_event_id(data) if case["domain"] == "event" else state_hash(case["value"])
        assert digest == case["hash"]
