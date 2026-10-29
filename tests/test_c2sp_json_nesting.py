"""JSON resource limits must not hide an included, signed revocation (DEV-035)."""

import base64
import datetime
import json

import pytest

from dnsid._utils import b64url_decode_strict, b64url_encode
from dnsid.c2sp_tlog import (
    C2spResourceFetchGuarantees,
    C2spTlogReader,
    C2spTlogReaderOptions,
    C2spTlogResourceLimitError,
    TlogProofV1,
    canonical_bytes,
    canonical_json,
    encode_entry_bundle,
    leaf_hash,
    merkle_root_from_entries,
    parse_c2sp_policy_file,
    parse_checkpoint,
    parse_json_no_duplicate_members,
    verify_c2sp_stream_bundle,
)
from dnsid.exceptions import VerificationError
from dnsid.models import RevocationEvent
from tests.test_c2sp_stream_bundle import _options, _vector
from tests.vectors.generate_c2sp_stream_bundle import (
    _cosignature,
    _note_signature,
    _private,
    _verifier,
)

DEPTHS = (0, 63, 64, 65, 500, 2000, 20000)


@pytest.fixture(params=DEPTHS, ids=lambda depth: f"depth-{depth}")
def nested_revocation(request):
    depth = request.param
    vector = _vector()
    bundle = json.loads(vector["bundle"])
    issuance = b64url_decode_strict(bundle["events"][0]["entry"])
    body = json.loads(b64url_decode_strict(bundle["events"][1]["entry"]))
    for field in ("sigs", "new_ku", "new_thumb", "prev_thumb"):
        body.pop(field)
    body.update(type="REVOCATION", reason="keyCompromise", x="NESTED")
    nested = b"[" * depth + b"0" + b"]" * depth
    # Sign exact bytes without asking a recursive encoder to construct the probe.
    signed = canonical_bytes(body).replace(b'"NESTED"', nested)
    signature = _private(1).sign(signed)
    _private(1).public_key().verify(signature, signed)
    body["sigs"] = {"ae": {"kid": "entity-1", "sig": b64url_encode(signature)}}
    revocation = canonical_bytes(body).replace(b'"NESTED"', nested)
    assert len(revocation) <= 65535
    entries = [issuance, revocation]

    root = merkle_root_from_entries(entries)
    text = f"log.example\n2\n{base64.b64encode(root).decode()}\n"
    log_hash = _verifier("log.example", _private(4), 1)[1]
    witness_hash = _verifier("witness.example", _private(5), 4)[1]
    checkpoint = (
        text + "\n" + _note_signature("log.example", log_hash, _private(4), text)
        + "\n" + _cosignature("witness.example", witness_hash, _private(5), text) + "\n"
    ).encode()
    bundle["checkpoint"] = b64url_encode(checkpoint)
    for index, entry in enumerate(entries):
        bundle["events"][index].update(
            entry=b64url_encode(entry), proof=b64url_encode(leaf_hash(entries[1 - index]))
        )
    bundle["state"] = {
        "event_count": 2, "last_event_type": "REVOCATION", "logged_state": "REVOKED"
    }
    unsigned = {k: v for k, v in bundle.items() if k != "sig"}
    bundle["sig"]["value"] = b64url_encode(_private(6).sign(canonical_bytes(unsigned)))

    resources = {
        "https://log.example/checkpoint": checkpoint,
        "https://log.example/tile/entries/000.p/2": encode_entry_bundle(entries),
    }

    class Transport:
        def security_guarantees(self):
            return C2spResourceFetchGuarantees(True, True, True, True, True)

        def fetch_bounded(self, url, maximum):
            data = resources[url]
            assert len(data) <= maximum
            return data

    options = _options(vector)
    options.max_bundle_bytes = 128 * 1024
    reader = C2spTlogReader(
        bundle["lr"],
        C2spTlogReaderOptions(
            policy=parse_c2sp_policy_file(vector["policy"]),
            transport=Transport(),
            entity_key=options.entity_key,
            checkpoint_freshness_ms=10**15,
            proofs={
                "1": TlogProofV1(
                    index=1, hashes=[leaf_hash(issuance)],
                    checkpoint=parse_checkpoint(checkpoint.decode()),
                )
            },
        ),
    )
    return depth, reader, canonical_bytes(bundle), options, bundle["fqdn"]


@pytest.mark.parametrize("operation", ["verify_non_revocation", "rebuild_history", "read_event",
                                       "rebuild_history_through", "stream_bundle"])
def test_signed_nested_revocation_never_disappears(nested_revocation, operation):
    depth, reader, bundle, options, domain = nested_revocation
    at = datetime.datetime.fromtimestamp(options.now(), tz=datetime.UTC)

    def verify():
        if operation == "stream_bundle":
            result = verify_c2sp_stream_bundle(bundle, options)
            assert result.logged_state == "REVOKED"
            return [item.event for item in result.events]
        if operation == "verify_non_revocation":
            reader.verify_non_revocation(domain, at)
            pytest.fail("a signed revocation must never leave an ACTIVE identity")
        if operation == "read_event":
            return [reader.read_event(f"{reader.lr}@1")]
        if operation == "rebuild_history_through":
            return reader.rebuild_history_through(
                domain, f"{reader.lr}@1", options.entity_key,
                max_depth=8, max_events=10, max_response_bytes=1024 * 1024,
                seen_log_references=frozenset(),
            ).events
        return reader.rebuild_history(domain)

    if depth >= 64:
        error = C2spTlogResourceLimitError if operation == "stream_bundle" else VerificationError
        with pytest.raises(error, match="JSON nesting limit exceeded") as caught:
            verify()
        assert caught.value.category == "INVALID_EVIDENCE"
        if operation != "stream_bundle":
            assert isinstance(caught.value.__cause__, C2spTlogResourceLimitError)
            assert not caught.value.transient
    elif operation == "verify_non_revocation":
        with pytest.raises(VerificationError, match="revoked"):
            verify()
    else:
        assert isinstance(verify()[-1], RevocationEvent)


@pytest.mark.parametrize("depth", [63, 64, 65, 500, 2000, 20000])
@pytest.mark.parametrize("leaf", [0, [], {}])
def test_json_depth_matches_go_value_depth(depth, leaf):
    value = leaf
    for _ in range(depth):
        value = [value]
    raw = b"[" * depth + canonical_bytes(leaf) + b"]" * depth
    if depth <= 64:
        assert canonical_bytes(value) == raw
        assert canonical_bytes(parse_json_no_duplicate_members(raw)) == raw
    else:
        for operation in (lambda: canonical_json(value),
                          lambda: parse_json_no_duplicate_members(raw)):
            with pytest.raises(C2spTlogResourceLimitError, match="JSON nesting limit exceeded"):
                operation()


def test_json_depth_scan_skips_escaped_strings():
    value = {"[" * 20000: ['[{}] \\"' * 20000, "\\", '"', "ok"]}
    raw = canonical_bytes(value)
    assert parse_json_no_duplicate_members(raw) == value
    assert canonical_bytes(parse_json_no_duplicate_members(raw)) == raw
