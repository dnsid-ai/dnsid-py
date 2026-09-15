"""Portable ``dnsid-c2sp-stream-bundle@v1`` conformance vector tests."""

from __future__ import annotations

import datetime
import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_decode_strict, b64url_encode
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError,
    C2spStreamBundleVerifierOptions,
    C2spTlogError,
    C2spTlogTransportError,
    Checkpoint,
    IndexedEntry,
    SQLiteCheckpointStore,
    StreamEvidence,
    TrustedCheckpoint,
    VerifiedC2spStreamBundle,
    canonical_bytes,
    leaf_hash,
    merkle_root_from_entries,
    parse_c2sp_tlog_lr,
    parse_checkpoint,
    parse_signed_note_verifier_key,
    verify_c2sp_stream_bundle,
)
from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource

VECTOR_PATH = Path(__file__).parent / "vectors" / "c2sp-stream-bundle-v1.json"


def _vector() -> dict:
    return json.loads(VECTOR_PATH.read_text())


def _options(vector: dict) -> C2spStreamBundleVerifierOptions:
    trust = vector["trust"]
    return C2spStreamBundleVerifierOptions(
        policy_bytes=vector["policy"].encode(),
        bundle_keys=[parse_signed_note_verifier_key(trust["bundle_verifier_key"])],
        entity_key=jwk_from_dict(trust["entity_jwk"]),
        checkpoint_freshness_ms=trust["checkpoint_freshness_ms"],
        max_bundle_lifetime_ms=trust["max_bundle_lifetime_ms"],
        max_bundle_bytes=32 * 1024,
        max_events=16,
        now=lambda: trust["now"],
    )


def _mutated_bundle(vector: dict, mutation: dict) -> bytes:
    value = json.loads(vector["bundle"])
    target = value
    parts = mutation["path"].strip("/").split("/")
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    last = parts[-1]
    if "append" in mutation:
        target[last] += mutation["append"]
    elif isinstance(target, list):
        target[int(last)] = mutation["value"]
    else:
        target[last] = mutation["value"]
    if mutation.get("resign"):
        unsigned = dict(value)
        unsigned.pop("sig")
        private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([6]) * 32)
        value["sig"]["value"] = b64url_encode(private.sign(canonical_bytes(unsigned)))
    return canonical_bytes(value)


def test_portable_stream_bundle_vector_verifies_exact_bytes_and_replayed_key():
    vector = _vector()
    result = verify_c2sp_stream_bundle(vector["bundle"].encode(), _options(vector))
    assert canonical_bytes(json.loads(vector["unsigned_bundle"])) == vector[
        "unsigned_bundle"
    ].encode()
    assert result.logged_state == vector["expected"]["status"]
    assert len(result.events) == vector["expected"]["event_count"]
    assert (
        result.active_operational_thumbprint
        == vector["expected"]["active_operational_thumbprint"]
    )
    assert result.bundle_signer_kid == vector["expected"]["bundle_signer_kid"]


def test_ignored_signature_copy_still_requires_its_exact_inclusion_proof():
    import base64

    from tests.vectors.generate_c2sp_stream_bundle import (
        _cosignature,
        _note_signature,
        _private,
        _verifier,
    )

    vector = _vector()
    bundle = json.loads(vector["bundle"])
    first = b64url_decode_strict(bundle["events"][0]["entry"])
    copy = json.loads(first)
    copy["sigs"]["op"]["sig"] = "AA"
    second = canonical_bytes(copy)
    root = merkle_root_from_entries([first, second])
    text = f"log.example\n2\n{base64.b64encode(root).decode()}\n"
    log_hash = _verifier("log.example", _private(4), 1)[1]
    witness_hash = _verifier("witness.example", _private(5), 4)[1]
    checkpoint = (text + "\n" + _note_signature("log.example", log_hash, _private(4), text)
                  + "\n" + _cosignature("witness.example", witness_hash, _private(5), text) + "\n")
    bundle["checkpoint"] = b64url_encode(checkpoint.encode())
    bundle["events"][0]["proof"] = b64url_encode(leaf_hash(second))
    bundle["events"][1]["entry"] = b64url_encode(second)
    bundle["events"][1]["proof"] = b64url_encode(leaf_hash(first))
    bundle["state"] = {"event_count": 1, "last_event_type": "ISSUANCE", "logged_state": "ACTIVE"}

    def signed():
        unsigned = {k: v for k, v in bundle.items() if k != "sig"}
        bundle["sig"]["value"] = b64url_encode(_private(6).sign(canonical_bytes(unsigned)))
        return canonical_bytes(bundle)

    assert len(verify_c2sp_stream_bundle(signed(), _options(vector)).events) == 1
    bundle["events"][1]["proof"] = b64url_encode(bytes(32))
    with pytest.raises(C2spTlogError, match="inclusion proof"):
        verify_c2sp_stream_bundle(signed(), _options(vector))


def test_verified_bundle_preserves_legacy_positional_constructor():
    vector = _vector()
    result = verify_c2sp_stream_bundle(vector["bundle"].encode(), _options(vector))

    legacy = VerifiedC2spStreamBundle(
        result.reference,
        result.checkpoint,
        result.events,
        result.logged_state,
        result.active_operational_thumbprint,
        result.expires,
        result.bundle_signer_kid,
    )

    assert legacy.events == result.events


def test_fetched_bundle_uses_authenticated_lr_endpoint_and_exact_bindings():
    vector = _vector()
    value = json.loads(vector["bundle"])
    reference = parse_c2sp_tlog_lr(value["lr"])
    requested = []

    class Fetcher:
        def fetch_bounded(self, url, max_bytes):
            requested.append((url, max_bytes))
            return vector["bundle"].encode()

    source = _FetchedStreamBundleSource(
        Fetcher(),
        object(),
        policy_bytes=vector["policy"].encode(),
        bundle_keys=_options(vector).bundle_keys,
        checkpoint_freshness_ms=vector["trust"]["checkpoint_freshness_ms"],
        max_bundle_lifetime_ms=vector["trust"]["max_bundle_lifetime_ms"],
        max_bundle_bytes=32 * 1024,
        max_events=16,
        now=lambda: vector["trust"]["now"],
    )
    result = source.load_verified_bundle(
        reference,
        value["fqdn"],
        jwk_from_dict(vector["trust"]["entity_jwk"]),
        None,
    )

    assert result is not None
    assert requested == [
        (f"{reference.log_prefix}/streams/{value['fqdn']}?format=bundle", 32 * 1024)
    ]
    with pytest.raises(C2spTlogError, match="fqdn does not match"):
        source.load_verified_bundle(
            reference,
            "other.example.com",
            jwk_from_dict(vector["trust"]["entity_jwk"]),
            None,
        )
    with pytest.raises(C2spTlogError, match="lr does not match"):
        source.load_verified_bundle(
            parse_c2sp_tlog_lr(value["lr"].replace("#ERER", "#OTHER")),
            value["fqdn"],
            jwk_from_dict(vector["trust"]["entity_jwk"]),
            None,
        )


def test_fetched_bundle_fallback_is_bounded_and_invalid_bundles_fail_closed():
    vector = _vector()
    value = json.loads(vector["bundle"])
    reference = parse_c2sp_tlog_lr(value["lr"])
    fallback_calls = []

    class Fallback:
        def load_stream(self, reference, fqdn):
            fallback_calls.append((reference, fqdn))
            return "raw evidence"

    class Fetcher:
        def __init__(self, response):
            self.response = response

        def fetch_bounded(self, url, max_bytes):
            if isinstance(self.response, Exception):
                raise self.response
            return self.response

    def source(response, checkpoint_store=None):
        return _FetchedStreamBundleSource(
            Fetcher(response),
            Fallback(),
            policy_bytes=vector["policy"].encode(),
            bundle_keys=_options(vector).bundle_keys,
            checkpoint_freshness_ms=vector["trust"]["checkpoint_freshness_ms"],
            max_bundle_lifetime_ms=vector["trust"]["max_bundle_lifetime_ms"],
            max_bundle_bytes=32 * 1024,
            max_events=16,
            checkpoint_store=checkpoint_store,
            now=lambda: vector["trust"]["now"],
        )

    unavailable = source(
        C2spTlogTransportError("unavailable", transient=True)
    )
    assert unavailable.load_verified_bundle(
        reference,
        value["fqdn"],
        jwk_from_dict(vector["trust"]["entity_jwk"]),
        None,
    ) is None
    assert unavailable.load_stream(reference, value["fqdn"]) == "raw evidence"

    bad_request = source(
        C2spTlogTransportError("bad request", transient=True, status_code=400)
    )
    with pytest.raises(C2spTlogTransportError):
        bad_request.load_verified_bundle(
            reference,
            value["fqdn"],
            jwk_from_dict(vector["trust"]["entity_jwk"]),
            None,
        )

    required = _FetchedStreamBundleSource(
        Fetcher(C2spTlogTransportError("unavailable", transient=True)),
        Fallback(),
        policy_bytes=vector["policy"].encode(),
        bundle_keys=_options(vector).bundle_keys,
        checkpoint_freshness_ms=vector["trust"]["checkpoint_freshness_ms"],
        max_bundle_lifetime_ms=vector["trust"]["max_bundle_lifetime_ms"],
        max_bundle_bytes=32 * 1024,
        max_events=16,
        require_bundle=True,
    )
    with pytest.raises(C2spTlogTransportError):
        required.load_verified_bundle(
            reference,
            value["fqdn"],
            jwk_from_dict(vector["trust"]["entity_jwk"]),
            None,
        )

    invalid = source(b"{}")
    with pytest.raises(C2spTlogError):
        invalid.load_verified_bundle(
            reference,
            value["fqdn"],
            jwk_from_dict(vector["trust"]["entity_jwk"]),
            None,
        )
    assert len(fallback_calls) == 1



@pytest.mark.parametrize("mutation", _vector()["negative_mutations"], ids=lambda item: item["name"])
def test_portable_stream_bundle_negative_mutations_fail_closed(mutation: dict):
    vector = _vector()
    expected = None if mutation["name"] == "proof-length" else mutation["error"]
    with pytest.raises(C2spTlogError, match=expected):
        verify_c2sp_stream_bundle(_mutated_bundle(vector, mutation), _options(vector))


def test_invalid_candidate_proof_fails_closed():
    vector = _vector()
    bundle = json.loads(vector["bundle"])
    bundle["events"][1]["proof"] = "AA"
    bundle["state"] = {
        "event_count": 1,
        "last_event_type": "ISSUANCE",
        "logged_state": "ACTIVE",
    }
    unsigned = dict(bundle)
    unsigned.pop("sig")
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([6]) * 32)
    bundle["sig"]["value"] = b64url_encode(private.sign(canonical_bytes(unsigned)))

    with pytest.raises(C2spTlogError, match="proof"):
        verify_c2sp_stream_bundle(canonical_bytes(bundle), _options(vector))


def test_portable_stream_bundle_resource_limits_apply_before_event_decode():
    vector = _vector()
    options = _options(vector)
    options.max_events = 1
    with pytest.raises(C2spTlogError, match="event maximum"):
        verify_c2sp_stream_bundle(vector["bundle"].encode(), options)

    options = _options(vector)
    options.max_tree_size = 1
    with pytest.raises(C2spTlogError, match="tree-size maximum"):
        verify_c2sp_stream_bundle(vector["bundle"].encode(), options)

    empty = json.loads(vector["bundle"])
    empty["events"] = []
    with pytest.raises(C2spTlogError, match="requires events"):
        verify_c2sp_stream_bundle(canonical_bytes(empty), _options(vector))


def test_portable_stream_bundle_rejects_untrusted_signer():
    vector = _vector()
    options = _options(vector)
    options.bundle_keys = []
    with pytest.raises(C2spTlogError, match="requires trusted keys"):
        verify_c2sp_stream_bundle(vector["bundle"].encode(), options)


def _seed_old_checkpoint(vector: dict, options: C2spStreamBundleVerifierOptions) -> bytes:
    bundle = json.loads(vector["bundle"])
    first_entry = b64url_decode_strict(bundle["events"][0]["entry"])
    old_root = leaf_hash(first_entry)
    options.checkpoint_store.put(
        TrustedCheckpoint(
            origin="log.example",
            tree_size=1,
            root_hash=old_root,
            witness_time=datetime.datetime.fromtimestamp(
                vector["trust"]["now"] - 120, tz=datetime.UTC
            ),
        )
    )
    return b64url_decode_strict(bundle["events"][0]["proof"])


def test_rejected_bundle_does_not_advance_checkpoint() -> None:
    vector = _vector()
    options = _options(vector)

    with pytest.raises(C2spTlogError, match="state does not match"):
        verify_c2sp_stream_bundle(
            _mutated_bundle(
                vector,
                {
                    "path": "/state/logged_state",
                    "value": "REVOKED",
                    "resign": True,
                },
            ),
            options,
        )

    assert options.checkpoint_store.get("log.example") is None


def test_fetched_bundle_uses_complete_scan_for_missing_consistency() -> None:
    vector = _vector()
    bundle = json.loads(vector["bundle"])
    reference = parse_c2sp_tlog_lr(bundle["lr"])
    entries = [b64url_decode_strict(item["entry"]) for item in bundle["events"]]
    bundle_checkpoint = parse_checkpoint(
        b64url_decode_strict(bundle["checkpoint"]).decode()
    )

    class Fetcher:
        def fetch_bounded(self, url, max_bytes):
            return vector["bundle"].encode()

    class Fallback:
        def __init__(self, raw_entries):
            self.raw_entries = raw_entries
            self.calls = 0

        def load_stream(self, reference, fqdn):
            self.calls += 1
            return StreamEvidence(
                checkpoint=Checkpoint(
                    origin=bundle_checkpoint.origin,
                    tree_size=len(self.raw_entries),
                    root_hash=merkle_root_from_entries(self.raw_entries),
                ),
                entries=[
                    IndexedEntry(index, entry)
                    for index, entry in enumerate(self.raw_entries)
                ],
                complete=True,
            )

    def verify(raw_entries, *, require_bundle=False, trusted_root=None):
        options = _options(vector)
        _seed_old_checkpoint(vector, options)
        if trusted_root is not None:
            stored = options.checkpoint_store.get(reference.origin)
            options.checkpoint_store.put(replace(stored, root_hash=trusted_root))
        fallback = Fallback(raw_entries)
        source = _FetchedStreamBundleSource(
            Fetcher(),
            fallback,
            policy_bytes=vector["policy"].encode(),
            bundle_keys=options.bundle_keys,
            checkpoint_freshness_ms=options.checkpoint_freshness_ms,
            max_bundle_lifetime_ms=options.max_bundle_lifetime_ms,
            max_bundle_bytes=options.max_bundle_bytes,
            max_events=options.max_events,
            checkpoint_store=options.checkpoint_store,
            require_bundle=require_bundle,
            now=options.now,
        )
        result = source.load_verified_bundle(
            reference,
            bundle["fqdn"],
            options.entity_key,
            None,
        )
        return result, fallback, options.checkpoint_store

    result, fallback, store = verify(entries)
    assert result is not None
    assert fallback.calls == 1
    assert store.get(reference.origin).tree_size == bundle_checkpoint.tree_size

    result, _, store = verify([*entries, b"newer unrelated entry"])
    assert result is not None
    assert store.get(reference.origin).tree_size == bundle_checkpoint.tree_size

    with pytest.raises(C2spTlogError, match="candidate checkpoint"):
        verify([entries[0], b"conflict"])
    with pytest.raises(C2spTlogError, match="candidate checkpoint prefix"):
        verify(entries[:1])
    with pytest.raises(C2spTlogError, match="consistency-proof source"):
        verify(entries, require_bundle=True)
    with pytest.raises(C2spCheckpointConsistencyError) as caught:
        verify(entries, trusted_root=bytes(32))
    assert caught.value.category == "LOG_INCONSISTENT"
    assert caught.value.trusted_tree_size == 1
    assert caught.value.observed_tree_size == bundle_checkpoint.tree_size


def test_portable_stream_bundle_equal_checkpoint_is_reusable():
    vector = _vector()
    options = _options(vector)
    verify_c2sp_stream_bundle(vector["bundle"].encode(), options)
    verify_c2sp_stream_bundle(vector["bundle"].encode(), options)


def test_portable_stream_bundle_growth_requires_consistency_source():
    vector = _vector()
    options = _options(vector)
    _seed_old_checkpoint(vector, options)
    with pytest.raises(C2spTlogError, match="requires a consistency-proof source"):
        verify_c2sp_stream_bundle(vector["bundle"].encode(), options)


@pytest.mark.parametrize("trusted_size,category", [
    (3, "LOG_ROLLBACK"), (2, "LOG_FORK"), (1, "LOG_INCONSISTENT"),
])
def test_bundle_classifies_durable_checkpoint_conflicts(tmp_path, trusted_size, category):
    vector = _vector()
    options = _options(vector)
    path = tmp_path / "trust.db"
    store = SQLiteCheckpointStore(path, create=True)
    trusted = TrustedCheckpoint(
        "log.example", trusted_size, bytes(32), datetime.datetime.now(datetime.UTC)
    )
    store.put(trusted)
    options.checkpoint_store = SQLiteCheckpointStore(path)

    class InvalidProof:
        def fetch_consistency_proof(self, reference, from_size, to_size):
            return [bytes(32)]

    options.consistency_source = InvalidProof()
    with pytest.raises(C2spCheckpointConsistencyError) as caught:
        verify_c2sp_stream_bundle(vector["bundle"].encode(), options)
    assert caught.value.category == category
    assert caught.value.origin == trusted.origin
    assert caught.value.trusted_tree_size == trusted_size
    assert caught.value.observed_tree_size == 2
    assert caught.value.trusted_root_hash == trusted.root_hash
    assert caught.value.observed_root_hash != trusted.root_hash
    assert store.get(trusted.origin) == trusted


def test_portable_stream_bundle_growth_verifies_injected_consistency_proof():
    vector = _vector()
    options = _options(vector)
    proof_node = _seed_old_checkpoint(vector, options)

    class Source:
        def fetch_consistency_proof(self, reference, from_size, to_size):
            assert reference.origin == "log.example"
            assert (from_size, to_size) == (1, 2)
            return [proof_node]

    options.consistency_source = Source()
    verify_c2sp_stream_bundle(vector["bundle"].encode(), options)
