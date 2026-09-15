"""Recursive c2sp-tlog migration verification."""

from __future__ import annotations

import base64
import datetime
import hashlib
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog import (
    C2spEventContext,
    C2spMigrationVerificationLimits,
    C2spResourceFetchGuarantees,
    C2spStreamBundleVerifierOptions,
    C2spTlogVerificationError,
    C2spTlogVerificationOptions,
    SignedNoteKey,
    TlogProofV1,
    canonical_bytes,
    canonicalize_c2sp_event,
    create_c2sp_tlog_verification_registry,
    encode_entry_bundle,
    leaf_hash,
    merkle_root_from_entries,
    parse_c2sp_event_entry,
    parse_c2sp_tlog_lr,
    signed_c2sp_event_bytes,
    verify_c2sp_stream_bundle,
)
from dnsid.exceptions import VerificationError
from dnsid.interfaces import NoopLogReader
from dnsid.models import (
    DomainLog,
    IssuanceEvent,
    KeyRotationEvent,
    MigrationEvent,
    RetirementEvent,
    RevocationEvent,
    VerifiedCutoffHistory,
)

_DOMAIN = "agent.example"
_NOW = datetime.datetime.now(datetime.UTC).replace(microsecond=0)


def _key(kid: str):
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return jwk_from_dict(
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "kid": kid,
            "use": "sig",
            "x": b64url_encode(public),
        }
    ), private


def _signed_entry(event, lr: str, entity_private, operational_private=None, *, previous=None,
                  entity_key=None, active_key=None) -> bytes:
    reference = parse_c2sp_tlog_lr(lr)
    context = C2spEventContext(
        scope=reference.scope,
        log_origin=reference.origin,
        stream_id=reference.stream_id,
        lr=reference.lr,
        seq=0,
    )
    if previous is not None:
        import json

        from dnsid.c2sp_tlog.event_codec import c2sp_event_id
        from dnsid.c2sp_tlog.stream_verifier import state_hash
        context.seq = json.loads(previous)["seq"] + 1
        context.prev_event_id = c2sp_event_id(previous)
        context.prev_state_hash = state_hash({"fqdn": event.domain, "status": "ACTIVE",
            "entity_thumb": entity_key.thumbprint(), "operational_thumb": active_key.thumbprint()})
    signed = signed_c2sp_event_bytes(event, context)
    if isinstance(event, KeyRotationEvent):
        assert operational_private is not None
        event.signing_kid = event.previous_kid
        event.sig = b64url_encode(entity_private.sign(signed))
        event.new_operational_proof = b64url_encode(
            operational_private.sign(signed)
        )
    else:
        event.signing_kid = "entity"
        event.sig = b64url_encode(entity_private.sign(signed))
        if isinstance(event, IssuanceEvent):
            assert operational_private is not None
            event.operational_countersig = b64url_encode(
                operational_private.sign(signed)
            )
    return canonicalize_c2sp_event(event, context)


def _verifier_key(
    name: str, signature_type: bytes, private: ed25519.Ed25519PrivateKey
) -> str:
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"{name}+00000000+{base64.b64encode(signature_type + public).decode()}"


def _checkpoint(
    origin: str,
    entries: list[bytes],
    log_private: ed25519.Ed25519PrivateKey,
    witness_private: ed25519.Ed25519PrivateKey,
) -> bytes:
    root = base64.b64encode(merkle_root_from_entries(entries)).decode()
    signed = f"{origin}\n{len(entries)}\n{root}\n"
    log_sig = base64.b64encode(bytes(4) + log_private.sign(signed.encode())).decode()
    timestamp = int(_NOW.timestamp())
    message = f"cosignature/v1\ntime {timestamp}\n{signed}".encode()
    witness_sig = base64.b64encode(
        bytes(4)
        + timestamp.to_bytes(8, "big")
        + witness_private.sign(message)
    ).decode()
    return (
        signed
        + "\n"
        + f"— {origin} {log_sig}\n"
        + f"— migration-witness {witness_sig}\n"
    ).encode()


def _bundle_key(private: ed25519.Ed25519PrivateKey) -> SignedNoteKey:
    name = "migration-bundle"
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = hashlib.sha256(name.encode() + b"\n\x01" + public).digest()[:4]
    return SignedNoteKey(name, public, key_id=key_id, signature_type=b"\x01")


def _bundle(
    lr: str,
    entries: list[bytes],
    checkpoint: bytes,
    policy: bytes,
    private: ed25519.Ed25519PrivateKey,
    key: SignedNoteKey,
) -> bytes:
    if len(entries) == 1:
        proofs = [b""]
    elif len(entries) == 2:
        proofs = [leaf_hash(entries[1]), leaf_hash(entries[0])]
    else:  # pragma: no cover - fixtures here need only one or two entries
        raise AssertionError("unsupported test proof geometry")
    final = parse_c2sp_event_entry(entries[-1])
    logged_state = (
        "RETIRED"
        if isinstance(final, RetirementEvent)
        else "REVOKED"
        if isinstance(final, RevocationEvent)
        else "ACTIVE"
    )
    value = {
        "v": 1,
        "type": "dnsid-c2sp-stream-bundle",
        "fqdn": _DOMAIN,
        "lr": lr,
        "checkpoint": b64url_encode(checkpoint),
        "policy_hash": b64url_encode(hashlib.sha256(policy).digest()),
        "complete_through_size": len(entries),
        "completeness_mode": "trusted-index",
        "events": [
            {
                "index": index,
                "entry": b64url_encode(entry),
                "proof": b64url_encode(proofs[index]),
            }
            for index, entry in enumerate(entries)
        ],
        "state": {
            "event_count": len(entries),
            "last_event_type": str(final.event_type),
            "logged_state": logged_state,
        },
        "expires": int(_NOW.timestamp()) + 30,
    }
    assert key.key_id is not None
    value["sig"] = {
        "alg": "EdDSA",
        "kid": f"{key.name}+{key.key_id.hex()}",
        "value": b64url_encode(private.sign(canonical_bytes(value))),
    }
    return canonical_bytes(value)


class _Fetcher:
    def __init__(self, resources: dict[str, bytes]) -> None:
        self.resources = resources
        self.calls: list[str] = []

    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        self.calls.append(url)
        data = self.resources[url]
        if len(data) > max_bytes:
            raise AssertionError("test fixture exceeded fetch bound")
        return data

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        return C2spResourceFetchGuarantees(True, True, True, True, True)


@dataclass
class _Logs:
    entries: dict[str, list[bytes]]
    entity_key: object
    entity_private: ed25519.Ed25519PrivateKey
    operational_key: object
    operational_private: ed25519.Ed25519PrivateKey

    @classmethod
    def create(cls) -> _Logs:
        entity_key, entity_private = _key("entity")
        operational_key, operational_private = _key("operational")
        return cls(
            {}, entity_key, entity_private, operational_key, operational_private
        )

    def lr(self, name: str) -> str:
        return f"c2sp-tlog:testnet:https://{name}.example#{name}"

    def issuance(self, name: str, *, entity=None, entity_private=None) -> str:
        lr = self.lr(name)
        key = entity or self.entity_key
        private = entity_private or self.entity_private
        event = IssuanceEvent(
            domain=_DOMAIN,
            governance_id="example",
            entity_key=key,
            operational_key=self.operational_key,
            timestamp=_NOW - datetime.timedelta(minutes=5),
        )
        self.entries[lr] = [
            _signed_entry(
                event, lr, private, self.operational_private
            )
        ]
        return lr

    def migration(
        self,
        name: str,
        previous: str,
        cutoff: int,
        *,
        domain: str = _DOMAIN,
        previous_log: str | None = None,
        final_ref: str | None = None,
        new_log: str | None = None,
        signer=None,
    ) -> str:
        lr = self.lr(name)
        event = MigrationEvent(
            domain=domain,
            previous_log=previous if previous_log is None else previous_log,
            new_log=lr if new_log is None else new_log,
            final_entry_ref=(
                f"{previous}@{cutoff}" if final_ref is None else final_ref
            ),
            timestamp=_NOW - datetime.timedelta(minutes=4 - len(self.entries)),
        )
        self.entries[lr] = [
            _signed_entry(event, lr, signer or self.entity_private)
        ]
        return lr

    def invalid_rotation(self, lr: str) -> None:
        new_key, new_private = _key("new-operational")
        event = KeyRotationEvent(
            domain=_DOMAIN,
            previous_kid="operational",
            previous_thumbprint="invalid-thumbprint",
            new_kid="new-operational",
            new_thumbprint=new_key.thumbprint(),
            new_public_key=new_key,
            timestamp=_NOW - datetime.timedelta(minutes=1),
        )
        self.entries[lr].append(
            _signed_entry(
                event, lr, self.operational_private, new_private,
                previous=self.entries[lr][-1], entity_key=self.entity_key,
                active_key=self.operational_key,
            )
        )

    def terminate(self, lr: str, event_type: str = "retired") -> None:
        event = (
            RetirementEvent(
                domain=_DOMAIN,
                timestamp=_NOW - datetime.timedelta(minutes=1),
            )
            if event_type == "retired"
            else RevocationEvent(
                domain=_DOMAIN,
                reason="keyCompromise",
                timestamp=_NOW - datetime.timedelta(minutes=1),
            )
        )
        self.entries[lr].append(
            _signed_entry(event, lr, self.entity_private, previous=self.entries[lr][-1],
                          entity_key=self.entity_key, active_key=self.operational_key)
        )

    def registry(
        self,
        *,
        limits: C2spMigrationVerificationLimits | None = None,
        bundles: bool = False,
        require_bundles: bool = True,
    ):
        witness = ed25519.Ed25519PrivateKey.generate()
        resources: dict[str, bytes] = {}
        policy_lines: list[str] = []
        checkpoints: dict[str, bytes] = {}
        for lr, entries in self.entries.items():
            reference = parse_c2sp_tlog_lr(lr)
            log_private = ed25519.Ed25519PrivateKey.generate()
            policy_lines.append(
                "log " + _verifier_key(reference.origin, b"\x01", log_private)
            )
            checkpoint = _checkpoint(
                reference.origin, entries, log_private, witness
            )
            checkpoints[lr] = checkpoint
            resources[f"{reference.log_prefix}/checkpoint"] = checkpoint
            suffix = "" if len(entries) == 256 else f".p/{len(entries)}"
            resources[f"{reference.log_prefix}/tile/entries/000{suffix}"] = (
                encode_entry_bundle(entries)
            )
        policy_lines.extend(
            [
                "witness migration-witness "
                + _verifier_key("migration-witness", b"\x04", witness),
                "quorum migration-witness",
            ]
        )
        policy = ("\n".join(policy_lines) + "\n").encode()
        bundle_private = ed25519.Ed25519PrivateKey.generate()
        bundle_key = _bundle_key(bundle_private)
        if bundles:
            for lr, entries in self.entries.items():
                reference = parse_c2sp_tlog_lr(lr)
                resources[
                    f"{reference.log_prefix}/streams/{_DOMAIN}?format=bundle"
                ] = _bundle(
                    lr,
                    entries,
                    checkpoints[lr],
                    policy,
                    bundle_private,
                    bundle_key,
                )
        options = C2spTlogVerificationOptions(
            policy_document=policy,
            resource_fetcher=_Fetcher(resources),
            checkpoint_freshness_ms=60_000,
            migration_limits=limits,
            bundle_verifier_keys=[bundle_key] if bundles else None,
            max_bundle_lifetime_ms=60_000 if bundles else None,
            require_stream_bundle=bundles and require_bundles,
        )
        return create_c2sp_tlog_verification_registry(options), options.resource_fetcher


def _history(logs: _Logs, destination: str, **kwargs):
    registry, fetcher = logs.registry(**kwargs)
    reader = registry.new_reader(destination)
    reader.verify_bilateral_binding(
        SimpleNamespace(identity_fqdn=_DOMAIN, gi="example"),
        logs.entity_key,
        logs.operational_key,
    )
    return reader, reader.rebuild_history(_DOMAIN), fetcher


def test_factory_recursively_verifies_single_and_nested_migrations() -> None:
    logs = _Logs.create()
    first = logs.issuance("first")
    second = logs.migration("second", first, 0)
    third = logs.migration("third", second, 0)

    reader, history, _ = _history(logs, third)

    assert [event.event_type for event in history] == [
        "ISSUANCE",
        "MIGRATION",
        "MIGRATION",
    ]
    assert reader._options.migration_reader_factory is not None
    assert reader._options.migration_limits == C2spMigrationVerificationLimits()
    predecessor = reader._options.migration_reader_factory(second)
    assert predecessor._options.transport is reader._options.transport
    assert predecessor._options.checkpoint_store is reader._options.checkpoint_store
    assert predecessor._options.policy is reader._options.policy
    assert predecessor._options.bundle_keys == reader._options.bundle_keys
    snapshot = DomainLog(_DOMAIN, history).snapshot_at(_NOW)
    assert snapshot.governance_id == "example"
    assert snapshot.active_key_thumbprint == logs.operational_key.thumbprint()


def test_prev_ref_is_exact_cutoff_and_later_old_entries_are_excluded() -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    logs.terminate(old)
    new = logs.migration("new", old, 0)

    reader, history, _ = _history(logs, new)
    evidence = reader.verify_non_revocation(_DOMAIN, _NOW)

    assert [event.event_type for event in history] == ["ISSUANCE", "MIGRATION"]
    assert evidence.history_start == f"{old}@0"
    assert evidence.history_end == f"{new}@0"
    historical = reader.verify_non_revocation(
        _DOMAIN, _NOW - datetime.timedelta(minutes=4)
    )
    assert historical.history_end == f"{old}@0"

    logs.entries[new] = []
    bad = logs.migration("new", old, 0, final_ref=f"{logs.lr('other')}@0")
    with pytest.raises(VerificationError, match="prev_ref"):
        _history(logs, bad)


def test_stream_bundles_use_the_same_recursive_cutoff_verification() -> None:
    from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource

    logs = _Logs.create()
    old = logs.issuance("old")
    logs.terminate(old)
    new = logs.migration("new", old, 0)

    reader, history, fetcher = _history(logs, new, bundles=True)

    assert isinstance(reader._source, _FetchedStreamBundleSource)
    assert [event.event_type for event in history] == ["ISSUANCE", "MIGRATION"]
    assert sum("?format=bundle" in url for url in fetcher.calls) == 2
    assert not any("tile/entries" in url for url in fetcher.calls)


def test_standalone_bundle_verifier_rejects_migration_without_predecessor_resolution() -> None:
    from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource

    logs = _Logs.create()
    old = logs.issuance("old")
    new = logs.migration("new", old, 0)
    registry, fetcher = logs.registry(bundles=True)
    reader = registry.new_reader(new)
    source = reader._source
    assert isinstance(source, _FetchedStreamBundleSource)
    reference = parse_c2sp_tlog_lr(new)
    bundle = fetcher.resources[
        f"{reference.log_prefix}/streams/{_DOMAIN}?format=bundle"
    ]
    options = C2spStreamBundleVerifierOptions(
        policy_bytes=source._policy_bytes,
        bundle_keys=source._bundle_keys,
        entity_key=logs.entity_key,
        checkpoint_freshness_ms=source._checkpoint_freshness_ms,
        max_bundle_lifetime_ms=source._max_bundle_lifetime_ms,
        max_bundle_bytes=source._max_bundle_bytes,
        max_events=source._max_events,
        max_tree_size=source._max_tree_size,
        max_clock_skew_ms=source._max_clock_skew_ms,
        now=source._now,
    )

    with pytest.raises(
        C2spTlogVerificationError,
        match="MIGRATION requires verified prior-log history",
    ):
        verify_c2sp_stream_bundle(bundle, options)


def test_raw_read_event_authorizes_migration_through_recursive_history() -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    new = logs.migration("new", old, 0)
    registry, _ = logs.registry()
    reader = registry.new_reader(new)
    reader._options.entity_key = logs.entity_key
    evidence = reader._source.load_stream(reader.parsed, _DOMAIN)
    reader._options.proofs["0"] = TlogProofV1(0, [], evidence.checkpoint)

    event = reader.read_event(f"{new}@0")

    assert event.event_type == "MIGRATION"


def test_invalid_migration_signature_does_not_fetch_its_previous_log() -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    new = logs.migration("new", old, 0)
    valid = logs.entries[new][0]
    _, unrelated_private = _key("unrelated")
    invalid = MigrationEvent(
        domain=_DOMAIN,
        previous_log=logs.lr("missing"),
        new_log=new,
        final_entry_ref=f"{logs.lr('missing')}@0",
        timestamp=_NOW - datetime.timedelta(minutes=3),
    )
    logs.entries[new] = [
        _signed_entry(invalid, new, unrelated_private),
        valid,
    ]

    _, history, fetcher = _history(logs, new)

    assert [event.event_type for event in history] == ["ISSUANCE", "MIGRATION"]
    assert not any("missing.example" in url for url in fetcher.calls)


def test_preferred_bundle_rejects_historical_lr_mismatch_without_fallback() -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    new = logs.migration("new", old, 0)
    registry, fetcher = logs.registry(bundles=True, require_bundles=False)
    old_prefix = parse_c2sp_tlog_lr(old).log_prefix
    new_prefix = parse_c2sp_tlog_lr(new).log_prefix
    fetcher.resources[f"{old_prefix}/streams/{_DOMAIN}?format=bundle"] = (
        fetcher.resources[f"{new_prefix}/streams/{_DOMAIN}?format=bundle"]
    )

    reader = registry.new_reader(new)
    with pytest.raises(VerificationError, match="lr does not match"):
        reader.verify_bilateral_binding(
            SimpleNamespace(identity_fqdn=_DOMAIN, gi="example"),
            logs.entity_key,
            logs.operational_key,
        )
    assert not any(url.startswith(f"{old_prefix}/tile/entries/") for url in fetcher.calls)


def test_non_c2sp_predecessor_uses_method_neutral_exact_cutoff() -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    issuance = parse_c2sp_event_entry(logs.entries[old][0])
    new = logs.migration(
        "new",
        "other:history",
        0,
        final_ref="other:cutoff",
    )
    registry, _ = logs.registry()

    class Reader(NoopLogReader):
        def rebuild_history_through(
            self,
            domain,
            final_entry_ref,
            entity_key,
            **limits,
        ):
            assert domain == _DOMAIN
            assert final_entry_ref == "other:cutoff"
            assert entity_key.thumbprint() == logs.entity_key.thumbprint()
            assert new in limits["seen_log_references"]
            return VerifiedCutoffHistory([issuance], [final_entry_ref], 1)

    registry.register("other", lambda _lr: Reader("other"))
    reader = registry.new_reader(new)
    reader.verify_bilateral_binding(
        SimpleNamespace(identity_fqdn=_DOMAIN, gi="example"),
        logs.entity_key,
        logs.operational_key,
    )

    history = reader.rebuild_history(_DOMAIN)
    assert [event.event_type for event in history] == ["ISSUANCE", "MIGRATION"]
    snapshot = DomainLog(_DOMAIN, history).snapshot_at(_NOW)
    assert snapshot.historical_state == "ACTIVE"
    assert snapshot.active_key_thumbprint == logs.operational_key.thumbprint()


def test_non_c2sp_predecessor_must_return_exact_cutoff_within_bounds() -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    issuance = parse_c2sp_event_entry(logs.entries[old][0])
    new = logs.migration("new", "other:history", 0, final_ref="other:cutoff")
    registry, _ = logs.registry()

    class Reader(NoopLogReader):
        def rebuild_history_through(self, *_args, **kwargs):
            return VerifiedCutoffHistory(
                [issuance], ["other:wrong"], kwargs["max_response_bytes"] + 1
            )

    registry.register("other", lambda _lr: Reader("other"))
    reader = registry.new_reader(new)
    reader._options.entity_key = logs.entity_key

    with pytest.raises(VerificationError, match="exact cutoff or bounds"):
        reader.rebuild_history(_DOMAIN)


def test_recursive_migration_detects_canonical_reference_cycle() -> None:
    logs = _Logs.create()
    first = logs.lr("first")
    second = logs.migration("second", first, 0)
    logs.migration("first", second, 0)

    with pytest.raises(VerificationError, match="cycle"):
        _history(logs, second)


@pytest.mark.parametrize("field", ["max_depth", "max_history_events", "max_response_bytes"])
def test_recursive_migration_limits_must_be_finite_positive_integers(
    field: str,
) -> None:
    with pytest.raises(C2spTlogVerificationError, match="positive integer"):
        C2spMigrationVerificationLimits(**{field: 0})


def test_recursive_migration_limits_depth_events_and_response_bytes() -> None:
    logs = _Logs.create()
    first = logs.issuance("first")
    second = logs.migration("second", first, 0)
    third = logs.migration("third", second, 0)

    cases = [
        (C2spMigrationVerificationLimits(max_depth=1), "depth maximum"),
        (
            C2spMigrationVerificationLimits(max_history_events=2),
            "event maximum",
        ),
        (
            C2spMigrationVerificationLimits(max_response_bytes=1),
            "byte maximum",
        ),
    ]
    for limits, message in cases:
        with pytest.raises(VerificationError, match=message):
            _history(logs, third, limits=limits)


@pytest.mark.parametrize("terminal", ["retired", "revoked"])
def test_recursive_migration_rejects_terminal_prior_state(terminal: str) -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    logs.terminate(old, terminal)
    new = logs.migration("new", old, 1)

    with pytest.raises(VerificationError, match="ACTIVE"):
        _history(logs, new)


@pytest.mark.parametrize(
    "mutation",
    [
        "fqdn",
        "new_lr",
        "prev_lr",
        "entity_key",
        "operational_thumbprint",
        "signature",
    ],
)
def test_recursive_migration_rejects_context_and_key_mismatches(
    mutation: str,
) -> None:
    logs = _Logs.create()
    old = logs.issuance("old")
    kwargs = {}
    if mutation == "fqdn":
        kwargs["domain"] = "other.example"
    elif mutation == "new_lr":
        kwargs["new_log"] = logs.lr("other")
    elif mutation == "prev_lr":
        kwargs["previous_log"] = logs.lr("other")
    elif mutation == "signature":
        _, kwargs["signer"] = _key("other")
    elif mutation == "entity_key":
        other_key, other_private = _key("entity")
        logs.issuance("old", entity=other_key, entity_private=other_private)
    new = logs.migration("new", old, 0, **kwargs)
    if mutation == "operational_thumbprint":
        logs.invalid_rotation(new)

    with pytest.raises(VerificationError):
        _history(logs, new)
