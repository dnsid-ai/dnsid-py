"""Trust profile v2 (epochs): the shared cross-SDK conformance vector.

``tests/vectors/c2sp-trust-profile-epochs-v1.json`` is a byte-for-byte copy of
dnsid-go's ``log/c2sptlog/testdata/c2sp-trust-profile-epochs-v1.json``
(format ``dnsid-c2sp-trust-profile-epochs@v1``, documented next to it in
``c2sp-trust-profile-epochs.md``). Never hand-edit it; regenerate it in
dnsid-go and copy it again. Every key in it is a disposable test key.

Each case runs through the same wiring ``create_c2sp_tlog_verification_registry``
builds: checkpoints through the registry's checkpoint policy and
``enforce_checkpoint_policy``, bundles through the registry reader's bundle
source, and continuity through the trusted checkpoint store.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from dnsid._crypto import jwk_from_dict
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError,
    C2spLifecycleErrorCategory,
    C2spResourceFetchGuarantees,
    C2spStreamBundleVerifierOptions,
    C2spTlogError,
    C2spTlogParseError,
    C2spTlogReader,
    C2spTlogVerificationOptions,
    InMemoryCheckpointStore,
    create_c2sp_tlog_verification_registry,
    enforce_checkpoint_policy,
    parse_c2sp_tlog_lr,
    parse_c2sp_tlog_trust_profile,
    parse_checkpoint,
)
from dnsid.c2sp_tlog.stream_bundle import (
    _FetchedStreamBundleSource,
    _verify_and_advance_checkpoint,
)

VECTOR_PATH = Path(__file__).parent / "vectors" / "c2sp-trust-profile-epochs-v1.json"
VECTOR_FORMAT = "dnsid-c2sp-trust-profile-epochs@v1"
VECTORS: dict[str, Any] = json.loads(VECTOR_PATH.read_bytes())
PARAMS: dict[str, Any] = VECTORS["parameters"]
NOW_MS = PARAMS["now"] * 1000
MAX_AGE_MS = PARAMS["checkpoint_max_age_seconds"] * 1000
SKEW_MS = PARAMS["clock_skew_seconds"] * 1000


class _BundleFetcher:
    """Serve one bundle body for every URL, with full public-read guarantees."""

    def __init__(self) -> None:
        self.body = b""
        self.urls: list[str] = []

    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        self.urls.append(url)
        assert len(self.body) <= max_bytes
        return self.body

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        return C2spResourceFetchGuarantees(True, True, True, True, True)


class _ProofSource:
    def __init__(self, proof: list[bytes]) -> None:
        self.proof = proof

    def fetch_consistency_proof(self, reference, from_size, to_size):  # noqa: ANN001
        return self.proof


def _reader(profile_name: str) -> tuple[C2spTlogReader, _BundleFetcher, InMemoryCheckpointStore]:
    profile = parse_c2sp_tlog_trust_profile(VECTORS["profiles"][profile_name].encode())
    fetcher = _BundleFetcher()
    store = InMemoryCheckpointStore()
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            trust_profile=profile,
            resource_fetcher=fetcher,
            trusted_checkpoint_store=store,
            checkpoint_freshness_ms=MAX_AGE_MS,
            max_clock_skew_ms=SKEW_MS,
            max_bundle_lifetime_ms=PARAMS["max_bundle_lifetime_seconds"] * 1000,
        )
    )
    reader = registry.new_reader(PARAMS["lr"])
    assert isinstance(reader, C2spTlogReader)
    return reader, fetcher, store


def _verify_checkpoint(reader: C2spTlogReader, text: str):  # noqa: ANN202
    checkpoint = parse_checkpoint(text)
    result = enforce_checkpoint_policy(
        checkpoint,
        reader.parsed.origin,
        reader._options.policy,
        reader.parsed.scope,
        NOW_MS,
        SKEW_MS,
        max_checkpoint_age_ms=MAX_AGE_MS,
    )
    return checkpoint, result


def _entity_key():  # noqa: ANN202
    issuance = json.loads(base64.b64decode(VECTORS["tree"]["entries"][0]))
    assert issuance["type"] == "ISSUANCE"
    return jwk_from_dict(issuance["ek"])


_CATEGORY_REASONS = {
    C2spLifecycleErrorCategory.LOG_ROLLBACK: "rollback",
    C2spLifecycleErrorCategory.LOG_FORK: "root_conflict",
    C2spLifecycleErrorCategory.LOG_INCONSISTENT: "consistency_failed",
}
_MESSAGE_REASONS = (
    ("signer is not", "bundle_signer"),
    ("policy_hash mismatch", "policy_hash"),
    ("above trust epoch", "max_tree_size"),
    ("below trust epoch", "min_tree_size"),
    ("witness quorum not satisfied", "witness_quorum"),
    ("stale", "stale"),
    ("missing accepted log signature", "log_signature"),
)


def _reason(exc: BaseException) -> str:
    """Map an SDK error to the vector's language-neutral reason code."""
    if isinstance(exc, C2spCheckpointConsistencyError) and exc.category in _CATEGORY_REASONS:
        return _CATEGORY_REASONS[exc.category]
    message = str(exc)
    for text, reason in _MESSAGE_REASONS:
        if text in message:
            return reason
    return f"unclassified: {message}"


def _check(expect: dict[str, Any], run) -> str:  # noqa: ANN001
    """Run a case; assert accept (and epoch) or reject (and reason)."""
    try:
        epoch = run()
    except C2spTlogError as exc:
        assert expect["result"] == "reject", f"rejected ({_reason(exc)}: {exc}), want accept"
        assert expect["reason"] in VECTORS["reason_codes"]
        assert _reason(exc) == expect["reason"], str(exc)
        return expect["reason"]
    assert expect["result"] == "accept", f"accepted, want reject {expect.get('reason')}"
    assert epoch == expect["epoch"]
    return "accept"


def _case_id(case: dict[str, Any]) -> str:
    return case["name"]


def test_vector_file_format_and_coverage() -> None:
    assert VECTORS["format"] == VECTOR_FORMAT
    counts = {
        name: len(VECTORS[name])
        for name in ("profile_cases", "checkpoint_cases", "bundle_cases", "continuity_cases")
    }
    assert sum(counts.values()) == 73, counts
    names = {case["name"] for kind in counts for case in VECTORS[kind]}
    for required in (
        "t7-6-legacy-below-n", "t7-6-legacy-at-n", "t7-6-successor-at-n",
        "t7-6-successor-above-n", "t7-6-legacy-above-n-capped",
        "t7-6-successor-below-n-floored", "mix-legacy-log-successor-witness",
        "mix-successor-log-legacy-witness", "bundle-legacy-epoch-at-n",
        "bundle-successor-epoch-above-n", "bundle-policy-hash-mismatch",
        "v1-legacy-at-n", "v1-bundle-legacy", "v1-legacy",
        "continuity-equal-root-at-n", "continuity-advance-to-n-plus-k",
        "bundle-shared-kid-selects-legacy", "bundle-shared-kid-selects-successor",
        "bundle-shared-kid-policy-hash-mismatch", "forged-legacy-line-successor-accepts",
        "forged-legacy-line-precedence", "max-tree-size-decimal-point",
        "max-tree-size-exponent", "max-tree-size-boolean", "max-tree-size-string",
        "unsafe-max-tree-size", "max-tree-size-largest",
    ):
        assert required in names, required


@pytest.mark.parametrize("case", VECTORS["profile_cases"], ids=_case_id)
def test_profile_vector(case: dict[str, Any]) -> None:
    document = case["document"].encode("utf-8")
    if case["expect"]["result"] == "reject":
        assert case["expect"]["reason"] == "profile_invalid"
        with pytest.raises(C2spTlogParseError):
            parse_c2sp_tlog_trust_profile(document)
        return
    profile = parse_c2sp_tlog_trust_profile(document)
    assert [epoch.id for epoch in profile.trust_epochs()] == case["epoch_ids"]


@pytest.mark.parametrize("case", VECTORS["checkpoint_cases"], ids=_case_id)
def test_checkpoint_vector(case: dict[str, Any]) -> None:
    reader, _, store = _reader(case["profile"])

    def run() -> str:
        checkpoint, result = _verify_checkpoint(reader, case["checkpoint"])
        assert checkpoint.tree_size == case["tree_size"]
        return result.trust_epoch

    _check(case["expect"], run)
    assert store.get(PARAMS["origin"]) is None


@pytest.mark.parametrize("case", VECTORS["bundle_cases"], ids=_case_id)
def test_bundle_vector(case: dict[str, Any]) -> None:
    reader, fetcher, _ = _reader(case["profile"])
    source = reader._source
    assert isinstance(source, _FetchedStreamBundleSource)
    source._now = lambda: PARAMS["now"]
    fetcher.body = case["bundle"].encode("utf-8")

    def run() -> str:
        verified = source.load_verified_bundle(
            reader.parsed, PARAMS["fqdn"], _entity_key(), None
        )
        assert verified is not None
        return verified.trust_epoch

    _check(case["expect"], run)
    assert fetcher.urls == [
        f"{PARAMS['log_prefix']}/streams/{PARAMS['fqdn']}?format=bundle"
    ]


@pytest.mark.parametrize("case", VECTORS["continuity_cases"], ids=_case_id)
def test_continuity_vector(case: dict[str, Any]) -> None:
    reader, _, store = _reader(case["profile"])
    reference = parse_c2sp_tlog_lr(PARAMS["lr"])
    for index, step in enumerate(case["steps"]):
        proof = [base64.b64decode(item) for item in step["consistency_proof"]]

        def run(step: dict[str, Any] = step, proof: list[bytes] = proof) -> str:
            checkpoint, result = _verify_checkpoint(reader, step["checkpoint"])
            assert result.checkpoint_witness_time is not None
            options = C2spStreamBundleVerifierOptions(
                policy_bytes=b"",
                bundle_keys=[],
                entity_key=_entity_key(),
                checkpoint_freshness_ms=MAX_AGE_MS,
                max_bundle_lifetime_ms=MAX_AGE_MS,
                max_bundle_bytes=1,
                max_events=1,
                consistency_source=_ProofSource(proof),
                checkpoint_store=store,
            )
            _verify_and_advance_checkpoint(
                reference, checkpoint, result.checkpoint_witness_time, options
            )
            return result.trust_epoch

        _check(step["expect"], run)
        trusted = store.get(PARAMS["origin"])
        want = step["trusted_after"]
        if want is None:
            assert trusted is None, f"step {index}"
        else:
            assert trusted is not None, f"step {index}"
            assert trusted.tree_size == want["tree_size"], f"step {index}"
            assert base64.b64encode(trusted.root_hash).decode() == want["root_hash"]


# ---------------------------------------------------------------------------
# Python-specific parse pitfalls the shared vector cannot express as documents
# that every JSON library reads the same way.
# ---------------------------------------------------------------------------

_BOUNDED = json.loads(VECTORS["profiles"]["v2-bounded"])


def _with_bound(raw_value: str) -> bytes:
    """Return v2-bounded with legacy max_tree_size set to a raw JSON token."""
    document = json.loads(VECTORS["profiles"]["v2-bounded"])
    document["epochs"][0]["max_tree_size"] = "__BOUND__"
    return json.dumps(document).replace('"__BOUND__"', raw_value).encode()


@pytest.mark.parametrize(
    "raw_value",
    ["true", "false", "5.0", "5e0", "1E1", '"5"', "-5", "0", "-0", "NaN",
     "Infinity", "-Infinity", "9007199254740992", "18446744073709551616", "[5]", "{}"],
)
def test_tree_size_bound_rejects_non_integer_tokens(raw_value: str) -> None:
    with pytest.raises(C2spTlogParseError):
        parse_c2sp_tlog_trust_profile(_with_bound(raw_value))


@pytest.mark.parametrize("raw_value", ["1", "5", "9007199254740991"])
def test_tree_size_bound_accepts_safe_integers(raw_value: str) -> None:
    document = json.loads(_with_bound(raw_value))
    document["epochs"][1].pop("min_tree_size")
    profile = parse_c2sp_tlog_trust_profile(json.dumps(document).encode())
    assert profile.epochs[0].max_tree_size == int(raw_value)
    assert type(profile.epochs[0].max_tree_size) is int


def test_null_bound_is_open() -> None:
    profile = parse_c2sp_tlog_trust_profile(_with_bound("null"))
    assert profile.epochs[0].max_tree_size is None


@pytest.mark.parametrize(
    "epoch_id", ["", "a" * 65, "leg acy", "légacy", "legacy\n", "１", "a/b", "a+b"]
)
def test_epoch_id_rejects_outside_charset(epoch_id: str) -> None:
    document = json.loads(VECTORS["profiles"]["v2-bounded"])
    document["epochs"][0]["id"] = epoch_id
    with pytest.raises(C2spTlogParseError):
        parse_c2sp_tlog_trust_profile(json.dumps(document).encode())


def test_epoch_id_accepts_full_charset_at_max_length() -> None:
    document = json.loads(VECTORS["profiles"]["v2-bounded"])
    document["epochs"][0]["id"] = ("Az09._-" * 10)[:64]
    profile = parse_c2sp_tlog_trust_profile(json.dumps(document).encode())
    assert profile.epochs[0].id == ("Az09._-" * 10)[:64]


def test_epoch_count_is_bounded() -> None:
    document = json.loads(VECTORS["profiles"]["v2-open"])
    base = document["epochs"][0]
    stranger = VECTORS["keys"]["stranger_bundle"]
    epochs = []
    for index in range(9):
        epoch = dict(base, id=f"e{index}")
        # Distinct kid per epoch keeps bundle selection unambiguous.
        epoch["bundle_verifier_keys"] = [stranger] if index % 2 else base[
            "bundle_verifier_keys"
        ]
        epoch["tlog_policy"] = base["tlog_policy"] + "#" * index
        epochs.append(epoch)
    document["epochs"] = epochs[:8]
    assert len(parse_c2sp_tlog_trust_profile(json.dumps(document).encode()).epochs) == 8
    document["epochs"] = epochs
    with pytest.raises(C2spTlogParseError):
        parse_c2sp_tlog_trust_profile(json.dumps(document).encode())


@pytest.mark.parametrize(
    "member, value",
    [("tlog_policy", ""), ("bundle_verifier_keys", []), ("tlog_policy", None)],
)
def test_version_2_rejects_any_version_1_member(member: str, value: object) -> None:
    document = json.loads(VECTORS["profiles"]["v2-open"])
    document[member] = value
    with pytest.raises(C2spTlogParseError):
        parse_c2sp_tlog_trust_profile(json.dumps(document).encode())


@pytest.mark.parametrize("value", [[], None])
def test_version_1_rejects_any_epochs_member(value: object) -> None:
    document = json.loads(VECTORS["profiles"]["v1-legacy"])
    document["epochs"] = value
    with pytest.raises(C2spTlogParseError):
        parse_c2sp_tlog_trust_profile(json.dumps(document).encode())


@pytest.mark.parametrize("version", ["true", "2.0", '"2"'])
def test_version_must_be_an_exact_integer(version: str) -> None:
    text = VECTORS["profiles"]["v2-open"].replace('"version": 2', f'"version": {version}')
    assert text != VECTORS["profiles"]["v2-open"]
    with pytest.raises(C2spTlogParseError):
        parse_c2sp_tlog_trust_profile(text.encode())


def test_policy_hash_covers_exact_policy_bytes() -> None:
    profile = parse_c2sp_tlog_trust_profile(VECTORS["profiles"]["v2-bounded"].encode())
    raw = json.loads(VECTORS["profiles"]["v2-bounded"])
    for epoch, raw_epoch in zip(profile.epochs, raw["epochs"], strict=True):
        assert epoch.policy_document == raw_epoch["tlog_policy"].encode("utf-8")
        assert epoch.policy_document.endswith(b"\n")
    assert hashlib.sha256(profile.epochs[0].policy_document).digest() != hashlib.sha256(
        profile.epochs[1].policy_document
    ).digest()


def test_version_1_profile_keeps_single_policy_wiring() -> None:
    reader, _, _ = _reader("v1-legacy")
    assert reader._options.policy.epochs == []
    assert reader._options.bundle_epochs is None
    assert isinstance(reader._options.bundle_policy_document, bytes)


def test_bundle_epochs_are_mutually_exclusive_with_single_trust() -> None:
    profile = parse_c2sp_tlog_trust_profile(VECTORS["profiles"]["v2-open"].encode())
    case = next(
        item for item in VECTORS["bundle_cases"] if item["expect"]["result"] == "accept"
        and item["profile"] == "v2-bounded"
    )
    from dnsid.c2sp_tlog import verify_c2sp_stream_bundle

    options = C2spStreamBundleVerifierOptions(
        policy_bytes=profile.epochs[0].policy_document,
        bundle_keys=[],
        entity_key=_entity_key(),
        checkpoint_freshness_ms=MAX_AGE_MS,
        max_bundle_lifetime_ms=MAX_AGE_MS,
        max_bundle_bytes=1 << 20,
        max_events=16,
        now=lambda: PARAMS["now"],
        epochs=profile.trust_epochs(),
    )
    with pytest.raises(C2spTlogError, match="mutually exclusive"):
        verify_c2sp_stream_bundle(case["bundle"].encode(), options)
    options.policy_bytes = b""
    assert verify_c2sp_stream_bundle(case["bundle"].encode(), options).trust_epoch


def _case(kind: str, name: str) -> dict[str, Any]:
    return next(case for case in VECTORS[kind] if case["name"] == name)


def _forge_line(line: str) -> str:
    """Keep a signature line's name and key hash; zero its signature bytes."""
    prefix, _, b64 = line.rpartition(" ")
    raw = base64.b64decode(b64)
    return f"{prefix} {base64.b64encode(raw[:4] + bytes(len(raw) - 4)).decode()}"


def _with_line(text: str, index: int, *, before: bool) -> str:
    body, _, sigs = text.partition("\n\n")
    lines = sigs.rstrip("\n").split("\n")
    forged = _forge_line(lines[index])
    lines.insert(index if before else index + 1, forged)
    return body + "\n\n" + "\n".join(lines) + "\n"


@pytest.mark.parametrize("index", [0, 1], ids=["log-line", "witness-line"])
def test_epoch_rejects_invalid_first_line_under_an_epoch_key(index: int) -> None:
    # Within an epoch the note is opened whole: the first line under each of
    # the epoch's keys must verify, so a forged line cannot hide behind a
    # later valid duplicate.
    reader, _, _ = _reader("v2-bounded")
    case = _case("checkpoint_cases", "t7-6-legacy-at-n")
    forged = _with_line(case["checkpoint"], index, before=True)
    with pytest.raises(C2spTlogError) as raised:
        _verify_checkpoint(reader, forged)
    assert _reason(raised.value) == "log_signature"


@pytest.mark.parametrize("index", [0, 1], ids=["log-line", "witness-line"])
def test_epoch_ignores_later_duplicate_lines(index: int) -> None:
    reader, _, _ = _reader("v2-bounded")
    case = _case("checkpoint_cases", "t7-6-legacy-at-n")
    forged = _with_line(case["checkpoint"], index, before=False)
    assert _verify_checkpoint(reader, forged)[1].trust_epoch == "legacy"


def test_forged_line_in_first_epoch_does_not_block_a_later_epoch() -> None:
    # The dual-signed checkpoint past N fails the legacy epoch (capped), and a
    # forged legacy log line makes legacy fail earlier still; the successor
    # epoch is independent and still accepts.
    reader, _, _ = _reader("v2-bounded")
    case = _case("checkpoint_cases", "dual-log-successor-witness-past-n")
    body, _, sigs = case["checkpoint"].partition("\n\n")
    lines = sigs.rstrip("\n").split("\n")
    legacy_log = VECTORS["keys"]["legacy_log"]
    legacy_hash = bytes.fromhex(legacy_log.split("+")[1])
    forged = "— log.example " + base64.b64encode(legacy_hash + bytes(64)).decode()
    lines = [forged, *[line for line in lines if not _is_line_under(line, legacy_hash)]]
    text = body + "\n\n" + "\n".join(lines) + "\n"
    assert _verify_checkpoint(reader, text)[1].trust_epoch == "successor"


def _is_line_under(line: str, key_hash: bytes) -> bool:
    return base64.b64decode(line.rpartition(" ")[2])[:4] == key_hash
