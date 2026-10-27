"""Hash-tile roots, authentication precedence, geometry, and resource bounds."""

import datetime
import random
from collections import Counter
from dataclasses import replace

import pytest

from dnsid._verification_budget import BudgetExhausted, verification_budget
from dnsid.c2sp_tlog import (
    C2spCheckpointConsistencyError,
    C2spTlogTransportError,
    ScanStreamSource,
    TrustedCheckpoint,
    leaf_hash,
    merkle_root_from_entries,
    node_hash,
    parse_c2sp_tlog_lr,
)
from dnsid.c2sp_tlog._async import run_verification
from dnsid.c2sp_tlog.hash_tiles import consistency_tiles
from dnsid.c2sp_tlog.tiles import tile_path

PREFIX = "https://log.example"
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)


class Tree:
    """Independent in-memory binary RFC 6962 tree, retaining complete subtrees."""

    def __init__(self, size):
        self.levels = [[leaf_hash(i.to_bytes(4, "big")) for i in range(size)]]
        while len(self.levels[-1]) > 1:
            previous = self.levels[-1]
            self.levels.append([
                node_hash(previous[i], previous[i + 1])
                for i in range(0, len(previous) - 1, 2)
            ])

    def root(self, size, start=0):
        if not size:
            return merkle_root_from_entries([])
        if size & (size - 1) == 0:
            return self.levels[size.bit_length() - 1][start // size]
        split = 1 << (size.bit_length() - 1)
        return node_hash(self.root(split, start), self.root(size - split, start + split))

    def checkpoint(self, size):
        return TrustedCheckpoint("log.example", size, self.root(size), NOW)

    def read(self, request):
        url, maximum = request
        suffix = url.removeprefix(PREFIX + "/tile/")
        level, path = suffix.split("/", 1)
        path, separator, partial = path.partition(".p/")
        index = int(path.replace("x", "").replace("/", ""))
        width = int(partial) if separator else 256
        hashes = self.levels[8 * int(level)][index * 256:index * 256 + width]
        assert len(hashes) == width
        assert maximum == 32 * width
        return b"".join(hashes)


@pytest.fixture(scope="module")
def tree():
    return Tree(400_000)


def verify(tree, m, n, *, read=None, trusted=None, candidate=None):
    requests = []

    def fetch(request):
        requests.append(request)
        return (read or tree.read)(request)

    run_verification(
        consistency_tiles(PREFIX, trusted or tree.checkpoint(m),
                          candidate or tree.checkpoint(n), 1_000_000),
        fetch,
    )
    return requests


def test_roots_and_two_tiles_per_level_across_tree_boundaries(tree):
    boundaries = sorted({
        value + offset for power in range(1, 19)
        for value in (1 << power, ((1 << power) // 256) * 256)
        for offset in (-1, 0, 1) if 1 < value + offset <= 400_000
    } | {70_000, 131_328, 316_417})
    pairs = {(m, n) for n in range(2, 81) for m in range(1, n)}
    pairs.update((m, n) for n in boundaries
                 for m in {1, n - 1, n // 2, *boundaries} if 0 < m < n)
    rng = random.Random(0)
    pairs.update((rng.randrange(1, n), n) for n in
                 (rng.randrange(2, 400_001) for _ in range(500)))
    for m, n in sorted(pairs):
        requests = verify(tree, m, n)
        counts = Counter(url.removeprefix(PREFIX + "/tile/").split("/")[0]
                         for url, _ in requests)
        assert max(counts.values()) <= 2, (m, n, requests)
        assert len(requests) == len(set(requests)), (m, n, requests)
        assert all("/entries/" not in url for url, _ in requests)
    assert len(verify(tree, 300, 70_000)) == 5
    assert tile_path(PREFIX, 0, 1234) == PREFIX + "/tile/0/x001/234"
    assert any("/x001/234" in url for url, _ in verify(tree, 315_905, 316_417))
    for n in (0, 1, 2, 255, 256, 257, 65_537):
        assert tree.root(n) == merkle_root_from_entries([i.to_bytes(4, "big") for i in range(n)])


@pytest.mark.parametrize("m", [1, 2, 3, 256, 65_536])
def test_wrong_trusted_root_is_inconsistent_even_at_powers_of_two(tree, m):
    trusted = replace(tree.checkpoint(m), root_hash=bytes(32))
    with pytest.raises(C2spCheckpointConsistencyError) as error:
        verify(tree, m, 70_000, trusted=trusted)
    assert error.value.category == "LOG_INCONSISTENT"
    assert error.value.trusted_root_hash == bytes(32)
    assert error.value.observed_root_hash == tree.root(70_000)


@pytest.mark.parametrize("tile", range(5))
def test_each_changed_tile_is_invalid_before_trusted_comparison(tree, tile):
    requests = verify(tree, 300, 70_000)
    target = requests[tile]

    def read(request):
        data = tree.read(request)
        if request == target:
            return bytes([data[0] ^ 1]) + data[1:]
        return data

    with pytest.raises(C2spCheckpointConsistencyError) as error:
        verify(tree, 300, 70_000, read=read,
               trusted=replace(tree.checkpoint(300), root_hash=bytes(32)))
    assert error.value.category == "INVALID_EVIDENCE"
    # Includes full tiles 0/001 and 1/000, neither on the candidate right edge.
    assert (PREFIX + "/tile/0/001", 8192) in requests


@pytest.mark.parametrize("delta", [-32, -1, 1, 32])
@pytest.mark.parametrize("tile", ["/tile/0/001", "/tile/0/273.p/112"])
def test_exact_tile_lengths_are_required(tree, delta, tile):
    def read(request):
        data = tree.read(request)
        if request[0].endswith(tile):
            return data[:delta] if delta < 0 else data + bytes(delta)
        return data

    with pytest.raises(C2spCheckpointConsistencyError) as error:
        verify(tree, 300, 70_000, read=read)
    assert error.value.category == "INVALID_EVIDENCE"


@pytest.mark.parametrize("status", [403, 404])
def test_missing_partial_retries_full_once_without_checkpoint_fetch(tree, status):
    calls = []

    def read(request):
        calls.append(request)
        url, maximum = request
        if ".p/" in url:
            raise C2spTlogTransportError("missing partial", transient=False, status_code=status)
        # Full successor tiles need only have an authentic candidate-size prefix.
        partial = next((r for r in calls if r[0].split(".p/")[0] == url and ".p/" in r[0]), None)
        if partial:
            data = tree.read(partial)
            return data + bytes(maximum - len(data))
        return tree.read(request)

    verify(tree, 300, 70_000, read=read)
    assert len(calls) == 8  # Five tiles plus the three missing-partial retries.
    assert len(calls) == len(set(calls))
    assert all("/tile/" in url for url, _ in calls)


@pytest.mark.parametrize("retry_length", [8191, 8193])
def test_full_retry_requires_exact_length(tree, retry_length):
    def read(request):
        if ".p/" in request[0]:
            raise C2spTlogTransportError("missing", transient=False, status_code=404)
        return bytes(retry_length)

    with pytest.raises(C2spCheckpointConsistencyError) as error:
        verify(tree, 300, 70_000, read=read)
    assert error.value.category == "INVALID_EVIDENCE"


@pytest.mark.parametrize("on_retry", [False, True])
@pytest.mark.parametrize("termination", ["cancellation", "deadline"])
def test_tile_reads_and_retries_share_overall_budget(tree, monkeypatch, on_retry, termination):
    import threading

    clock = [0.0]
    cancel = threading.Event()
    calls = []
    monkeypatch.setattr("dnsid._verification_budget.time.monotonic", lambda: clock[0])

    def read(request):
        calls.append(request)
        if on_retry and len(calls) == 1:
            raise C2spTlogTransportError("missing", transient=False, status_code=404)
        if termination == "deadline":
            clock[0] = 2.0
        else:
            cancel.set()
        return bytes(request[1])

    with pytest.raises(BudgetExhausted), verification_budget(timeout=1, cancelled=cancel):
        verify(tree, 300, 70_000, read=read)
    assert len(calls) == (2 if on_retry else 1)


def test_tree_limit_is_checked_before_tile_reads(tree):
    requests = []
    with pytest.raises(C2spCheckpointConsistencyError) as error:
        run_verification(
            consistency_tiles(PREFIX, tree.checkpoint(1), tree.checkpoint(70_000), 69_999),
            lambda request: requests.append(request),
        )
    assert error.value.category == "INVALID_EVIDENCE"
    assert requests == []


def test_bounded_fetcher_rejects_oversized_tile(tree):
    class Fetcher:
        def fetch_bounded(self, url, maximum):
            return bytes(maximum + 1)

    source = ScanStreamSource(Fetcher(), lambda checkpoint: None)
    with pytest.raises(C2spTlogTransportError) as error:
        source.verify_checkpoint_consistency(
            parse_c2sp_tlog_lr("c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"),
            tree.checkpoint(1), tree.checkpoint(2),
        )
    assert error.value.category == "INVALID_EVIDENCE"
    assert not error.value.transient
