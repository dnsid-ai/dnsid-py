"""Stream sources: fetch a checkpoint plus every entry of a C2SP log.

Synchronous transports remain supported; bounded fetchers may add native async reads.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from typing import Protocol, cast

from .._verification_budget import (
    async_run_blocking,
    async_verification_operation,
    verification_operation,
)
from .checkpoint import Checkpoint, parse_checkpoint
from .checkpoint_store import TrustedCheckpoint
from .errors import C2spTlogError, C2spTlogTransportError, C2spTlogVerificationError
from .hash_tiles import consistency_tiles
from .lr import ParsedC2spTlogLr
from .resource_fetcher import (
    C2spBoundedResourceFetcher,
    C2spResourceFetchGuarantees,
    async_fetch_bounded_bytes,
    fetch_bounded_bytes,
)
from .tiles import checkpoint_path, entry_bundle_path, parse_entry_bundle

C2spTlogTransport = Callable[[str], "bytes | str"] | C2spBoundedResourceFetcher
"""Lower-level callable transport or bounded standard-resource fetcher."""


_ENTRIES_PER_BUNDLE = 256
_DEFAULT_MAX_TREE_SIZE = 1_000_000
_DEFAULT_MAX_CHECKPOINT_BYTES = 1_048_576
_DEFAULT_MAX_ENTRY_BUNDLE_BYTES = 16_777_472
_DEFAULT_MAX_TOTAL_ENTRY_BYTES = 268_435_456


@dataclass(frozen=True)
class C2spScanLimits:
    """Resource limits for the built-in complete C2SP log scanner.

    C2SP entry-bundle geometry is fixed at 256 entries. Defaults bound the
    scanner to one million entries, 1 MiB checkpoints, exactly 16,777,472
    bytes per bundle, and 256 MiB total entry-bundle bytes.
    """

    max_tree_size: int = _DEFAULT_MAX_TREE_SIZE
    max_checkpoint_bytes: int = _DEFAULT_MAX_CHECKPOINT_BYTES
    max_entry_bundle_bytes: int = _DEFAULT_MAX_ENTRY_BUNDLE_BYTES
    max_total_entry_bytes: int = _DEFAULT_MAX_TOTAL_ENTRY_BYTES

    def __post_init__(self) -> None:
        """Validate scanner limits when the configuration is created."""
        _positive(self.max_tree_size, "max_tree_size")
        _positive(self.max_checkpoint_bytes, "max_checkpoint_bytes")
        _positive(self.max_entry_bundle_bytes, "max_entry_bundle_bytes")
        _positive(self.max_total_entry_bytes, "max_total_entry_bytes")


@dataclass
class IndexedEntry:
    """One raw log entry paired with its zero-based leaf index."""

    index: int
    data: bytes


@dataclass
class C2spProvenEntry:
    """Untrusted single-entry evidence returned by a ``C2spTlogSource``."""

    index: int
    entry_bytes: bytes
    inclusion_proof: list[bytes]
    checkpoint: bytes


@dataclass
class StreamEvidence:
    """A checkpoint and the entries fetched under it."""

    checkpoint: Checkpoint
    entries: list[IndexedEntry] = field(default_factory=list)
    complete: bool = False
    checkpoint_bytes: bytes = b""
    completeness_mode: str = ""
    complete_through_size: int | None = None
    response_bytes: int | None = None


C2spStreamEvidence = StreamEvidence


class C2spTlogSource(Protocol):
    """Source-neutral interface returning untrusted C2SP evidence."""

    def fetch_checkpoint(self, reference: ParsedC2spTlogLr) -> bytes:
        """Fetch the raw signed checkpoint bytes for *reference*."""
        ...

    def read_entry(self, reference: ParsedC2spTlogLr, index: int) -> C2spProvenEntry:
        """Return entry *index* with an inclusion proof and its checkpoint."""
        ...

    def load_stream(
        self, reference: ParsedC2spTlogLr, fqdn: str
    ) -> C2spStreamEvidence:
        """Return checkpoint-plus-entries evidence covering *fqdn*'s stream."""
        ...


class AsyncC2spTlogSource(C2spTlogSource, Protocol):
    """Optional async evidence reads with the same guarantees as C2spTlogSource."""

    async def async_fetch_checkpoint(self, reference: ParsedC2spTlogLr) -> bytes:
        """Fetch the raw signed checkpoint bytes without blocking."""
        ...

    async def async_read_entry(self, reference: ParsedC2spTlogLr, index: int) -> C2spProvenEntry:
        """Return bounded, untrusted inclusion evidence without blocking."""
        ...

    async def async_load_stream(self, reference: ParsedC2spTlogLr, fqdn: str) -> C2spStreamEvidence:
        """Return the same complete evidence as load_stream without blocking."""
        ...


class C2spConsistencyProofSource(Protocol):
    """Optional source for RFC 6962 checkpoint consistency proofs."""

    def fetch_consistency_proof(
        self, reference: ParsedC2spTlogLr, from_size: int, to_size: int
    ) -> list[bytes]:
        """Return the RFC 6962 consistency proof from *from_size* to *to_size*."""
        ...


class ScanStreamSource:
    """Fetches the checkpoint and scans every entry bundle beneath it.

    *authenticate_checkpoint* runs against the parsed checkpoint before any
    entries are fetched (policy enforcement lives there).
    """

    def __init__(
        self,
        transport: C2spTlogTransport,
        authenticate_checkpoint: Callable[[Checkpoint], None],
        *,
        max_tree_size: int = _DEFAULT_MAX_TREE_SIZE,
        max_checkpoint_bytes: int = _DEFAULT_MAX_CHECKPOINT_BYTES,
        max_entry_bundle_bytes: int = _DEFAULT_MAX_ENTRY_BUNDLE_BYTES,
        max_total_entry_bytes: int = _DEFAULT_MAX_TOTAL_ENTRY_BYTES,
    ) -> None:
        """Bind the source to *transport* and validate its resource limits.

        Raises:
            C2spTlogVerificationError: If any limit is not a positive integer.
        """
        self._transport = transport
        self._authenticate_checkpoint = authenticate_checkpoint
        self._entries_per_bundle = _ENTRIES_PER_BUNDLE
        self._max_tree_size = _positive(max_tree_size, "max_tree_size")
        self._max_checkpoint_bytes = _positive(max_checkpoint_bytes, "max_checkpoint_bytes")
        self._max_entry_bundle_bytes = _positive(
            max_entry_bundle_bytes, "max_entry_bundle_bytes"
        )
        self._max_total_entry_bytes = _positive(
            max_total_entry_bytes, "max_total_entry_bytes"
        )

    def load(self, prefix: str) -> StreamEvidence:
        """Fetch the checkpoint under *prefix* and scan every entry beneath it.

        Returns:
            Complete evidence: the authenticated checkpoint plus all entries.

        Raises:
            C2spTlogParseError: If the checkpoint or an entry bundle is
                malformed.
            C2spTlogVerificationError: If checkpoint authentication fails, a
                configured size limit is exceeded, or a bundle width is wrong.
        """
        steps = self._load_steps(prefix)
        try:
            url, maximum = next(steps)
            while True:
                url, maximum = steps.send(self._bytes(url, maximum))
        except StopIteration as done:
            return cast(StreamEvidence, done.value)
        finally:
            steps.close()

    @async_verification_operation
    async def async_load(self, prefix: str) -> StreamEvidence:
        """Scan standard resources asynchronously, authenticating before tile reads."""
        from ._async import async_run_verification

        async def read(request: tuple[str, int]) -> bytes:
            url, maximum = request
            if callable(getattr(self._transport, "fetch_bounded", None)):
                return await async_fetch_bounded_bytes(self._transport, url, maximum)
            return await async_run_blocking(self._bytes, url, maximum)

        return await async_run_verification(self._load_steps(prefix), read)

    def _load_steps(self, prefix: str) -> Generator[tuple[str, int], bytes, StreamEvidence]:
        checkpoint_bytes = yield checkpoint_path(prefix), self._max_checkpoint_bytes
        checkpoint = parse_checkpoint(checkpoint_bytes.decode("utf-8"))
        self._authenticate_checkpoint(checkpoint)
        if checkpoint.tree_size > self._max_tree_size:
            raise C2spTlogVerificationError(
                f"checkpoint tree size exceeds configured maximum {self._max_tree_size}"
            )

        entries: list[IndexedEntry] = []
        total_entry_bytes = 0
        n = 0
        while n * self._entries_per_bundle < checkpoint.tree_size:
            want = min(
                self._entries_per_bundle,
                checkpoint.tree_size - n * self._entries_per_bundle,
            )
            width = None if want == self._entries_per_bundle else want
            bundle_bytes = yield entry_bundle_path(prefix, n, width), self._max_entry_bundle_bytes
            total_entry_bytes += len(bundle_bytes)
            if total_entry_bytes > self._max_total_entry_bytes:
                raise C2spTlogVerificationError(
                    "entry bundles exceed configured total byte maximum "
                    f"{self._max_total_entry_bytes}"
                )
            bundle = parse_entry_bundle(bundle_bytes)
            if len(bundle) != want:
                raise C2spTlogVerificationError("entry bundle width mismatch")
            for i, entry in enumerate(bundle):
                entries.append(
                    IndexedEntry(index=n * self._entries_per_bundle + i, data=entry)
                )
            n += 1
        return StreamEvidence(
            checkpoint=checkpoint,
            entries=entries,
            complete=True,
            checkpoint_bytes=checkpoint_bytes,
            completeness_mode="full-scan",
            complete_through_size=checkpoint.tree_size,
            response_bytes=len(checkpoint_bytes) + total_entry_bytes,
        )

    @verification_operation
    def verify_checkpoint_consistency(
        self, reference: ParsedC2spTlogLr,
        trusted: TrustedCheckpoint, candidate: TrustedCheckpoint,
    ) -> None:
        """Authenticate continuity from bounded hash tiles, without scanning entries."""
        from ._async import run_verification

        run_verification(
            consistency_tiles(reference.log_prefix, trusted, candidate, self._max_tree_size),
            lambda request: self._bytes(*request),
        )

    @async_verification_operation
    async def async_verify_checkpoint_consistency(
        self, reference: ParsedC2spTlogLr,
        trusted: TrustedCheckpoint, candidate: TrustedCheckpoint,
    ) -> None:
        """Authenticate continuity with native async tile reads when available."""
        from ._async import async_run_verification

        async def read(request: tuple[str, int]) -> bytes:
            if callable(getattr(self._transport, "fetch_bounded", None)):
                return await async_fetch_bounded_bytes(self._transport, *request)
            return await async_run_blocking(self._bytes, *request)

        await async_run_verification(
            consistency_tiles(reference.log_prefix, trusted, candidate, self._max_tree_size),
            read,
        )

    def security_guarantees(self) -> C2spResourceFetchGuarantees | None:
        """Return the injected fetcher's public-read capabilities, if declared."""
        if not callable(getattr(self._transport, "fetch_bounded", None)):
            return None
        provider = getattr(self._transport, "security_guarantees", None)
        value = provider() if callable(provider) else None
        return value if isinstance(value, C2spResourceFetchGuarantees) else None

    def fetch_checkpoint(self, reference: ParsedC2spTlogLr) -> bytes:
        """Fetch bounded raw checkpoint bytes for *reference*."""
        return self._bytes(
            checkpoint_path(reference.log_prefix), self._max_checkpoint_bytes
        )

    def load_stream(
        self, reference: ParsedC2spTlogLr, fqdn: str
    ) -> C2spStreamEvidence:
        """Load a full scan; the reader verifies *fqdn* and all evidence."""
        return self.load(reference.log_prefix)

    def read_entry(self, reference: ParsedC2spTlogLr, index: int) -> C2spProvenEntry:
        """Return one entry plus a proof derived from a complete scan."""
        evidence = self.load_stream(reference, reference.stream_id)
        return self._proven_entry(evidence, index)

    @async_verification_operation
    async def async_fetch_checkpoint(self, reference: ParsedC2spTlogLr) -> bytes:
        """Fetch one bounded checkpoint using the native capability if present."""
        url = checkpoint_path(reference.log_prefix)
        if callable(getattr(self._transport, "fetch_bounded", None)):
            return await async_fetch_bounded_bytes(self._transport, url, self._max_checkpoint_bytes)
        return await async_run_blocking(self._bytes, url, self._max_checkpoint_bytes)

    async def async_load_stream(self, reference: ParsedC2spTlogLr, fqdn: str) -> C2spStreamEvidence:
        """Load complete raw evidence through native async resource reads."""
        return await self.async_load(reference.log_prefix)

    async def async_read_entry(self, reference: ParsedC2spTlogLr, index: int) -> C2spProvenEntry:
        """Build an inclusion proof from an asynchronously fetched full scan."""
        evidence = await self.async_load_stream(reference, reference.stream_id)
        return await async_run_blocking(self._proven_entry, evidence, index)

    @staticmethod
    def _proven_entry(evidence: StreamEvidence, index: int) -> C2spProvenEntry:
        entries = sorted(evidence.entries, key=lambda entry: entry.index)
        if index < 0 or index >= len(entries) or entries[index].index != index:
            raise C2spTlogVerificationError(f"C2SP entry index out of range: {index}")
        return C2spProvenEntry(
            index=index,
            entry_bytes=entries[index].data,
            inclusion_proof=_inclusion_proof(
                [entry.data for entry in entries], index
            ),
            checkpoint=evidence.checkpoint_bytes,
        )

    def _bytes(self, url: str, maximum: int) -> bytes:
        if callable(getattr(self._transport, "fetch_bounded", None)):
            return fetch_bounded_bytes(self._transport, url, maximum)
        try:
            response = cast(Callable[[str], bytes | str], self._transport)(url)
        except C2spTlogError:
            raise
        except (ConnectionError, OSError, TimeoutError) as exc:
            raise C2spTlogTransportError(
                f"failed to fetch C2SP resource: {url}", transient=True, cause=exc
            ) from exc
        except Exception as exc:
            raise C2spTlogTransportError(
                f"failed to fetch C2SP resource: {url}", transient=False, cause=exc
            ) from exc
        data = response.encode("utf-8") if isinstance(response, str) else response
        if not isinstance(data, bytes):
            raise C2spTlogTransportError(
                f"C2SP transport returned a non-bytes response: {url}",
                transient=False,
            )
        if len(data) > maximum:
            raise C2spTlogTransportError(
                f"C2SP response exceeds configured byte maximum {maximum}: {url}",
                transient=False,
            )
        return data


def enforce_public_read_guarantees(
    source: object, reference: ParsedC2spTlogLr
) -> None:
    """Fail closed unless *source* demonstrates the public transport contract."""
    del reference  # Capabilities apply to every URL the source may fetch.
    provider = getattr(source, "security_guarantees", None)
    guarantees = provider() if callable(provider) else None
    if not isinstance(guarantees, C2spResourceFetchGuarantees):
        raise C2spTlogVerificationError(
            "public c2sp-tlog source must declare resource-fetch security capabilities"
        )
    missing = [
        description
        for enabled, description in (
            (guarantees.https_only, "HTTPS-only transport"),
            (guarantees.rejects_redirects, "redirect rejection"),
            (
                guarantees.validates_all_resolved_addresses,
                "validation of every resolved address",
            ),
            (
                guarantees.connects_to_validated_address,
                "connection to a validated address",
            ),
            (
                guarantees.bounds_response_during_read,
                "response bounding during reads",
            ),
        )
        if enabled is not True
    ]
    if missing:
        raise C2spTlogVerificationError(
            "public c2sp-tlog source lacks " + ", ".join(missing)
        )


def _positive(value: int, name: str) -> int:
    if type(value) is not int or value < 1:
        raise C2spTlogVerificationError(f"{name} must be a positive integer")
    return value


def _inclusion_proof(entries: list[bytes], index: int) -> list[bytes]:
    """Build an RFC 6962 inclusion proof from a complete ordered entry list."""
    from .merkle import leaf_hash, node_hash

    if index < 0 or index >= len(entries):
        raise C2spTlogVerificationError(f"C2SP entry index out of range: {index}")
    level = [leaf_hash(entry) for entry in entries]
    position = index
    proof: list[bytes] = []
    while len(level) > 1:
        if position % 2 == 1:
            proof.append(level[position - 1])
        elif position + 1 < len(level):
            proof.append(level[position + 1])
        next_level: list[bytes] = []
        for offset in range(0, len(level), 2):
            if offset + 1 < len(level):
                next_level.append(node_hash(level[offset], level[offset + 1]))
            else:
                next_level.append(level[offset])
        level = next_level
        position //= 2
    return proof
