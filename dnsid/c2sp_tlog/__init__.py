"""c2sp-tlog — LogReader for C2SP tile-log transparency logs.

Wire-compatible with the other DNSid SDKs' c2sp-tlog implementations.
Use the generic verification convenience factory with caller-supplied trust:

    from dnsid.c2sp_tlog import (
        C2spTlogVerificationOptions,
        create_c2sp_tlog_verification_registry,
    )

    log_registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_url="https://policy.example/dnsid-policy",
        )
    )

The policy URL is independently trusted configuration and is never discovered
from an unverified identity record. The separately named
``create_dnsid_managed_verification_registry`` factory opts into reviewed,
SDK-embedded Identity Digital trust roots. Lower-level reader registration
remains available for custom sources, mirrors, and private transports.
"""

from __future__ import annotations

from dataclasses import replace

from ..registry import LogRegistry
from .canonical import (
    assert_canonical_json_bytes,
    canonical_bytes,
    canonical_json,
    parse_json_no_duplicate_members,
)
from .checkpoint import Checkpoint, NoteSignature, parse_checkpoint, parse_note_signature
from .checkpoint_store import (
    CheckpointStore,
    InMemoryCheckpointStore,
    TrustedCheckpoint,
)
from .errors import (
    C2spCheckpointConsistencyError,
    C2spCheckpointStoreError,
    C2spLifecycleErrorCategory,
    C2spTlogError,
    C2spTlogParseError,
    C2spTlogTransportError,
    C2spTlogVerificationError,
)
from .event_codec import (
    C2spEventContext,
    C2spSignatureValue,
    c2sp_envelope_to_event,
    c2sp_event_id,
    canonicalize_c2sp_event,
    event_to_c2sp_envelope,
    parse_c2sp_event_entry,
    parse_c2sp_signatures,
    required_c2sp_signature_names,
    signed_c2sp_entry_bytes,
    signed_c2sp_event_bytes,
)
from .lr import (
    ParsedC2spTlogLr,
    canonical_log_prefix,
    checkpoint_origin,
    generate_c2sp_tlog_stream_id,
    parse_c2sp_tlog_lr,
)
from .managed_verification_registry import (
    DnsidManagedVerificationOptions,
    create_dnsid_managed_verification_registry,
)
from .merkle import (
    inclusion_root,
    leaf_hash,
    merkle_root_from_entries,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from .policy import (
    C2spTlogOriginPolicy,
    C2spTlogPolicy,
    C2spTlogQuorumRule,
    CheckpointPolicyResult,
    enforce_checkpoint_policy,
    normalized_origin_policy,
    parse_c2sp_policy_file,
)
from .prepared import (
    C2spChain,
    C2spSignerRole,
    C2spVerificationContext,
    PreparedC2spTlogEvent,
    entry_bytes,
    parse_prepared_event,
    prepare_event,
    required_signer_roles,
    sign_prepared_event,
    write_prepared_event,
)
from .proof import TlogProofV1, parse_tlog_proof_v1, verify_c2sp_tlog_proof
from .reader import (
    C2spMigrationVerificationLimits,
    C2spTlogReader,
    C2spTlogReaderOptions,
)
from .resource_fetcher import (
    C2spBoundedResourceFetcher,
    C2spResourceFetchGuarantees,
    SafeC2spResourceFetcher,
)
from .signed_note import (
    SignedNoteKey,
    parse_signed_note_verifier_key,
    verified_cosignature_timestamp,
    verify_checkpoint_signature,
    verify_note_signature,
)
from .sqlite_checkpoint_store import SQLiteCheckpointStore
from .stream_bundle import (
    C2spStreamBundleVerifierOptions,
    VerifiedC2spStreamBundle,
    verify_c2sp_stream_bundle,
)
from .stream_source import (
    C2spConsistencyProofSource,
    C2spProvenEntry,
    C2spScanLimits,
    C2spStreamEvidence,
    C2spTlogSource,
    C2spTlogTransport,
    IndexedEntry,
    ScanStreamSource,
    StreamEvidence,
)
from .stream_verifier import (
    MigrationVerificationResult,
    StreamVerifierOptions,
    VerifiedLifecycleEvent,
    state_hash,
    verify_lifecycle,
    verify_logged_event_signature,
    verify_stream_lifecycle,
)
from .tiles import (
    checkpoint_path,
    encode_entry_bundle,
    entry_bundle_path,
    parse_entry_bundle,
    tile_path,
)
from .trust_profile import C2spTlogTrustProfile, parse_c2sp_tlog_trust_profile
from .verification_registry import (
    C2spTlogVerificationOptions,
    create_c2sp_tlog_verification_registry,
)


def register_c2sp_tlog(registry: LogRegistry, options: C2spTlogReaderOptions) -> None:
    """Register the c2sp-tlog reader factory on *registry*."""
    bound_options = replace(
        options, migration_reader_factory=registry.new_reader
    )
    registry.register(
        "c2sp-tlog", lambda lr: C2spTlogReader(lr, bound_options)
    )


#: Exact C2SP specification revisions this binding implements.  These are the
#: pinned spec tags from https://github.com/C2SP/C2SP; profile dispatch and
#: wire formats follow these revisions exactly and are never inferred from
#: newer spec versions.
C2SP_SPEC_REVISIONS: dict[str, str] = {
    "tlog-checkpoint": "v1.0.0",
    "tlog-tiles": "v0.1.0",
    "tlog-proof": "ab17a74116563005f908b9167e6421cc929a5c2b",
    "tlog-policy": "1896a5aea5559b3203d275d0206d872f59348cf5",
    "tlog-witness": "v1.0.0",
    "tlog-cosignature": "v1.0.1",
    "tlog-mirror": "d0fe789122c75b903bfc1680b0b8b8dc570f0db3",
    "signed-note": "v1.0.0",
}

#: DNSid lifecycle event envelope version implemented by this binding
#: (the envelope's top-level ``v`` member).
DNSID_C2SP_ENVELOPE_VERSION: int = 1


__all__ = [
    "C2spEventContext",
    "C2spConsistencyProofSource",
    "C2spSignatureValue",
    "C2spTlogError",
    "C2spCheckpointConsistencyError",
    "C2spCheckpointStoreError",
    "C2spLifecycleErrorCategory",
    "C2spMigrationVerificationLimits",
    "C2spTlogOriginPolicy",
    "C2spTlogParseError",
    "C2spTlogTransportError",
    "C2spTlogPolicy",
    "C2spTlogQuorumRule",
    "C2spTlogReader",
    "C2spTlogReaderOptions",
    "C2spTlogSource",
    "C2spTlogTransport",
    "C2spTlogVerificationError",
    "C2spTlogVerificationOptions",
    "C2spTlogTrustProfile",
    "Checkpoint",
    "CheckpointPolicyResult",
    "CheckpointStore",
    "C2spBoundedResourceFetcher",
    "C2spProvenEntry",
    "C2spResourceFetchGuarantees",
    "C2spScanLimits",
    "C2spStreamEvidence",
    "C2spStreamBundleVerifierOptions",
    "IndexedEntry",
    "InMemoryCheckpointStore",
    "SQLiteCheckpointStore",
    "NoteSignature",
    "ParsedC2spTlogLr",
    "C2spChain",
    "C2spSignerRole",
    "C2spVerificationContext",
    "PreparedC2spTlogEvent",
    "SafeC2spResourceFetcher",
    "ScanStreamSource",
    "SignedNoteKey",
    "StreamEvidence",
    "StreamVerifierOptions",
    "TlogProofV1",
    "TrustedCheckpoint",
    "VerifiedLifecycleEvent",
    "VerifiedC2spStreamBundle",
    "assert_canonical_json_bytes",
    "c2sp_envelope_to_event",
    "canonical_bytes",
    "C2SP_SPEC_REVISIONS",
    "DNSID_C2SP_ENVELOPE_VERSION",
    "DnsidManagedVerificationOptions",
    "canonical_json",
    "canonical_log_prefix",
    "canonicalize_c2sp_event",
    "c2sp_event_id",
    "checkpoint_origin",
    "checkpoint_path",
    "create_c2sp_tlog_verification_registry",
    "create_dnsid_managed_verification_registry",
    "encode_entry_bundle",
    "entry_bytes",
    "enforce_checkpoint_policy",
    "entry_bundle_path",
    "event_to_c2sp_envelope",
    "generate_c2sp_tlog_stream_id",
    "inclusion_root",
    "leaf_hash",
    "merkle_root_from_entries",
    "MigrationVerificationResult",
    "node_hash",
    "normalized_origin_policy",
    "parse_c2sp_event_entry",
    "parse_c2sp_policy_file",
    "parse_c2sp_signatures",
    "parse_c2sp_tlog_lr",
    "parse_c2sp_tlog_trust_profile",
    "parse_checkpoint",
    "parse_entry_bundle",
    "parse_json_no_duplicate_members",
    "parse_note_signature",
    "parse_signed_note_verifier_key",
    "parse_tlog_proof_v1",
    "parse_prepared_event",
    "prepare_event",
    "required_signer_roles",
    "sign_prepared_event",
    "register_c2sp_tlog",
    "required_c2sp_signature_names",
    "signed_c2sp_entry_bytes",
    "signed_c2sp_event_bytes",
    "state_hash",
    "tile_path",
    "verified_cosignature_timestamp",
    "verify_c2sp_tlog_proof",
    "verify_checkpoint_signature",
    "verify_inclusion",
    "verify_consistency",
    "verify_lifecycle",
    "verify_logged_event_signature",
    "verify_note_signature",
    "verify_stream_lifecycle",
    "verify_c2sp_stream_bundle",
    "write_prepared_event",
]
