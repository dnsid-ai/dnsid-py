"""Tests for the c2sp-tlog verification convenience factory."""

from __future__ import annotations

import base64
import datetime
import hashlib
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dnsid import JWKS, DnsIdTxtRecord, IdentityManager, IdentityManagerDependencies
from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog import (
    C2spResourceFetchGuarantees,
    C2spScanLimits,
    C2spTlogReader,
    C2spTlogTransportError,
    C2spTlogVerificationError,
    C2spTlogVerificationOptions,
    InMemoryCheckpointStore,
    SafeC2spResourceFetcher,
    ScanStreamSource,
    SignedNoteKey,
    canonical_json,
    create_c2sp_tlog_verification_registry,
    encode_entry_bundle,
    merkle_root_from_entries,
    prepare_event,
)
from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.models import AgentStatus, IssuanceEvent, TLSCertificate, TransportConfig, TXTRecord
from tests.conftest import MockDNSResolver

_LR = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"


def _policy_document() -> bytes:
    key = base64.b64encode(b"\x01" + bytes(range(32))).decode("ascii")
    return f"log log.example+00000000+{key}\nquorum none\n".encode()


def _bundle_key(
    name: str = "bundle.example", key_bytes: bytes = bytes(reversed(range(32)))
) -> SignedNoteKey:
    signature_type = b"\x01"
    key_id = hashlib.sha256(
        name.encode() + b"\n" + signature_type + key_bytes
    ).digest()[:4]
    return SignedNoteKey(
        name=name,
        key_bytes=key_bytes,
        key_id=key_id,
        signature_type=signature_type,
    )


class _Fetcher:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.calls: list[tuple[str, int]] = []

    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        self.calls.append((url, max_bytes))
        return self.response

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        return C2spResourceFetchGuarantees(True, True, True, True, True)


def test_factory_from_document_configures_exact_safe_defaults() -> None:
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(policy_document=_policy_document())
    )
    reader = registry.new_reader(_LR)

    assert isinstance(reader, C2spTlogReader)
    assert isinstance(reader._source, ScanStreamSource)
    assert isinstance(reader._options.checkpoint_store, InMemoryCheckpointStore)
    assert reader._source._entries_per_bundle == 256
    assert reader._source._max_entry_bundle_bytes == 16_777_472
    assert reader._options.checkpoint_freshness_ms is None
    assert reader._options.max_clock_skew_ms == 0


def test_factory_configures_direct_bundle_verifier_keys() -> None:
    document = _policy_document()
    bundle_key = _bundle_key()
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_document=document,
            bundle_verifier_keys=[bundle_key],
            max_bundle_lifetime_ms=600_000,
            require_stream_bundle=True,
        )
    )
    reader = registry.new_reader(_LR)

    assert isinstance(reader._source, _FetchedStreamBundleSource)
    assert isinstance(reader._source._fallback, ScanStreamSource)
    assert reader._source._require_bundle is True
    assert reader._options.bundle_policy_document == document
    assert reader._options.bundle_keys == [bundle_key]
    assert reader._options.max_bundle_lifetime_ms == 600_000


def test_factory_rejects_invalid_direct_bundle_verifier_keys() -> None:
    duplicate = _bundle_key()
    invalid_key_sets = [
        [_bundle_key(key_bytes=bytes(range(32)))],
        [duplicate, duplicate],
        [
            SignedNoteKey(
                name="bundle.example",
                key_bytes=b"short",
                key_id=b"1234",
                signature_type=b"\x01",
            )
        ],
    ]
    for keys in invalid_key_sets:
        with pytest.raises(ArgumentError, match="bundle_verifier_keys"):
            create_c2sp_tlog_verification_registry(
                C2spTlogVerificationOptions(
                    policy_document=_policy_document(),
                    bundle_verifier_keys=keys,
                    max_bundle_lifetime_ms=600_000,
                )
            )


def test_factory_fetches_policy_with_same_resource_fetcher() -> None:
    fetcher = _Fetcher(_policy_document())
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_url="https://policy.example/dnsid-policy",
            resource_fetcher=fetcher,
        )
    )
    reader = registry.new_reader(_LR)

    assert fetcher.calls == [("https://policy.example/dnsid-policy", 1_048_576)]
    assert isinstance(reader, C2spTlogReader)
    assert reader._options.transport is fetcher


def test_factory_applies_limits_freshness_skew_and_shared_store() -> None:
    limits = C2spScanLimits(
        max_tree_size=12,
        max_checkpoint_bytes=100,
        max_entry_bundle_bytes=200,
        max_total_entry_bytes=300,
    )
    store = InMemoryCheckpointStore()
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_document=_policy_document(),
            resource_fetcher=_Fetcher(b"unused"),
            scan_limits=limits,
            trusted_checkpoint_store=store,
            checkpoint_freshness_ms=60_000,
            max_clock_skew_ms=2_000,
        )
    )

    first = registry.new_reader(_LR)
    second = registry.new_reader(_LR.replace("instance_A", "instance_B"))

    assert first._options.checkpoint_store is store
    assert second._options.checkpoint_store is store
    assert first._options.checkpoint_freshness_ms == 60_000
    assert first._options.max_clock_skew_ms == 2_000
    assert first._source._entries_per_bundle == 256
    assert first._source._max_tree_size == 12
    assert first._source._max_checkpoint_bytes == 100
    assert first._source._max_entry_bundle_bytes == 200
    assert first._source._max_total_entry_bytes == 300


def test_omitted_freshness_keeps_non_revocation_fail_closed() -> None:
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(policy_document=_policy_document())
    )
    reader = registry.new_reader(_LR)

    with pytest.raises(VerificationError, match="requires checkpoint_freshness_ms") as exc:
        reader._assert_fresh(datetime.datetime.now(datetime.UTC))
    assert exc.value.transient is False


@pytest.mark.parametrize(
    "options",
    [
        C2spTlogVerificationOptions(),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(),
            policy_url="https://policy.example/dnsid-policy",
        ),
        C2spTlogVerificationOptions(policy_url="http://policy.example/policy"),
        C2spTlogVerificationOptions(policy_url="https://user@policy.example/policy"),
        C2spTlogVerificationOptions(policy_url="https://policy.example/policy#x"),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_policy_bytes=0
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_policy_bytes=True
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_policy_bytes=1.5  # type: ignore[arg-type]
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), checkpoint_freshness_ms=0
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_clock_skew_ms=-1
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_clock_skew_ms=False
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_bundle_lifetime_ms=0
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(),
            bundle_verifier_keys=[_bundle_key()],
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_stream_bundle_bytes=True
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), max_stream_bundle_events=-1
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(), require_stream_bundle=True
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(),
            require_stream_bundle=1,  # type: ignore[arg-type]
        ),
        C2spTlogVerificationOptions(
            policy_document=_policy_document(),
            resource_fetcher=_Fetcher(b"unused"),
            transport_config=TransportConfig(dns_server="127.0.0.1:7753"),
        ),
    ],
)
def test_factory_rejects_invalid_configuration(
    options: C2spTlogVerificationOptions,
) -> None:
    with pytest.raises(ArgumentError):
        create_c2sp_tlog_verification_registry(options)


@pytest.mark.parametrize("field", list(C2spResourceFetchGuarantees.__dataclass_fields__))
def test_factory_eagerly_rejects_missing_fetcher_capability(field: str) -> None:
    class InsufficientFetcher(_Fetcher):
        def security_guarantees(self) -> C2spResourceFetchGuarantees:
            values = dict.fromkeys(
                C2spResourceFetchGuarantees.__dataclass_fields__, True
            )
            values[field] = False
            return C2spResourceFetchGuarantees(**values)

    with pytest.raises(ArgumentError, match="lacks"):
        create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(
                policy_document=_policy_document(),
                resource_fetcher=InsufficientFetcher(b"unused"),
            )
        )


def test_transport_config_reaches_built_in_fetcher() -> None:
    seen: list[TransportConfig | None] = []

    class Fetcher(SafeC2spResourceFetcher):
        def __init__(self, **kwargs: object) -> None:
            seen.append(kwargs.get("transport_config"))  # type: ignore[arg-type]
            super().__init__(**kwargs)  # type: ignore[arg-type]

    transport = TransportConfig(dns_server="127.0.0.1:7753")
    with patch("dnsid.c2sp_tlog.verification_registry.SafeC2spResourceFetcher", Fetcher):
        create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(
                policy_document=_policy_document(), transport_config=transport
            )
        )
    assert seen == [transport]


def test_policy_url_requires_bounded_custom_fetcher() -> None:
    with pytest.raises(ArgumentError, match="fetch_bounded"):
        create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(
                policy_url="https://policy.example/dnsid-policy",
                resource_fetcher=object(),  # type: ignore[arg-type]
            )
        )


def test_policy_response_accepts_exact_bound_and_rejects_one_more() -> None:
    exact = _policy_document()
    create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_url="https://policy.example/dnsid-policy",
            resource_fetcher=_Fetcher(exact),
            max_policy_bytes=len(exact),
        )
    )
    with pytest.raises(C2spTlogTransportError, match="byte maximum"):
        create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(
                policy_url="https://policy.example/dnsid-policy",
                resource_fetcher=_Fetcher(exact + b"x"),
                max_policy_bytes=len(exact),
            )
        )


def test_scan_limits_require_strict_positive_runtime_integers() -> None:
    for kwargs in (
        {"max_tree_size": 0},
        {"max_checkpoint_bytes": True},
        {"max_entry_bundle_bytes": 1.5},
        {"max_total_entry_bytes": -1},
    ):
        with pytest.raises(C2spTlogVerificationError, match="positive integer"):
            C2spScanLimits(**kwargs)  # type: ignore[arg-type]


def test_factory_registry_verifies_identity_from_standard_c2sp_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise factory -> IdentityManager using checkpoint and entry-bundle bytes."""
    domain = "agent.example.com"
    lr = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)

    def key_pair(kid: str):
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return private, jwk_from_dict(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "kid": kid,
                "use": "sig",
                "x": b64url_encode(public),
            }
        )

    entity_private, entity_key = key_pair("entity-1")
    operational_private, operational_key = key_pair("operational-1")
    event = IssuanceEvent(
        domain=domain,
        governance_id="example.com",
        timestamp=now - datetime.timedelta(minutes=2),
        entity_key=entity_key,
        operational_key=operational_key,
    )
    prepared = prepare_event(event, lr)
    envelope = dict(prepared.envelope)
    envelope["sigs"] = {
        "ae": {
            "kid": entity_key.kid,
            "sig": b64url_encode(entity_private.sign(prepared.signed_bytes)),
        },
        "op": {
            "kid": operational_key.kid,
            "sig": b64url_encode(operational_private.sign(prepared.signed_bytes)),
        },
    }
    entry = canonical_json(envelope).encode()

    log_private = ed25519.Ed25519PrivateKey.generate()
    witness_private = ed25519.Ed25519PrivateKey.generate()
    root = merkle_root_from_entries([entry])
    signed_text = f"log.example\n1\n{base64.b64encode(root).decode()}\n"
    witness_timestamp = int((now - datetime.timedelta(minutes=1)).timestamp())
    checkpoint = (
        signed_text
        + "\n"
        + _checkpoint_signature("log.example", signed_text, log_private)
        + "\n"
        + _checkpoint_cosignature(
            "log.example-witness",
            signed_text,
            witness_private,
            witness_timestamp,
        )
        + "\n"
    ).encode()
    policy = (
        "log "
        + _policy_key("log.example", b"\x01", log_private)
        + "\nwitness required "
        + _policy_key("log.example-witness", b"\x04", witness_private)
        + "\nquorum required\n"
    ).encode()

    class ResourceFetcher(_Fetcher):
        def __init__(self) -> None:
            super().__init__(b"")
            self.resources = {
                "https://log.example/checkpoint": checkpoint,
                "https://log.example/tile/entries/000.p/1": encode_entry_bundle([entry]),
            }

        def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
            self.calls.append((url, max_bytes))
            return self.resources[url]

    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_document=policy,
            resource_fetcher=ResourceFetcher(),
            checkpoint_freshness_ms=5 * 60 * 1000,
            max_clock_skew_ms=1_000,
        )
    )

    record = DnsIdTxtRecord(
        v="dnsid-draft-01",
        gi="example.com",
        ek="https://example.com/entity.jwks",
        ku=f"https://{domain}/agent.jwks",
        lr=lr,
        su=f"https://{domain}/status",
        identity_fqdn=domain,
    )
    record.sg = b64url_encode(entity_private.sign(record.canonical().encode("ascii")))
    resolver = MockDNSResolver(
        {f"_dnsid.{domain}": [TXTRecord(strings=[record.serialize().encode()], ttl=60)]}
    )
    tls = TLSCertificate(
        not_after=now + datetime.timedelta(days=1),
        san_dns_names=[domain, "example.com"],
    )

    def fetch_jwks(url: str, *args: object, **kwargs: object):
        return (JWKS([operational_key]), tls) if url == record.ku else (JWKS([entity_key]), tls)

    monkeypatch.setattr("dnsid.manager._fetch_jwks", fetch_jwks)
    monkeypatch.setattr(
        "dnsid.manager._fetch_strict_json_status",
        lambda *args, **kwargs: AgentStatus("ACTIVE", now),
    )
    manager = IdentityManager.for_verification(
        IdentityManagerDependencies(dns_resolver=resolver, log_registry=registry)
    )

    verified = manager.verify_domain(domain)
    assert verified.domain == domain
    assert verified.jwks.keys == [operational_key]
    assert verified.record_signing_jwks.keys == [entity_key]


def _policy_key(
    name: str, signature_type: bytes, private: ed25519.Ed25519PrivateKey
) -> str:
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"{name}+00000000+{base64.b64encode(signature_type + public).decode()}"


def _checkpoint_signature(
    name: str, signed_text: str, private: ed25519.Ed25519PrivateKey
) -> str:
    signature = private.sign(signed_text.encode())
    return f"— {name} {base64.b64encode(bytes(4) + signature).decode()}"


def _checkpoint_cosignature(
    name: str,
    signed_text: str,
    private: ed25519.Ed25519PrivateKey,
    timestamp: int,
) -> str:
    message = f"cosignature/v1\ntime {timestamp}\n{signed_text}".encode()
    signature = private.sign(message)
    body = bytes(4) + timestamp.to_bytes(8, "big") + signature
    return f"— {name} {base64.b64encode(body).decode()}"
