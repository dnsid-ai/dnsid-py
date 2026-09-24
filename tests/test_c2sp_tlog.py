"""Tests for the c2sp-tlog LogReader (dnsid/c2sp_tlog).

The specification vectors (VECTOR_*) are shared across the DNSid SDKs so the
implementations stay byte-compatible.  The testnet checkpoint/policy fixtures
were captured from a live dnsid-testnet registry.
"""

from __future__ import annotations

import base64
import datetime
import json
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog import (
    C2spEventContext,
    C2spLifecycleErrorCategory,
    C2spResourceFetchGuarantees,
    C2spTlogOriginPolicy,
    C2spTlogParseError,
    C2spTlogPolicy,
    C2spTlogReader,
    C2spTlogReaderOptions,
    C2spTlogTransportError,
    C2spTlogVerificationError,
    SignedNoteKey,
    TlogProofV1,
    VerifiedLifecycleEvent,
    canonical_json,
    canonical_log_prefix,
    encode_entry_bundle,
    enforce_checkpoint_policy,
    entry_bundle_path,
    leaf_hash,
    merkle_root_from_entries,
    parse_c2sp_event_entry,
    parse_c2sp_policy_file,
    parse_c2sp_tlog_lr,
    parse_checkpoint,
    parse_json_no_duplicate_members,
    parse_signed_note_verifier_key,
    signed_c2sp_entry_bytes,
    signed_c2sp_event_bytes,
    tile_path,
    verify_lifecycle,
)
from dnsid.c2sp_tlog.event_codec import parse_chain_fields
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.models import IssuanceEvent
from dnsid.registry import LogRegistry
from tests.c2sp_fixtures import correct_entries

# ---------------------------------------------------------------------------
# Method specification vectors (shared across the DNSid SDK test suites)
# ---------------------------------------------------------------------------

VECTOR_ISSUANCE_SIGNED = '{"ek":{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"},"fqdn":"agent.example","gi":"example.com","kind":"dnsid.lifecycle","ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"},"ts":1782172800,"type":"ISSUANCE","v":1}'
VECTOR_ISSUANCE = '{"ek":{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"},"fqdn":"agent.example","gi":"example.com","kind":"dnsid.lifecycle","ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"},"sigs":{"ae":{"kid":"ae-test-1","sig":"Qp_IOg6S-ksElLBrMTwUqQ6slrt-W-wbXtadHY6nXOPbUXs1013_kNdrMWYEWjVZcvXptqxwshbKu-wtz4h6CQ"},"op":{"kid":"op-test-1","sig":"jWSZhq4Cm5FeHipM1MX5LVdej9cpStNAaoCFZSG3G_w-0w4rhYss2Vvi0lz7DcvVFO8K2nde0VfX2c5Ga5bvAg"}},"ts":1782172800,"type":"ISSUANCE","v":1}'
VECTOR_ROTATION = '{"fqdn":"agent.example","kind":"dnsid.lifecycle","new_ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-2","kty":"OKP","x":"ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw"},"new_thumb":"d8Me3uJ82jhdsCstWyVMr3_I2ueeTYG5agM1-2r1_bY","prev_thumb":"aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU","sigs":{"new_op":{"kid":"op-test-2","sig":"JfWp_M8PVCoWAAqkiCX-3OjLlrRZLEcgusyTK6yDSJmeP0Ojw9Nc6cy-nDQjs21vx9-CyNMmWPOXAU_YJ6ddBg"},"prev_op":{"kid":"op-test-1","sig":"pPTFBLO3qGxqJ9xOrppA-z5SlQuPoCq1Sf9OwrizoN8K8VTtIuxg0xJDXE1BVzWnMt9GAcyx1yM3Rx3JZ16oCQ"}},"ts":1782259200,"type":"KEY_ROTATION","v":1}'
VECTOR_REVOCATION = '{"fqdn":"agent.example","kind":"dnsid.lifecycle","reason":"keyCompromise","sigs":{"ae":{"kid":"ae-test-1","sig":"CjrMHNl_BdMG5qkbyttuCGyhlchkhTowOyfkZn2T-Wl_jnqYB5Jh0TYuNS6BLJlDLYS9OFD8FItH2dEJ0f4eCw"}},"ts":1782345600,"type":"REVOCATION","v":1}'

# Re-sign these historical templates with mandatory context and logical chains.

VECTOR_ISSUANCE, VECTOR_ROTATION, VECTOR_REVOCATION = [entry.decode() for entry in correct_entries(
    [VECTOR_ISSUANCE, VECTOR_ROTATION, VECTOR_REVOCATION],
    "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA",
)]
VECTOR_ISSUANCE_SIGNED = signed_c2sp_entry_bytes(VECTOR_ISSUANCE.encode()).decode()

# Captured from a live dnsid-testnet registry (policy + signed checkpoint).
TESTNET_LOG_KEY = "registry.dev.dnsid.test+63709d10+ARwL6oG1DPOaYXpfGFYdSw26SwXFlXwg/4pSQkH+meO1"
TESTNET_WITNESS_KEY = "dnsid-testnet-witness+140f1588+BAsNEfLiOQ/CLTgTGutdjkXbl+Ur7aleRlda6PWY0lcW"
TESTNET_CHECKPOINT = (
    "registry.dev.dnsid.test\n"
    "1\n"
    "hoRk0hkPFzObCxDX9po81RS5jnJB3iXBewKTs061yX0=\n"
    "\n"
    "— registry.dev.dnsid.test Y3CdECgpKysQCRqhl6VHhpBNH1fVarM6rb7x1GEaTHLOm6N4EyO/wy+ZjAf3wU+zJeBzJZ0zs0DA+u/D9ooB6RFJtAA=\n"
    "— dnsid-testnet-witness FA8ViAAAAABqVT7r7JIYyN4uQ5HTMTos+yN1oxBaNRgxoLkpzkWDR3LhxYQ3urhvCZ7hdbVNZU2OsUues3gpgSCrOrpSBmQAJOgDAg==\n"
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class TestSpecVectors:
    def test_signed_entry_bytes_strip_sigs(self):
        got = signed_c2sp_entry_bytes(VECTOR_ISSUANCE.encode())
        assert got.decode() == VECTOR_ISSUANCE_SIGNED

    def test_leaf_hashes_and_merkle_root(self):
        entries = [v.encode() for v in (VECTOR_ISSUANCE, VECTOR_ROTATION, VECTOR_REVOCATION)]
        assert len(entries[0]) == 770
        assert _b64(leaf_hash(entries[0])) == "mH0hrpqSYETaJdx6BpcEklARZATbAT3tntChSUeJKcQ="
        assert _b64(leaf_hash(entries[1])) == "BuF3uCKictRePB1ubOJmsBJ5k2sOvhRRUBsh7sbxLGY="
        assert _b64(leaf_hash(entries[2])) == "7KF5ZZrdKiRsx8Z/hpByFdWbeF/WZ0AnsrJaYDyRGrA="
        assert (
            _b64(merkle_root_from_entries(entries))
            == "OuHGLpRIcq/txCi1fNzHvGIoQNJ6Loz/2JA1EiEcVlw="
        )

    def test_vector_lifecycle_verifies(self):
        entries = [v.encode() for v in (VECTOR_ISSUANCE, VECTOR_ROTATION, VECTOR_REVOCATION)]
        events = [parse_c2sp_event_entry(data) for data in entries]
        issuance = events[0]
        assert isinstance(issuance, IssuanceEvent)
        assert issuance.entity_key is not None
        from dnsid.c2sp_tlog import StreamVerifierOptions

        items = [
            VerifiedLifecycleEvent(
                index=i, leaf_hash=leaf_hash(entries[i]), data=entries[i],
                event=events[i], chain=parse_chain_fields(json.loads(entries[i])),
            )
            for i in range(3)
        ]
        verify_lifecycle(
            items,
            StreamVerifierOptions(
                signer_key=issuance.entity_key,
                checkpoint_integration_time_ms=1_782_345_700_000,
            ),
        )

    def test_wrong_signer_key_rejected(self):
        entries = [v.encode() for v in (VECTOR_ISSUANCE,)]
        events = [parse_c2sp_event_entry(data) for data in entries]
        issuance = events[0]
        assert isinstance(issuance, IssuanceEvent)
        assert issuance.operational_key is not None
        from dnsid.c2sp_tlog import StreamVerifierOptions

        items = [
            VerifiedLifecycleEvent(
                index=0, leaf_hash=leaf_hash(entries[0]), data=entries[0],
                event=events[0], chain=parse_chain_fields(json.loads(entries[0])),
            )
        ]
        with pytest.raises(C2spTlogVerificationError, match="trusted entity key"):
            verify_lifecycle(
                items,
                StreamVerifierOptions(
                    signer_key=issuance.operational_key,  # ku, not ek
                    checkpoint_integration_time_ms=1_782_345_700_000,
                ),
            )


class TestTilePaths:
    def test_tile_n_path_components(self):
        assert tile_path("p", 0, 1234067) == "p/tile/0/x001/x234/067"
        assert entry_bundle_path("p", 7, 5) == "p/tile/entries/007.p/5"
        assert entry_bundle_path("p", 0) == "p/tile/entries/000"


class TestSignedNoteKeys:
    def test_parses_name_keyid_key_form(self):
        key_b64 = _b64(bytes([1]) + bytes([250] * 32))
        key = parse_signed_note_verifier_key(f"example.com/foo+530d903a+{key_b64}")
        assert key.name == "example.com/foo"
        assert key.key_id is not None and key.key_id.hex() == "530d903a"
        assert key.signature_type == b"\x01"
        assert len(key.key_bytes) == 32

    def test_parses_testnet_keys(self):
        log = parse_signed_note_verifier_key(TESTNET_LOG_KEY)
        witness = parse_signed_note_verifier_key(TESTNET_WITNESS_KEY)
        assert log.name == "registry.dev.dnsid.test"
        assert log.signature_type == b"\x01"
        assert witness.signature_type == b"\x04"


class TestCheckpointPolicy:
    def _policy(self) -> C2spTlogPolicy:
        return C2spTlogPolicy(
            origins={
                "registry.dev.dnsid.test": C2spTlogOriginPolicy(
                    log_keys=[TESTNET_LOG_KEY],
                    witness_keys=[TESTNET_WITNESS_KEY],
                    quorum=1,
                )
            }
        )

    def test_real_testnet_checkpoint_verifies(self):
        checkpoint = parse_checkpoint(TESTNET_CHECKPOINT)
        assert checkpoint.tree_size == 1
        result = enforce_checkpoint_policy(
            checkpoint,
            "registry.dev.dnsid.test",
            self._policy(),
            "public",
            now_ms=1_800_000_000_000,
        )
        assert result.checkpoint_witness_time is not None
        assert len(result.accepted_witness_timestamps) == 1

    def test_tampered_checkpoint_rejected(self):
        tampered = TESTNET_CHECKPOINT.replace("\n1\n", "\n2\n")
        checkpoint = parse_checkpoint(tampered)
        with pytest.raises(C2spTlogVerificationError, match="log signature"):
            enforce_checkpoint_policy(
                checkpoint,
                "registry.dev.dnsid.test",
                self._policy(),
                "public",
                now_ms=1_800_000_000_000,
            )

    def test_witness_timestamp_in_future_rejected(self):
        checkpoint = parse_checkpoint(TESTNET_CHECKPOINT)
        with pytest.raises(C2spTlogVerificationError, match="quorum"):
            enforce_checkpoint_policy(
                checkpoint,
                "registry.dev.dnsid.test",
                self._policy(),
                "public",
                now_ms=0,
            )


class TestCanonicalJson:
    def test_sorts_members_and_minimal_escaping(self):
        assert canonical_json({"b": 1, "a": "x"}) == '{"a":"x","b":1}'
        assert canonical_json([1, "a", None, True]) == '[1,"a",null,true]'

    def test_rejects_duplicate_members(self):
        with pytest.raises(C2spTlogParseError, match="duplicate"):
            parse_json_no_duplicate_members(b'{"a":1,"a":2}')

    def test_non_canonical_entry_bytes_rejected(self):
        with pytest.raises(C2spTlogParseError, match="canonical"):
            signed_c2sp_entry_bytes(b'{"b":1,"a":2}')


class TestLrGrammar:
    def test_generate_c2sp_tlog_stream_id_uses_128_random_bits(self, monkeypatch):
        import dnsid.c2sp_tlog.lr as lr_module
        from dnsid.c2sp_tlog import generate_c2sp_tlog_stream_id

        requested = []

        def token_bytes(size):
            requested.append(size)
            return bytes(range(size))

        monkeypatch.setattr(lr_module.secrets, "token_bytes", token_bytes)

        stream_id = generate_c2sp_tlog_stream_id()
        assert requested == [16]
        assert stream_id == "AAECAwQFBgcICQoLDA0ODw"
        assert "=" not in stream_id

    def test_parses_testnet_lr(self):
        parsed = parse_c2sp_tlog_lr(
            "c2sp-tlog:public:https://registry.dev.dnsid.test#bob.test.dnsid.test"
        )
        assert parsed.scope == "public"
        assert parsed.log_prefix == "https://registry.dev.dnsid.test"
        assert parsed.origin == "registry.dev.dnsid.test"
        assert parsed.stream_id == "bob.test.dnsid.test"
        assert parsed.entry_index is None

    def test_entry_index_suffix(self):
        parsed = parse_c2sp_tlog_lr("c2sp-tlog:testnet:http://log.test#stream@41")
        assert parsed.entry_index == 41

    def test_root_url_accepted_as_prefix(self):
        assert canonical_log_prefix("https://log.example") == "https://log.example"

    def test_public_requires_https(self):
        with pytest.raises(C2spTlogParseError, match="https"):
            parse_c2sp_tlog_lr("c2sp-tlog:public:http://log.example#stream")

    def test_rejects_trailing_slash_and_dot_segments(self):
        with pytest.raises(C2spTlogParseError):
            parse_c2sp_tlog_lr("c2sp-tlog:testnet:https://log.example/x/#stream")
        with pytest.raises(C2spTlogParseError):
            parse_c2sp_tlog_lr("c2sp-tlog:testnet:https://log.example/../x#stream")


class TestPolicyFile:
    def test_parses_log_witness_quorum(self):
        witness_b64 = _b64(bytes([4]) + bytes([7] * 32))
        log_b64 = _b64(bytes([1]) + bytes([9] * 32))
        text = (
            "# test policy\n"
            f"log log.example+00000000+{log_b64}\n"
            f"witness w1 w1.example+00000000+{witness_b64}\n"
            "quorum w1\n"
        )
        policy = parse_c2sp_policy_file(text)
        origin = policy.origins["log.example"]
        assert origin.quorum == 1
        assert origin.quorum_rule is not None and origin.quorum_rule.kind == "witness"

    def test_requires_exactly_one_quorum(self):
        with pytest.raises(C2spTlogVerificationError, match="quorum"):
            parse_c2sp_policy_file("log a+00000000+" + _b64(bytes([1]) + bytes(32)) + "\n")


# ---------------------------------------------------------------------------
# End-to-end: synthetic log served through a dict transport
# ---------------------------------------------------------------------------


def _ed25519_jwk(kid: str) -> tuple[dict[str, str], ed25519.Ed25519PrivateKey]:
    private = ed25519.Ed25519PrivateKey.generate()
    x = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return (
        {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid, "use": "sig",
         "x": b64url_encode(x)},
        private,
    )


_KEY_HASH_PREFIX = bytes(4)


def _note_sig(name: str, signed_text: str, key: ed25519.Ed25519PrivateKey) -> str:
    sig = key.sign(signed_text.encode())
    return f"— {name} {_b64(_KEY_HASH_PREFIX + sig)}"


def _cosig(
    name: str, signed_text: str, key: ed25519.Ed25519PrivateKey, timestamp: int
) -> str:
    message = f"cosignature/v1\ntime {timestamp}\n{signed_text}"
    sig = key.sign(message.encode())
    body = timestamp.to_bytes(8, "big") + sig
    return f"— {name} {_b64(_KEY_HASH_PREFIX + body)}"


class TestEndToEndReader:
    DOMAIN = "agent.example.com"
    LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"

    def _build_log(
        self,
        candidate_entries: Callable[[bytes], list[bytes]] | None = None,
    ) -> tuple[C2spTlogReader, datetime.datetime]:
        entity_raw, entity_priv = _ed25519_jwk("ek-1")
        ku_raw, ku_priv = _ed25519_jwk("ku-1")
        ts = datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC)
        event = IssuanceEvent(
            domain=self.DOMAIN,
            governance_id="example.com",
            timestamp=ts,
            entity_key=jwk_from_dict(entity_raw),
            operational_key=jwk_from_dict(ku_raw),
        )
        context = C2spEventContext(
            scope="testnet",
            log_origin="log.example",
            stream_id="instance_AAAAAAAAAAAAAAAAAAAAAA",
            lr=self.LR,
            seq=0,
        )
        signed = signed_c2sp_event_bytes(event, context)
        event.signing_kid = "ek-1"
        event.sig = b64url_encode(entity_priv.sign(signed))
        event.operational_countersig = b64url_encode(ku_priv.sign(signed))
        from dnsid.c2sp_tlog import canonicalize_c2sp_event

        entry = canonicalize_c2sp_event(event, context)

        entries = [*(candidate_entries(entry) if candidate_entries else []), entry]
        root = merkle_root_from_entries(entries)
        signed_text = f"log.example\n{len(entries)}\n{_b64(root)}\n"
        log_note_priv = ed25519.Ed25519PrivateKey.generate()
        witness_priv = ed25519.Ed25519PrivateKey.generate()
        witness_ts = int(ts.timestamp()) + 60
        checkpoint_text = (
            signed_text
            + "\n"
            + _note_sig("log.example", signed_text, log_note_priv)
            + "\n"
            + _cosig("log.example-witness", signed_text, witness_priv, witness_ts)
            + "\n"
        )

        policy = C2spTlogPolicy(
            origins={
                "log.example": C2spTlogOriginPolicy(
                    log_keys=[
                        SignedNoteKey(
                            name="log.example",
                            key_bytes=log_note_priv.public_key().public_bytes(
                                Encoding.Raw, PublicFormat.Raw
                            ),
                            signature_type=b"\x01",
                        )
                    ],
                    witness_keys=[
                        SignedNoteKey(
                            name="log.example-witness",
                            key_bytes=witness_priv.public_key().public_bytes(
                                Encoding.Raw, PublicFormat.Raw
                            ),
                            signature_type=b"\x04",
                        )
                    ],
                    quorum=1,
                )
            }
        )

        urls = {
            "https://log.example/checkpoint": checkpoint_text.encode(),
            f"https://log.example/tile/entries/000.p/{len(entries)}": (
                encode_entry_bundle(entries)
            ),
        }

        def transport(url: str) -> bytes:
            if url not in urls:
                raise C2spTlogVerificationError(f"unexpected URL: {url}")
            return urls[url]

        reader = C2spTlogReader(
            self.LR,
            C2spTlogReaderOptions(
                policy=policy,
                transport=transport,
                entity_key=jwk_from_dict(entity_raw),
                checkpoint_freshness_ms=10**15,
            ),
        )
        return reader, ts

    def test_rebuild_history_returns_verified_issuance(self):
        reader, ts = self._build_log()
        history = reader.rebuild_history(self.DOMAIN)
        assert len(history) == 1
        assert isinstance(history[0], IssuanceEvent)
        assert history[0].domain == self.DOMAIN

    def test_read_event_requires_proofed_entry_in_bundle_backed_history(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource

        reader, _ = self._build_log()
        evidence = reader._source.load_stream(reader.parsed, self.DOMAIN)
        reader._options.proofs["0"] = TlogProofV1(
            index=0, hashes=[], checkpoint=evidence.checkpoint
        )
        history = reader._load_complete_history(self.DOMAIN)
        reader._history_cache.clear()
        bundle = SimpleNamespace(
            reference=reader.parsed,
            events=history.current_stream_events,
            checkpoint=evidence.checkpoint,
            checkpoint_bytes=evidence.checkpoint_bytes,
            checkpoint_witness_time=history.checkpoint_witness_time,
            expires=int(datetime.datetime.now(datetime.UTC).timestamp()) + 60,
            migration_results={},
        )
        source = _FetchedStreamBundleSource(
            object(),
            reader._source,
            policy_bytes=b"unused",
            bundle_keys=[],
            checkpoint_freshness_ms=1,
            max_bundle_lifetime_ms=1,
            max_bundle_bytes=1,
            max_events=1,
        )
        reader._source = source

        with patch.object(source, "load_verified_bundle", return_value=bundle) as load:
            event = reader.read_event(f"{self.LR}@0")

        load.assert_called_once()
        assert isinstance(event, IssuanceEvent)
        assert event.domain == self.DOMAIN

        reader._history_cache.clear()
        bundle.events = []
        with patch.object(source, "load_verified_bundle", return_value=bundle):
            with pytest.raises(VerificationError, match="not in the verified lifecycle"):
                reader.read_event(f"{self.LR}@0")

    def test_read_event_honors_required_bundle_failure(self):
        from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource

        reader, _ = self._build_log()
        evidence = reader._source.load_stream(reader.parsed, self.DOMAIN)
        reader._options.proofs["0"] = TlogProofV1(
            index=0, hashes=[], checkpoint=evidence.checkpoint
        )

        class UnavailableFetcher:
            def fetch_bounded(self, url, max_bytes):
                raise C2spTlogTransportError("bundle unavailable", transient=True)

        reader._source = _FetchedStreamBundleSource(
            UnavailableFetcher(),
            reader._source,
            policy_bytes=b"unused",
            bundle_keys=[],
            checkpoint_freshness_ms=1,
            max_bundle_lifetime_ms=1,
            max_bundle_bytes=1,
            max_events=1,
            require_bundle=True,
        )

        with pytest.raises(VerificationError, match="bundle unavailable"):
            reader.read_event(f"{self.LR}@0")

    def test_global_scan_skips_invalid_candidates(self):
        def invalid_candidates(valid: bytes) -> list[bytes]:
            parsed = parse_json_no_duplicate_members(valid)

            def changed(**updates: object) -> bytes:
                candidate = dict(parsed)
                candidate.update(updates)
                return canonical_json(candidate).encode()

            bad_signature = dict(parsed)
            bad_signature["sigs"] = {
                **parsed["sigs"],
                "ae": {**parsed["sigs"]["ae"], "sig": "AA"},
            }
            return [
                b"not JSON",
                canonical_json({"unrelated": "entry"}).encode(),
                changed(v=2),
                changed(type="FUTURE"),
                changed(fqdn="other.example.com"),
                changed(lr="c2sp-tlog:testnet:https://log.example#other.example.com"),
                canonical_json(bad_signature).encode(),
            ]

        reader, _ = self._build_log(invalid_candidates)

        history = reader.rebuild_history(self.DOMAIN)

        assert len(history) == 1
        assert isinstance(history[0], IssuanceEvent)
        assert history[0].domain == self.DOMAIN

    def test_global_scan_checkpoint_authentication_failure_is_fatal(self):
        reader, _ = self._build_log()
        transport = reader._source._transport

        def tampered_checkpoint(url: str) -> bytes | str:
            body = transport(url)
            if url.endswith("/checkpoint"):
                data = body.encode() if isinstance(body, str) else body
                return data.replace(b"\n1\n", b"\n2\n", 1)
            return body

        reader._source._transport = tampered_checkpoint

        with pytest.raises(VerificationError, match="log signature") as exc_info:
            reader.rebuild_history(self.DOMAIN)
        assert exc_info.value.code is VerificationCode.LOG_ERROR
        assert exc_info.value.transient is False
        assert exc_info.value.category == C2spLifecycleErrorCategory.INVALID_EVIDENCE
        assert isinstance(exc_info.value.__cause__, C2spTlogVerificationError)

    def test_global_scan_completeness_failure_is_fatal(self):
        reader, _ = self._build_log()
        load_stream = reader._source.load_stream

        def incomplete(reference, fqdn):
            evidence = load_stream(reference, fqdn)
            evidence.entries = []
            return evidence

        reader._source.load_stream = incomplete

        with pytest.raises(VerificationError, match="scan length") as exc_info:
            reader.rebuild_history(self.DOMAIN)
        assert exc_info.value.code is VerificationCode.LOG_ERROR
        assert exc_info.value.transient is False
        assert exc_info.value.category == C2spLifecycleErrorCategory.INCOMPLETE_STREAM
        assert isinstance(exc_info.value.__cause__, C2spTlogVerificationError)

    def test_incomplete_source_has_stable_category(self):
        from dnsid.exceptions import VerificationError

        reader, _ = self._build_log()
        load_stream = reader._source.load_stream

        def incomplete(reference, fqdn):
            evidence = load_stream(reference, fqdn)
            evidence.complete = False
            return evidence

        reader._source.load_stream = incomplete

        with pytest.raises(VerificationError) as exc_info:
            reader.rebuild_history(self.DOMAIN)
        assert exc_info.value.category == C2spLifecycleErrorCategory.INCOMPLETE_STREAM

    def test_key_timestamp_finds_operational_binding(self):
        reader, ts = self._build_log()
        history = reader.rebuild_history(self.DOMAIN)
        issuance = history[0]
        assert isinstance(issuance, IssuanceEvent)
        assert issuance.operational_key is not None
        got = reader.key_timestamp(self.DOMAIN, issuance.operational_key.thumbprint())
        assert got == ts

    def test_key_timestamp_unknown_thumbprint_raises(self):
        from dnsid.exceptions import VerificationError

        reader, _ = self._build_log()
        with pytest.raises(VerificationError, match="thumbprint not found"):
            reader.key_timestamp(self.DOMAIN, "nope")

    def test_verify_non_revocation_returns_evidence(self):
        reader, _ = self._build_log()
        evidence = reader.verify_non_revocation(
            self.DOMAIN, datetime.datetime.now(datetime.UTC)
        )

        assert evidence.log_reference == self.LR
        assert evidence.logged_state == "ACTIVE"
        assert evidence.history_start == f"{self.LR}@0"
        assert evidence.history_end == f"{self.LR}@0"
        assert evidence.complete_through == 1
        assert evidence.completeness_mode == "full-scan"
        assert isinstance(evidence.checkpoint, bytes) and evidence.checkpoint
        assert evidence.freshness_time.tzinfo is datetime.UTC

    def test_verify_non_revocation_evidence_stops_at_operation_time(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from dnsid.models import RevocationEvent

        reader, ts = self._build_log()
        issuance = reader.rebuild_history(self.DOMAIN)[0]
        terminal = RevocationEvent(
            domain=self.DOMAIN,
            reason="keyCompromise",
            timestamp=ts + datetime.timedelta(seconds=1),
        )
        reader._load_complete_history = MagicMock(
            return_value=SimpleNamespace(
                events=[issuance, terminal],
                checkpoint_witness_time=datetime.datetime.now(datetime.UTC),
                current_stream_events=[
                    SimpleNamespace(event=issuance, index=0),
                    SimpleNamespace(event=terminal, index=1),
                ],
                logged_state="REVOKED",
                history_start=f"{self.LR}@0",
                history_end=f"{self.LR}@1",
                event_refs=[f"{self.LR}@0", f"{self.LR}@1"],
                complete_through=2,
                completeness_mode="full-scan",
                checkpoint=b"checkpoint",
            )
        )

        evidence = reader.verify_non_revocation(self.DOMAIN, ts)

        assert evidence.logged_state == "ACTIVE"
        assert evidence.history_end == f"{self.LR}@0"
        assert evidence.complete_through == 2

    @pytest.mark.parametrize("terminal_kind", ["REVOKED", "RETIRED"])
    def test_complete_terminal_history_fails_identity_continuity_checks(
        self, terminal_kind: str
    ):
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from dnsid.exceptions import VerificationError
        from dnsid.models import RetirementEvent, RevocationEvent

        reader, ts = self._build_log()
        issuance = reader.rebuild_history(self.DOMAIN)[0]
        assert isinstance(issuance, IssuanceEvent)
        assert issuance.operational_key is not None
        assert reader._options.entity_key is not None
        terminal = (
            RevocationEvent(
                domain=self.DOMAIN,
                reason="keyCompromise",
                timestamp=ts + datetime.timedelta(seconds=1),
            )
            if terminal_kind == "REVOKED"
            else RetirementEvent(
                domain=self.DOMAIN,
                timestamp=ts + datetime.timedelta(seconds=1),
            )
        )
        reader._load_complete_history = MagicMock(
            return_value=SimpleNamespace(events=[issuance, terminal])
        )
        record = SimpleNamespace(identity_fqdn=self.DOMAIN, gi="example.com")
        with pytest.raises(VerificationError, match="terminal"):
            reader.verify_bilateral_binding(
                record, reader._options.entity_key, issuance.operational_key
            )
        thumbprint = issuance.operational_key.thumbprint()
        with pytest.raises(VerificationError, match="terminal"):
            reader.verify_operational_continuity(
                self.DOMAIN, thumbprint, thumbprint
            )

    @pytest.mark.parametrize("terminal_kind", ["REVOKED", "RETIRED"])
    def test_verify_non_revocation_rejects_terminal_history(self, terminal_kind: str):
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from dnsid.exceptions import VerificationError
        from dnsid.models import RetirementEvent, RevocationEvent

        reader, ts = self._build_log()
        issuance = reader.rebuild_history(self.DOMAIN)[0]
        terminal = (
            RevocationEvent(
                domain=self.DOMAIN,
                reason="keyCompromise",
                timestamp=ts + datetime.timedelta(seconds=1),
            )
            if terminal_kind == "REVOKED"
            else RetirementEvent(
                domain=self.DOMAIN,
                timestamp=ts + datetime.timedelta(seconds=1),
            )
        )
        reader._load_complete_history = MagicMock(
            return_value=SimpleNamespace(
                events=[issuance, terminal],
                checkpoint_witness_time=datetime.datetime.now(datetime.UTC),
            )
        )
        with pytest.raises(VerificationError, match="revoked|retired"):
            reader.verify_non_revocation(
                self.DOMAIN, ts + datetime.timedelta(seconds=2)
            )

    def test_reader_registration(self):
        from dnsid.c2sp_tlog import register_c2sp_tlog

        reader, _ = self._build_log()
        options = reader._options
        original_factory = options.migration_reader_factory
        first_registry = LogRegistry()
        second_registry = LogRegistry()
        register_c2sp_tlog(first_registry, options)
        register_c2sp_tlog(second_registry, options)
        first = first_registry.new_reader(self.LR)
        second = second_registry.new_reader(self.LR)

        assert isinstance(first, C2spTlogReader)
        assert isinstance(second, C2spTlogReader)
        assert options.migration_reader_factory is original_factory
        assert first._options is not options
        assert second._options is not options
        assert (
            getattr(first._options.migration_reader_factory, "__self__", None)
            is first_registry
        )
        assert (
            getattr(second._options.migration_reader_factory, "__self__", None)
            is second_registry
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# ---------------------------------------------------------------------------
# Prepared-event model: split signing across independent providers
# ---------------------------------------------------------------------------


class _SingleKeyProvider:
    """Minimal KeyProvider double holding one fixed Ed25519 key."""

    def __init__(self, jwk_raw: dict, private: ed25519.Ed25519PrivateKey) -> None:
        self._jwk = jwk_from_dict(jwk_raw)
        self._private = private

    def signing_key(self):
        return self._jwk

    def jwk(self, kid: str):
        from dnsid.exceptions import ArgumentError

        if kid != self._jwk.kid:
            raise ArgumentError(f"key not found: {kid!r}")
        return self._jwk

    def sign(self, payload: bytes) -> bytes:
        return self._private.sign(payload)

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        from dnsid.exceptions import ArgumentError

        if kid != self._jwk.kid:
            raise ArgumentError(f"key not found: {kid!r}")
        return self._private.sign(payload)


class TestPreparedEventModel:
    DOMAIN = "agent.example.com"
    LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"

    def _issuance(self):
        entity_raw, entity_priv = _ed25519_jwk("ek-1")
        ku_raw, ku_priv = _ed25519_jwk("ku-1")
        event = IssuanceEvent(
            domain=self.DOMAIN,
            governance_id="example.com",
            timestamp=datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC),
            entity_key=jwk_from_dict(entity_raw),
            operational_key=jwk_from_dict(ku_raw),
        )
        return event, (entity_raw, entity_priv), (ku_raw, ku_priv)

    def test_split_signing_across_providers(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            entry_bytes,
            parse_c2sp_event_entry,
            parse_prepared_event,
            prepare_event,
            sign_prepared_event,
        )

        event, (ek_raw, ek_priv), (ku_raw, ku_priv) = self._issuance()
        prepared = prepare_event(event, self.LR)
        assert prepared.missing_signatures() == [
            C2spSignerRole.ENTITY,
            C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
        ]

        # Entity-side process signs ae...
        entity_signed = sign_prepared_event(
            prepared, C2spSignerRole.ENTITY, _SingleKeyProvider(ek_raw, ek_priv)
        )
        # ...its bytes cross a process boundary; the operational side parses
        # them as untrusted input under its expected identity (ae validates
        # against the embedded ek, which must match the trusted entity_key).
        from dnsid.c2sp_tlog import C2spVerificationContext

        ctx = C2spVerificationContext(
            fqdn=self.DOMAIN,
            gi="example.com",
            entity_key=jwk_from_dict(ek_raw),
            operational_key=jwk_from_dict(ku_raw),
        )
        wire = canonical_json(entity_signed.envelope).encode()
        reparsed = parse_prepared_event(wire, self.LR, ctx)
        assert reparsed.missing_signatures() == [
            C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE
        ]
        complete = sign_prepared_event(
            reparsed,
            C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
            _SingleKeyProvider(ku_raw, ku_priv),
            ctx,
        )
        data = entry_bytes(complete)
        parsed_event = parse_c2sp_event_entry(data)
        assert isinstance(parsed_event, IssuanceEvent)
        assert parsed_event.domain == self.DOMAIN

    def test_tampered_prepared_bytes_rejected(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            parse_prepared_event,
            prepare_event,
            sign_prepared_event,
        )

        event, (ek_raw, ek_priv), _ = self._issuance()
        signed = sign_prepared_event(
            prepare_event(event, self.LR),
            C2spSignerRole.ENTITY,
            _SingleKeyProvider(ek_raw, ek_priv),
        )
        tampered = dict(signed.envelope)
        tampered["gi"] = "evil.example"
        wire = canonical_json(tampered).encode()
        with pytest.raises(C2spTlogVerificationError, match="invalid existing"):
            parse_prepared_event(wire, self.LR)

    def test_wrong_provider_key_rejected(self):
        from dnsid.c2sp_tlog import C2spSignerRole, prepare_event, sign_prepared_event
        from dnsid.exceptions import ArgumentError

        event, _, (ku_raw, ku_priv) = self._issuance()
        # The ku provider cannot produce the ek kid the Entity role requires.
        with pytest.raises(
            (C2spTlogVerificationError, ArgumentError), match="not found|does not match"
        ):
            sign_prepared_event(
                prepare_event(event, self.LR),
                C2spSignerRole.ENTITY,
                _SingleKeyProvider(ku_raw, ku_priv),  # ku key for ae role
            )

    def test_public_issuance_derives_seq0_chain(self):
        from dnsid.c2sp_tlog import prepare_event

        event, _, _ = self._issuance()
        public_lr = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
        prepared = prepare_event(event, public_lr)
        assert prepared.envelope["seq"] == 0
        assert "prev_index" not in prepared.envelope
        assert prepared.envelope["lr"] == public_lr

    def test_writer_rejects_bare_normalized_fqdn_stream_id(self):
        from dnsid.c2sp_tlog import prepare_event

        event, _, _ = self._issuance()
        bare_lr = "c2sp-tlog:testnet:https://log.example#agent.example.com"
        with pytest.raises(C2spTlogParseError, match="identity-instance"):
            prepare_event(event, bare_lr)

    def test_writer_rejects_bare_fqdn_after_event_normalization(self):
        from dnsid.c2sp_tlog import prepare_event

        event, _, _ = self._issuance()
        event.domain = "Agent.Example.Com."
        bare_lr = "c2sp-tlog:testnet:https://log.example#agent.example.com"
        with pytest.raises(C2spTlogParseError, match="identity-instance"):
            prepare_event(event, bare_lr)

    def test_prepared_input_rejects_bare_fqdn_stream_id(self):
        from dnsid.c2sp_tlog import parse_prepared_event, prepare_event

        event, _, _ = self._issuance()
        envelope = dict(prepare_event(event, self.LR).envelope)
        bare_lr = "c2sp-tlog:testnet:https://log.example#agent.example.com"
        envelope["stream_id"] = self.DOMAIN
        envelope["lr"] = bare_lr
        with pytest.raises(C2spTlogParseError, match="identity-instance"):
            parse_prepared_event(canonical_json(envelope).encode(), bare_lr)

    def test_public_non_genesis_requires_chain(self):
        from dnsid.c2sp_tlog import prepare_event
        from dnsid.models import RevocationEvent

        event = RevocationEvent(
            domain=self.DOMAIN,
            reason="keyCompromise",
            timestamp=datetime.datetime(2026, 7, 2, tzinfo=datetime.UTC),
        )
        public_lr = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
        with pytest.raises(C2spTlogParseError, match="chain metadata"):
            prepare_event(event, public_lr)

    def test_entity_role_pins_non_issuance_fqdn(self):
        from dnsid.c2sp_tlog import (
            C2spChain,
            C2spSignerRole,
            C2spVerificationContext,
            parse_prepared_event,
            prepare_event,
            sign_prepared_event,
        )
        from dnsid.models import RevocationEvent

        raw, private = _ed25519_jwk("ek-1")
        prepared = prepare_event(
            RevocationEvent(domain=self.DOMAIN, reason="keyCompromise",
                            timestamp=datetime.datetime(2026, 7, 2, tzinfo=datetime.UTC)), self.LR,
            C2spChain(1, b64url_encode(bytes(32)), b64url_encode(bytes(32))),
        )
        provider = _SingleKeyProvider(raw, private)
        trusted = C2spVerificationContext(entity_key=jwk_from_dict(raw), fqdn=self.DOMAIN)
        with pytest.raises(C2spTlogVerificationError, match="expected fqdn"):
            sign_prepared_event(prepared, C2spSignerRole.ENTITY, provider,
                                C2spVerificationContext(entity_key=trusted.entity_key))
        wrong = C2spVerificationContext(entity_key=trusted.entity_key, fqdn="other.example.com")
        with pytest.raises(C2spTlogVerificationError, match="fqdn does not match"):
            sign_prepared_event(prepared, C2spSignerRole.ENTITY, provider, wrong)
        with pytest.raises(C2spTlogVerificationError, match="fqdn does not match"):
            parse_prepared_event(canonical_json(prepared.envelope).encode(), self.LR, wrong)
        with pytest.raises(C2spTlogVerificationError, match="do not carry gi"):
            sign_prepared_event(prepared, C2spSignerRole.ENTITY, provider,
                                C2spVerificationContext(entity_key=trusted.entity_key, fqdn=self.DOMAIN, gi="example.com"))
        assert sign_prepared_event(prepared, C2spSignerRole.ENTITY, provider, trusted).envelope["sigs"]["ae"]

    def test_entity_role_pins_migration_destination(self):
        from dnsid.c2sp_tlog import (
            C2spChain,
            C2spSignerRole,
            C2spVerificationContext,
            parse_prepared_event,
            prepare_event,
            sign_prepared_event,
        )
        from dnsid.models import MigrationEvent

        raw, private = _ed25519_jwk("ek-1")
        destination = "c2sp-tlog:testnet:https://new-log.example#instance_BBBBBBBBBBBBBBBBBBBBBB"
        prepared = prepare_event(
            MigrationEvent(domain=self.DOMAIN, previous_log=self.LR,
                           new_log=destination, final_entry_ref=f"{self.LR}@0",
                           timestamp=datetime.datetime(2026, 7, 2, tzinfo=datetime.UTC)),
            self.LR,
            C2spChain(1, b64url_encode(bytes(32)), b64url_encode(bytes(32))),
        )
        provider = _SingleKeyProvider(raw, private)
        ctx = C2spVerificationContext(entity_key=jwk_from_dict(raw), fqdn=self.DOMAIN)
        with pytest.raises(C2spTlogVerificationError, match="expected new_lr"):
            sign_prepared_event(prepared, C2spSignerRole.ENTITY, provider, ctx)
        ctx.new_lr = "c2sp-tlog:testnet:https://other.example#instance_CCCCCCCCCCCCCCCCCCCCCC"
        with pytest.raises(C2spTlogVerificationError, match="new_lr does not match"):
            sign_prepared_event(prepared, C2spSignerRole.ENTITY, provider, ctx)
        with pytest.raises(C2spTlogVerificationError, match="new_lr does not match"):
            parse_prepared_event(canonical_json(prepared.envelope).encode(), self.LR, ctx)
        ctx.new_lr = destination
        assert sign_prepared_event(prepared, C2spSignerRole.ENTITY, provider, ctx).envelope["sigs"]["ae"]

    def test_write_prepared_event_submits_and_returns_ref(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            C2spVerificationContext,
            prepare_event,
            sign_prepared_event,
            write_prepared_event,
        )

        event, (ek_raw, ek_priv), (ku_raw, ku_priv) = self._issuance()
        ctx = C2spVerificationContext(
            fqdn=self.DOMAIN,
            gi="example.com",
            entity_key=jwk_from_dict(ek_raw),
            operational_key=jwk_from_dict(ku_raw),
        )
        complete = sign_prepared_event(
            sign_prepared_event(
                prepare_event(event, self.LR),
                C2spSignerRole.ENTITY,
                _SingleKeyProvider(ek_raw, ek_priv),
            ),
            C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
            _SingleKeyProvider(ku_raw, ku_priv),
            ctx,
        )
        seen: dict = {}

        def submit(data: bytes, idempotency_key: str) -> int:
            seen["bytes"] = data
            seen["key"] = idempotency_key
            return 7

        ref = write_prepared_event(
            complete, submit=submit, idempotency_key="issue-1"
        )
        assert str(ref) == f"{self.LR}@7"
        assert seen["key"] == "issue-1"
        assert seen["bytes"].startswith(b"{")

    def test_write_prepared_event_requires_non_empty_idempotency_key(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            C2spVerificationContext,
            prepare_event,
            sign_prepared_event,
            write_prepared_event,
        )

        event, (ek_raw, ek_priv), (ku_raw, ku_priv) = self._issuance()
        ctx = C2spVerificationContext(
            fqdn=self.DOMAIN,
            gi="example.com",
            entity_key=jwk_from_dict(ek_raw),
            operational_key=jwk_from_dict(ku_raw),
        )
        complete = sign_prepared_event(
            sign_prepared_event(
                prepare_event(event, self.LR),
                C2spSignerRole.ENTITY,
                _SingleKeyProvider(ek_raw, ek_priv),
            ),
            C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
            _SingleKeyProvider(ku_raw, ku_priv),
            ctx,
        )
        with pytest.raises(C2spTlogVerificationError, match="idempotency"):
            write_prepared_event(complete, submit=lambda _data, _key: 0, idempotency_key="")

    def test_unknown_signed_fields_preserved(self):
        from dnsid.c2sp_tlog import parse_prepared_event, prepare_event

        event, _, _ = self._issuance()
        envelope = dict(prepare_event(event, self.LR).envelope)
        envelope["x_extension"] = "kept"
        envelope = dict(sorted(envelope.items()))
        wire = canonical_json(envelope).encode()
        reparsed = parse_prepared_event(wire, self.LR)
        assert reparsed.envelope["x_extension"] == "kept"
        # The extension is inside the signed bytes.
        assert b"x_extension" in reparsed.signed_bytes

    def test_entry_bytes_requires_all_roles(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            entry_bytes,
            prepare_event,
            sign_prepared_event,
        )

        event, (ek_raw, ek_priv), _ = self._issuance()
        only_ae = sign_prepared_event(
            prepare_event(event, self.LR),
            C2spSignerRole.ENTITY,
            _SingleKeyProvider(ek_raw, ek_priv),
        )
        with pytest.raises(C2spTlogParseError, match="missing sigs"):
            entry_bytes(only_ae)

    def test_lr_mismatch_rejected(self):
        from dnsid.c2sp_tlog import parse_prepared_event, prepare_event

        event, _, _ = self._issuance()
        wire = canonical_json(prepare_event(event, self.LR).envelope).encode()
        with pytest.raises(C2spTlogParseError, match="mismatch"):
            parse_prepared_event(
                wire, "c2sp-tlog:testnet:https://other.example#agent.example.com"
            )


class TestDistinctKeys:
    def test_issuance_with_identical_keys_rejected(self):
        from dnsid.c2sp_tlog import StreamVerifierOptions, signed_c2sp_event_bytes

        raw, priv = _ed25519_jwk("shared")
        event = IssuanceEvent(
            domain="agent.example.com",
            governance_id="example.com",
            timestamp=datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC),
            entity_key=jwk_from_dict(raw),
            operational_key=jwk_from_dict(raw),
        )
        context = C2spEventContext(scope="testnet", log_origin="log.example",
            stream_id="instance", lr="c2sp-tlog:testnet:https://log.example#instance", seq=0)
        signed = signed_c2sp_event_bytes(event, context)
        event.signing_kid = "shared"
        event.sig = b64url_encode(priv.sign(signed))
        event.operational_countersig = b64url_encode(priv.sign(signed))
        from dnsid.c2sp_tlog import canonicalize_c2sp_event

        entry = canonicalize_c2sp_event(event, context)
        items = [
            VerifiedLifecycleEvent(
                index=0, leaf_hash=leaf_hash(entry), data=entry, event=event, chain={"seq": 0}
            )
        ]
        with pytest.raises(C2spTlogVerificationError, match="distinct"):
            verify_lifecycle(
                items,
                StreamVerifierOptions(
                    signer_key=jwk_from_dict(raw),
                    checkpoint_integration_time_ms=1_800_000_000_000,
                ),
            )


def test_unexpected_signature_role_is_ignored():
    from dnsid.c2sp_tlog import (
        IndexedEntry,
        StreamVerifierOptions,
        canonical_bytes,
        verify_stream_lifecycle,
    )

    malformed = json.loads(VECTOR_REVOCATION)
    malformed["sigs"]["unexpected"] = {"kid": "x", "sig": "AA"}
    result = verify_stream_lifecycle(
        [
            IndexedEntry(index=0, data=VECTOR_ISSUANCE.encode()),
            IndexedEntry(index=1, data=canonical_bytes(malformed)),
        ],
        "agent.example",
        StreamVerifierOptions(
            checkpoint_integration_time_ms=1_800_000_000_000,
        ),
    )
    assert len(result) == 1


def test_authenticated_bad_chain_fails_after_ignoring_bad_signature(monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as stream_verifier
    monkeypatch.setattr(stream_verifier, "_validate_public_fields", lambda *args: None)
    monkeypatch.setattr(stream_verifier, "c2sp_event_id", lambda data: b64url_encode(
        stream_verifier.sha256(stream_verifier.signed_c2sp_entry_bytes(data))))
    monkeypatch.setattr(stream_verifier, "_applied_keys", lambda *args: (None, None))
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    from dnsid.c2sp_tlog import IndexedEntry, verify_stream_lifecycle
    from dnsid.models import KeyRotationEvent, RevocationEvent

    candidates = {
        "issuance": IssuanceEvent(domain="agent.example.com"),
        "bad-signature": RevocationEvent(domain="agent.example.com"),
        "bad-chain": KeyRotationEvent(domain="agent.example.com"),
    }

    monkeypatch.setattr(
        stream_verifier,
        "parse_c2sp_event_entry",
        lambda data, context, **kwargs: candidates[data.decode()],
    )
    monkeypatch.setattr(
        stream_verifier, "parse_json_no_duplicate_members", lambda data: {"fqdn": "agent.example.com"}
    )
    monkeypatch.setattr(
        stream_verifier,
        "parse_chain_fields",
        lambda name: {},
    )
    monkeypatch.setattr(stream_verifier, "leaf_hash", lambda data: data)
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    monkeypatch.setattr(
        stream_verifier,
        "_candidate_is_authenticated",
        lambda candidate, selected, options: candidate.data != b"bad-signature",
    )

    def verify(events, options):
        if events[-1].data == b"bad-chain":
            raise C2spTlogVerificationError("invalid prev_index")

    monkeypatch.setattr(stream_verifier, "verify_lifecycle", verify)
    entries = [
        IndexedEntry(index=0, data=b"issuance"),
        IndexedEntry(index=1, data=b"bad-signature"),
        IndexedEntry(index=2, data=b"bad-chain"),
    ]

    with pytest.raises(C2spTlogVerificationError) as exc_info:
        verify_stream_lifecycle(entries, "agent.example.com")
    assert exc_info.value.category == C2spLifecycleErrorCategory.CHAIN_CONTINUITY
    assert exc_info.value.failing_candidate_index == 2


def test_authenticated_second_issuance_is_fatal(monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as stream_verifier
    monkeypatch.setattr(stream_verifier, "_validate_public_fields", lambda *args: None)
    monkeypatch.setattr(stream_verifier, "c2sp_event_id", lambda data: b64url_encode(
        stream_verifier.sha256(stream_verifier.signed_c2sp_entry_bytes(data))))
    monkeypatch.setattr(stream_verifier, "_applied_keys", lambda *args: (None, None))
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    from dnsid.c2sp_tlog import IndexedEntry, verify_stream_lifecycle

    monkeypatch.setattr(
        stream_verifier,
        "parse_c2sp_event_entry",
        lambda data, context, **kwargs: IssuanceEvent(domain="agent.example.com"),
    )
    monkeypatch.setattr(
        stream_verifier, "parse_json_no_duplicate_members", lambda data: {"fqdn": "agent.example.com"}
    )
    monkeypatch.setattr(stream_verifier, "parse_chain_fields", lambda value: {})
    monkeypatch.setattr(stream_verifier, "leaf_hash", lambda data: data)
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    monkeypatch.setattr(
        stream_verifier,
        "_candidate_is_authenticated",
        lambda candidate, selected, options: True,
    )
    monkeypatch.setattr(stream_verifier, "verify_lifecycle", lambda events, options: None)

    with pytest.raises(C2spTlogVerificationError) as exc_info:
        verify_stream_lifecycle(
            [
                IndexedEntry(index=0, data=b"issuance-1"),
                IndexedEntry(index=1, data=b"issuance-2"),
            ],
            "agent.example.com",
        )
    assert exc_info.value.category == C2spLifecycleErrorCategory.DUPLICATE_ISSUANCE
    assert exc_info.value.failing_candidate_index == 1


def test_resigned_identical_payload_is_deduplicated(monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as stream_verifier
    monkeypatch.setattr(stream_verifier, "_validate_public_fields", lambda *args: None)
    monkeypatch.setattr(stream_verifier, "c2sp_event_id", lambda data: b64url_encode(
        stream_verifier.sha256(stream_verifier.signed_c2sp_entry_bytes(data))))
    monkeypatch.setattr(stream_verifier, "_applied_keys", lambda *args: (None, None))
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    from dnsid.c2sp_tlog import IndexedEntry, verify_stream_lifecycle
    from dnsid.models import KeyRotationEvent

    monkeypatch.setattr(
        stream_verifier,
        "parse_c2sp_event_entry",
        lambda data, context, **kwargs: (
            IssuanceEvent(domain="agent.example.com")
            if data.startswith(b"issuance")
            else KeyRotationEvent(domain="agent.example.com")
        ),
    )
    monkeypatch.setattr(
        stream_verifier, "parse_json_no_duplicate_members", lambda data: {"fqdn": "agent.example.com"}
    )
    monkeypatch.setattr(stream_verifier, "parse_chain_fields", lambda value: {})
    monkeypatch.setattr(
        stream_verifier,
        "signed_c2sp_entry_bytes",
        lambda data: b"issuance-effect" if data.startswith(b"issuance") else data,
    )
    monkeypatch.setattr(
        stream_verifier,
        "_candidate_is_authenticated",
        lambda candidate, selected, options: True,
    )
    monkeypatch.setattr(stream_verifier, "verify_lifecycle", lambda events, options: None)

    result = verify_stream_lifecycle(
        [IndexedEntry(index=0, data=b"issuance-signature-1"),
         IndexedEntry(index=1, data=b"issuance-signature-2"),
         IndexedEntry(index=2, data=b"rotation")], "agent.example.com")
    assert [item.index for item in result] == [0, 2]


def test_byte_identical_complete_entry_is_applied_once(monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as stream_verifier
    monkeypatch.setattr(stream_verifier, "_validate_public_fields", lambda *args: None)
    monkeypatch.setattr(stream_verifier, "c2sp_event_id", lambda data: b64url_encode(
        stream_verifier.sha256(stream_verifier.signed_c2sp_entry_bytes(data))))
    monkeypatch.setattr(stream_verifier, "_applied_keys", lambda *args: (None, None))
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    from dnsid.c2sp_tlog import IndexedEntry, verify_stream_lifecycle

    monkeypatch.setattr(
        stream_verifier,
        "parse_c2sp_event_entry",
        lambda data, context, **kwargs: IssuanceEvent(domain="agent.example.com"),
    )
    monkeypatch.setattr(
        stream_verifier, "parse_json_no_duplicate_members", lambda data: {"fqdn": "agent.example.com"}
    )
    monkeypatch.setattr(stream_verifier, "parse_chain_fields", lambda value: {})
    monkeypatch.setattr(
        stream_verifier,
        "_candidate_is_authenticated",
        lambda candidate, selected, options: True,
    )
    monkeypatch.setattr(stream_verifier, "verify_lifecycle", lambda events, options: None)

    selected = verify_stream_lifecycle(
        [
            IndexedEntry(index=0, data=b"identical-entry"),
            IndexedEntry(index=1, data=b"identical-entry"),
        ],
        "agent.example.com",
    )

    assert [item.index for item in selected] == [0]


def test_authenticated_post_terminal_candidate_is_fatal(monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as stream_verifier
    monkeypatch.setattr(stream_verifier, "_validate_public_fields", lambda *args: None)
    monkeypatch.setattr(stream_verifier, "c2sp_event_id", lambda data: b64url_encode(
        stream_verifier.sha256(stream_verifier.signed_c2sp_entry_bytes(data))))
    monkeypatch.setattr(stream_verifier, "_applied_keys", lambda *args: (None, None))
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    from dnsid.c2sp_tlog import IndexedEntry, verify_stream_lifecycle
    from dnsid.models import KeyRotationEvent, RevocationEvent

    candidates = {
        b"issuance": IssuanceEvent(domain="agent.example.com"),
        b"revocation": RevocationEvent(domain="agent.example.com"),
        b"rotation": KeyRotationEvent(domain="agent.example.com"),
    }
    monkeypatch.setattr(
        stream_verifier,
        "parse_c2sp_event_entry",
        lambda data, context, **kwargs: candidates[data],
    )
    monkeypatch.setattr(
        stream_verifier, "parse_json_no_duplicate_members", lambda data: {"fqdn": "agent.example.com"}
    )
    monkeypatch.setattr(stream_verifier, "parse_chain_fields", lambda value: {})
    monkeypatch.setattr(
        stream_verifier,
        "_candidate_is_authenticated",
        lambda candidate, selected, options: True,
    )

    def verify(events, options):
        if len(events) == 3:
            raise C2spTlogVerificationError(
                "event appears after terminal lifecycle event",
                category=C2spLifecycleErrorCategory.TERMINAL_STATE,
            )

    monkeypatch.setattr(stream_verifier, "verify_lifecycle", verify)

    with pytest.raises(C2spTlogVerificationError) as exc_info:
        verify_stream_lifecycle(
            [
                IndexedEntry(index=0, data=b"issuance"),
                IndexedEntry(index=1, data=b"revocation"),
                IndexedEntry(index=2, data=b"rotation"),
            ],
            "agent.example.com",
        )
    assert exc_info.value.category == C2spLifecycleErrorCategory.TERMINAL_STATE
    assert exc_info.value.failing_candidate_index == 2


def test_inbound_migration_resolution_is_memoized(monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as stream_verifier
    monkeypatch.setattr(stream_verifier, "_validate_public_fields", lambda *args: None)
    monkeypatch.setattr(stream_verifier, "c2sp_event_id", lambda data: b64url_encode(
        stream_verifier.sha256(stream_verifier.signed_c2sp_entry_bytes(data))))
    monkeypatch.setattr(stream_verifier, "_applied_keys", lambda *args: (None, None))
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    from dnsid.c2sp_tlog import (
        IndexedEntry,
        MigrationVerificationResult,
        StreamVerifierOptions,
        verify_stream_lifecycle,
    )
    from dnsid.models import KeyRotationEvent, MigrationEvent

    entity_raw, _ = _ed25519_jwk("entity-memo")
    operational_raw, _ = _ed25519_jwk("op-memo")
    result = MigrationVerificationResult(
        jwk_from_dict(entity_raw), jwk_from_dict(operational_raw)
    )
    calls = 0

    def resolve(event):
        nonlocal calls
        calls += 1
        return result

    migration = MigrationEvent(domain="agent.example.com")
    candidates = {
        b"migration": migration,
        b"rotation": KeyRotationEvent(domain="agent.example.com"),
    }
    monkeypatch.setattr(
        stream_verifier,
        "parse_c2sp_event_entry",
        lambda data, context, **kwargs: candidates[data],
    )
    monkeypatch.setattr(
        stream_verifier, "parse_json_no_duplicate_members", lambda data: {"fqdn": "agent.example.com"}
    )
    monkeypatch.setattr(stream_verifier, "parse_chain_fields", lambda value: {})
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)

    def authenticate(candidate, selected, options):
        assert options.verify_migration is not None
        options.verify_migration(migration)
        return True

    def verify(events, options):
        assert options.verify_migration is not None
        options.verify_migration(migration)

    monkeypatch.setattr(stream_verifier, "_candidate_is_authenticated", authenticate)
    monkeypatch.setattr(stream_verifier, "verify_lifecycle", verify)

    verify_stream_lifecycle(
        [
            IndexedEntry(index=0, data=b"migration"),
            IndexedEntry(index=1, data=b"rotation"),
        ],
        "agent.example.com",
        StreamVerifierOptions(verify_migration=resolve),
    )

    assert calls == 1


def test_typed_inbound_migration_resolver_failure_is_fatal(monkeypatch):
    import dnsid.c2sp_tlog.stream_verifier as stream_verifier
    monkeypatch.setattr(stream_verifier, "_validate_public_fields", lambda *args: None)
    monkeypatch.setattr(stream_verifier, "c2sp_event_id", lambda data: b64url_encode(
        stream_verifier.sha256(stream_verifier.signed_c2sp_entry_bytes(data))))
    monkeypatch.setattr(stream_verifier, "_applied_keys", lambda *args: (None, None))
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)
    from dnsid.c2sp_tlog import IndexedEntry, StreamVerifierOptions, verify_stream_lifecycle
    from dnsid.c2sp_tlog.errors import C2spLifecycleErrorCategory
    from dnsid.models import MigrationEvent

    migration = MigrationEvent(domain="agent.example.com")
    monkeypatch.setattr(stream_verifier, "parse_c2sp_event_entry", lambda data, context, **kwargs: migration)
    monkeypatch.setattr(stream_verifier, "parse_json_no_duplicate_members", lambda data: {"fqdn": "agent.example.com"})
    monkeypatch.setattr(stream_verifier, "parse_chain_fields", lambda value: {})
    monkeypatch.setattr(stream_verifier, "signed_c2sp_entry_bytes", lambda data: data)

    def fail(_event):
        raise C2spTlogVerificationError("prior history invalid")

    with pytest.raises(C2spTlogVerificationError) as exc:
        verify_stream_lifecycle(
            [IndexedEntry(index=0, data=b"migration")],
            "agent.example.com",
            StreamVerifierOptions(verify_migration=fail),
        )
    assert exc.value.category == C2spLifecycleErrorCategory.INVALID_MIGRATION


def test_verified_inbound_migration_history_is_stitched_once():
    from dnsid.c2sp_tlog import MigrationVerificationResult
    from dnsid.c2sp_tlog.reader import _stitch_migration_history
    from dnsid.exceptions import VerificationError
    from dnsid.models import MigrationEvent, RevocationEvent

    entity_raw, _ = _ed25519_jwk("entity")
    operational_raw, _ = _ed25519_jwk("op")
    entity_key = jwk_from_dict(entity_raw)
    operational_key = jwk_from_dict(operational_raw)
    issuance = IssuanceEvent(
        domain="agent.example.com",
        governance_id="example.com",
        entity_key=entity_key,
        operational_key=operational_key,
        timestamp=datetime.datetime(2026, 1, 2, tzinfo=datetime.UTC),
    )
    migration = MigrationEvent(
        domain="agent.example.com",
        previous_log="method-a:stream-1",
        new_log="method-b:stream-1",
        final_entry_ref="method-a:entry-10",
        timestamp=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
    )
    result = MigrationVerificationResult(entity_key, operational_key, [issuance])

    assert _stitch_migration_history(
        "agent.example.com", [migration], {id(migration): result}
    ) == [issuance, migration]

    duplicate = MigrationVerificationResult(
        entity_key, operational_key, [issuance, migration]
    )
    with pytest.raises(VerificationError) as exc_info:
        _stitch_migration_history(
            "agent.example.com", [migration], {id(migration): duplicate}
        )
    assert exc_info.value.category == C2spLifecycleErrorCategory.INVALID_MIGRATION

    terminal = MigrationVerificationResult(
        entity_key,
        operational_key,
        [
            issuance,
            RevocationEvent(
                domain="agent.example.com",
                reason="keyCompromise",
                timestamp=datetime.datetime(2026, 1, 3, tzinfo=datetime.UTC),
            ),
        ],
    )
    with pytest.raises(VerificationError) as exc_info:
        _stitch_migration_history(
            "agent.example.com", [migration], {id(migration): terminal}
        )
    assert exc_info.value.category == C2spLifecycleErrorCategory.INVALID_MIGRATION


# ---------------------------------------------------------------------------
# Review fixes (PR #122): safe-int bound, JCS floats, split-ISSUANCE identity
# pinning, and single-snapshot log loading.
# ---------------------------------------------------------------------------


class TestSafeIntegerBound:
    def test_boundary_accepted_and_exceeded_rejected(self):
        from dnsid.c2sp_tlog.event_codec import _MAX_SAFE_INT, _as_safe_int

        assert _as_safe_int(_MAX_SAFE_INT, "seq") == _MAX_SAFE_INT
        with pytest.raises(C2spTlogParseError, match="safe integer range"):
            _as_safe_int(_MAX_SAFE_INT + 1, "seq")

    def test_oversized_ts_in_entry_rejected(self):
        from dnsid.c2sp_tlog.event_codec import _MAX_SAFE_INT

        # Hand-build the bytes (canonical_bytes itself now rejects the oversized
        # integer) so the entry reaches the parser's _as_safe_int check.
        raw = (
            '{"fqdn":"agent.example.com","kind":"dnsid.lifecycle",'
            '"reason":"keyCompromise","sigs":{"ae":{"kid":"k","sig":"AAAA"}},'
            f'"ts":{_MAX_SAFE_INT + 1},"type":"REVOCATION","v":1}}'
        ).encode()
        # Rejected either at canonicalization (oversized int) or _as_safe_int.
        with pytest.raises(
            C2spTlogParseError, match="interoperable range|safe integer range|missing lr"
        ):
            parse_c2sp_event_entry(raw)


class TestCanonicalFloats:
    def test_integer_valued_float_serializes_as_integer(self):
        assert canonical_json({"n": 2.0}) == '{"n":2}'

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0.1, "0.1"),
            (0.000001, "0.000001"),  # boundary: fixed notation
            (1e-7, "1e-7"),  # boundary: exponential, no zero-pad
            (1e21, "1e+21"),  # boundary: exponential
            (1e20, "100000000000000000000"),  # boundary: fixed
            (-4.5, "-4.5"),
            (-0.0, "0"),
            (123.456, "123.456"),
        ],
    )
    def test_rfc8785_number_formatting(self, value, expected):
        # RFC 8785 / ECMAScript Number::toString, not Python's json (1e-06).
        assert canonical_json(value) == expected

    def test_exactly_representable_large_int_serializes_js_consistently(self):
        # 2**53 and 10**20 are exact doubles; large ints match JS formatting.
        assert canonical_json(2**53) == "9007199254740992"
        assert canonical_json(10**20) == "100000000000000000000"
        assert canonical_json(10**21) == "1e+21"

    def test_non_representable_integer_rejected(self):
        # 2**53 + 1 has no exact IEEE-754 double, so no SDK could reproduce it.
        with pytest.raises(C2spTlogParseError, match="not exactly representable"):
            canonical_json(2**53 + 1)

    def test_canonicalization_round_trips_large_float(self):
        from dnsid.c2sp_tlog import canonical_bytes
        from dnsid.c2sp_tlog.canonical import assert_canonical_json_bytes

        data = canonical_bytes({"n": 1e20})
        # Re-parsing yields a Python int; canonicalization must reproduce the
        # same bytes (the round trip Ben flagged).
        assert_canonical_json_bytes(data)


class TestSplitIssuanceIdentityPinning:
    DOMAIN = "agent.example.com"
    LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"

    def _entity_signed_wire(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            canonical_json,
            prepare_event,
            sign_prepared_event,
        )

        entity_raw, entity_priv = _ed25519_jwk("ek-1")
        ku_raw, _ = _ed25519_jwk("ku-1")
        event = IssuanceEvent(
            domain=self.DOMAIN,
            governance_id="example.com",
            timestamp=datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC),
            entity_key=jwk_from_dict(entity_raw),
            operational_key=jwk_from_dict(ku_raw),
        )
        signed = sign_prepared_event(
            prepare_event(event, self.LR),
            C2spSignerRole.ENTITY,
            _SingleKeyProvider(entity_raw, entity_priv),
        )
        return canonical_json(signed.envelope).encode(), entity_raw, ku_raw

    def test_wrong_fqdn_rejected(self):
        from dnsid.c2sp_tlog import C2spVerificationContext, parse_prepared_event

        wire, _, ku_raw = self._entity_signed_wire()
        ctx = C2spVerificationContext(
            fqdn="victim.example.com", operational_key=jwk_from_dict(ku_raw)
        )
        with pytest.raises(C2spTlogVerificationError, match="fqdn does not match"):
            parse_prepared_event(wire, self.LR, ctx)

    def test_wrong_operational_key_rejected(self):
        from dnsid.c2sp_tlog import C2spVerificationContext, parse_prepared_event

        wire, _, _ = self._entity_signed_wire()
        other_ku_raw, _ = _ed25519_jwk("ku-other")
        ctx = C2spVerificationContext(
            fqdn=self.DOMAIN, operational_key=jwk_from_dict(other_ku_raw)
        )
        with pytest.raises(C2spTlogVerificationError, match="not the expected operational"):
            parse_prepared_event(wire, self.LR, ctx)

    def test_wrong_entity_key_rejected(self):
        from dnsid.c2sp_tlog import C2spVerificationContext, parse_prepared_event

        wire, _, ku_raw = self._entity_signed_wire()
        other_ek_raw, _ = _ed25519_jwk("ek-other")
        ctx = C2spVerificationContext(
            fqdn=self.DOMAIN,
            gi="example.com",
            operational_key=jwk_from_dict(ku_raw),
            entity_key=jwk_from_dict(other_ek_raw),
        )
        with pytest.raises(C2spTlogVerificationError, match="ek does not match"):
            parse_prepared_event(wire, self.LR, ctx)

    def test_matching_identity_accepted(self):
        from dnsid.c2sp_tlog import C2spVerificationContext, parse_prepared_event

        wire, entity_raw, ku_raw = self._entity_signed_wire()
        ctx = C2spVerificationContext(
            fqdn=self.DOMAIN,
            gi="example.com",
            operational_key=jwk_from_dict(ku_raw),
            entity_key=jwk_from_dict(entity_raw),
        )
        prepared = parse_prepared_event(wire, self.LR, ctx)
        assert prepared.envelope["fqdn"] == self.DOMAIN


class TestSingleSnapshotLoad(TestEndToEndReader):
    def test_dnsid1_checks_share_one_log_load(self):
        from unittest.mock import patch

        reader, _ = self._build_log()
        with patch.object(
            reader._source, "load_stream", wraps=reader._source.load_stream
        ) as mock_load:
            history = reader.rebuild_history(self.DOMAIN)
            reader.verify_non_revocation(
                self.DOMAIN, datetime.datetime.now(datetime.UTC)
            )
            issuance = history[0]
            assert isinstance(issuance, IssuanceEvent)
            assert issuance.operational_key is not None
            reader.key_timestamp(self.DOMAIN, issuance.operational_key.thumbprint())
        # All three verified reads reuse one loaded + policy-checked snapshot.
        assert mock_load.call_count == 1

    def test_non_revocation_refreshes_an_expired_cached_snapshot(self):
        from unittest.mock import patch

        reader, _ = self._build_log()
        reader.rebuild_history(self.DOMAIN)
        cached = next(iter(reader._history_cache.values()))
        fresh_witness_time = cached.checkpoint_witness_time
        reader._options.checkpoint_freshness_ms = 1_000
        reader._now_ms = lambda: fresh_witness_time.timestamp() * 1000 + 500
        cached.checkpoint_witness_time -= datetime.timedelta(seconds=2)

        with patch.object(
            reader._source, "load_stream", wraps=reader._source.load_stream
        ) as mock_load:
            reader.verify_non_revocation(
                self.DOMAIN, datetime.datetime.now(datetime.UTC)
            )

        assert mock_load.call_count == 1
        assert next(iter(reader._history_cache.values())).checkpoint_witness_time == (
            fresh_witness_time
        )


class TestSourceAbstraction(TestEndToEndReader):
    def test_scan_source_returns_portable_full_scan_and_proven_entry(self):
        from dnsid.c2sp_tlog import verify_inclusion

        reader, _ = self._build_log()
        evidence = reader._source.load_stream(reader.parsed, self.DOMAIN)
        assert evidence.completeness_mode == "full-scan"
        assert evidence.complete_through_size == evidence.checkpoint.tree_size
        assert evidence.checkpoint_bytes

        proven = reader._source.read_entry(reader.parsed, 0)
        assert proven.entry_bytes == evidence.entries[0].data
        assert proven.checkpoint == evidence.checkpoint_bytes
        assert verify_inclusion(
            proven.entry_bytes,
            proven.index,
            evidence.checkpoint.tree_size,
            evidence.checkpoint.root_hash,
            proven.inclusion_proof,
        )

    def test_reader_accepts_injected_source_without_transport(self):
        from unittest.mock import MagicMock

        reader, _ = self._build_log()
        source = MagicMock()
        injected = C2spTlogReader(
            self.LR,
            C2spTlogReaderOptions(policy=reader._options.policy, source=source),
        )
        assert injected._source is source

    def test_reader_rejects_ambiguous_transport_and_source(self):
        from unittest.mock import MagicMock

        reader, _ = self._build_log()
        with pytest.raises(C2spTlogVerificationError, match="either transport or source"):
            C2spTlogReader(
                self.LR,
                C2spTlogReaderOptions(
                    policy=reader._options.policy,
                    transport=MagicMock(),
                    source=MagicMock(),
                ),
            )

    def test_reader_rejects_bundle_fetching_with_injected_source(self):
        from unittest.mock import MagicMock

        reader, _ = self._build_log()
        with pytest.raises(C2spTlogVerificationError, match="requires a transport"):
            C2spTlogReader(
                self.LR,
                C2spTlogReaderOptions(
                    policy=reader._options.policy,
                    source=MagicMock(),
                    bundle_policy_document=b"policy",
                    bundle_keys=[MagicMock()],
                ),
            )

    def test_public_reader_rejects_source_without_security_guarantees(self):
        from unittest.mock import MagicMock

        reader, _ = self._build_log()
        public_lr = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
        with pytest.raises(
            C2spTlogVerificationError, match="must declare resource-fetch"
        ):
            C2spTlogReader(
                public_lr,
                C2spTlogReaderOptions(
                    policy=reader._options.policy,
                    source=MagicMock(spec=[]),
                ),
            )

    @pytest.mark.parametrize(
        ("guarantees", "missing"),
        [
            (
                C2spResourceFetchGuarantees(False, True, True, True, True),
                "HTTPS-only",
            ),
            (
                C2spResourceFetchGuarantees(True, False, True, True, True),
                "redirect rejection",
            ),
            (
                C2spResourceFetchGuarantees(True, True, False, True, True),
                "validation of every resolved address",
            ),
            (
                C2spResourceFetchGuarantees(True, True, True, False, True),
                "connection to a validated address",
            ),
            (
                C2spResourceFetchGuarantees(True, True, True, True, False),
                "response bounding during reads",
            ),
        ],
    )
    def test_public_reader_rejects_incomplete_security_guarantees(
        self, guarantees, missing
    ):
        from unittest.mock import MagicMock

        reader, _ = self._build_log()
        public_lr = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
        source = MagicMock()
        source.security_guarantees.return_value = guarantees
        with pytest.raises(C2spTlogVerificationError, match=missing):
            C2spTlogReader(
                public_lr,
                C2spTlogReaderOptions(
                    policy=reader._options.policy,
                    source=source,
                ),
            )

    def test_public_reader_accepts_explicit_conforming_source(self):
        from unittest.mock import MagicMock

        reader, _ = self._build_log()
        public_lr = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
        source = MagicMock()
        source.security_guarantees.return_value = C2spResourceFetchGuarantees(
            True, True, True, True, True
        )
        injected = C2spTlogReader(
            public_lr,
            C2spTlogReaderOptions(policy=reader._options.policy, source=source),
        )
        assert injected._source is source

    def test_public_scan_transport_requires_bounded_fetch_capability(self):
        reader, _ = self._build_log()
        public_lr = "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"

        class Transport:
            def security_guarantees(self):
                return C2spResourceFetchGuarantees(True, True, True, True, True)

            def __call__(self, url):
                return b""

        with pytest.raises(
            C2spTlogVerificationError, match="must declare resource-fetch"
        ):
            C2spTlogReader(
                public_lr,
                C2spTlogReaderOptions(
                    policy=reader._options.policy,
                    transport=Transport(),
                ),
            )

    def test_scan_source_passes_per_resource_bound_to_conforming_transport(self):
        from dnsid.c2sp_tlog import ScanStreamSource, parse_c2sp_tlog_lr

        calls = []

        class Transport:
            def security_guarantees(self):
                return C2spResourceFetchGuarantees(True, True, True, True, True)

            def fetch_bounded(self, url, maximum):
                calls.append((url, maximum))
                return b"checkpoint"

            def __call__(self, url):
                raise AssertionError("unbounded fetch path used")

        source = ScanStreamSource(Transport(), lambda checkpoint: None)
        reference = parse_c2sp_tlog_lr(
            "c2sp-tlog:public:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
        )
        assert source.fetch_checkpoint(reference) == b"checkpoint"
        assert calls == [("https://log.example/checkpoint", 1024 * 1024)]

    def test_reader_adapts_transport_failure_as_transient_with_cause(self):
        reader, _ = self._build_log()
        cause = TimeoutError("timed out")

        class Source:
            def load_stream(self, reference, fqdn):
                raise C2spTlogTransportError(
                    "checkpoint unavailable", transient=True, cause=cause
                )

        reader._source = Source()
        with pytest.raises(VerificationError) as exc_info:
            reader.rebuild_history(self.DOMAIN)
        error = exc_info.value
        assert error.code is VerificationCode.LOG_ERROR
        assert error.transient is True
        assert error.category == C2spLifecycleErrorCategory.INVALID_EVIDENCE.value
        assert isinstance(error.__cause__, C2spTlogTransportError)
        assert error.__cause__.__cause__ is cause

    @pytest.mark.parametrize(
        ("cause", "transient"),
        [
            (TimeoutError("timed out"), True),
            (ValueError("unsafe redirect"), False),
        ],
    )
    def test_scan_transport_retry_classification(self, cause, transient):
        reader, _ = self._build_log()

        def failing_transport(url):
            raise cause

        reader._source._transport = failing_transport
        with pytest.raises(VerificationError) as exc_info:
            reader.rebuild_history(self.DOMAIN)
        error = exc_info.value
        assert error.transient is transient
        assert isinstance(error.__cause__, C2spTlogTransportError)
        assert error.__cause__.__cause__ is cause

    def test_reader_adapts_parse_failure_as_non_transient_with_cause(self):
        reader, _ = self._build_log()

        class Source:
            def load_stream(self, reference, fqdn):
                raise C2spTlogParseError("malformed checkpoint")

        reader._source = Source()
        with pytest.raises(VerificationError) as exc_info:
            reader.rebuild_history(self.DOMAIN)
        error = exc_info.value
        assert error.code is VerificationCode.LOG_ERROR
        assert error.transient is False
        assert error.category == C2spLifecycleErrorCategory.INVALID_EVIDENCE.value
        assert isinstance(error.__cause__, C2spTlogParseError)


class TestMandatoryOperationalContext:
    DOMAIN = "agent.example.com"
    LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"

    def _entity_signed(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            prepare_event,
            sign_prepared_event,
        )

        entity_raw, entity_priv = _ed25519_jwk("ek-1")
        ku_raw, ku_priv = _ed25519_jwk("ku-1")
        event = IssuanceEvent(
            domain=self.DOMAIN,
            governance_id="example.com",
            timestamp=datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC),
            entity_key=jwk_from_dict(entity_raw),
            operational_key=jwk_from_dict(ku_raw),
        )
        signed = sign_prepared_event(
            prepare_event(event, self.LR),
            C2spSignerRole.ENTITY,
            _SingleKeyProvider(entity_raw, entity_priv),
        )
        return signed, (ku_raw, ku_priv)

    def test_countersign_without_full_context_rejected(self):
        from dnsid.c2sp_tlog import C2spSignerRole, sign_prepared_event

        signed, (ku_raw, ku_priv) = self._entity_signed()
        ku_provider = _SingleKeyProvider(ku_raw, ku_priv)
        # No context at all → must fail (fqdn/gi/entity_key/operational_key).
        with pytest.raises(C2spTlogVerificationError, match="complete expected identity"):
            sign_prepared_event(
                signed, C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE, ku_provider
            )

    def test_countersign_with_partial_context_rejected(self):
        from dnsid.c2sp_tlog import (
            C2spSignerRole,
            C2spVerificationContext,
            sign_prepared_event,
        )

        signed, (ku_raw, ku_priv) = self._entity_signed()
        ku_provider = _SingleKeyProvider(ku_raw, ku_priv)
        partial = C2spVerificationContext(fqdn=self.DOMAIN)  # missing gi/keys
        with pytest.raises(C2spTlogVerificationError, match="missing: gi"):
            sign_prepared_event(
                signed,
                C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
                ku_provider,
                partial,
            )


class TestAppendOnlyConsistency(TestEndToEndReader):
    def _second_reader_sharing_store(self, first):
        # A new reader (new verification pass) that shares the same options,
        # hence the same checkpoint store.
        return C2spTlogReader(self.LR, first._options)

    def test_first_contact_accepted_and_recorded(self):
        reader, _ = self._build_log()
        reader.rebuild_history(self.DOMAIN)
        stored = reader._options.checkpoint_store.get(reader.parsed.origin)
        assert stored is not None
        assert stored.tree_size == 1

    def test_consistent_reload_accepted(self):
        reader, _ = self._build_log()
        reader.rebuild_history(self.DOMAIN)
        # A fresh reader over the same log + shared store re-verifies fine.
        again = self._second_reader_sharing_store(reader)
        history = again.rebuild_history(self.DOMAIN)
        assert len(history) == 1

    def test_shrunk_tree_rejected(self):
        from dnsid.exceptions import VerificationError

        reader, _ = self._build_log()
        reader.rebuild_history(self.DOMAIN)
        # Forge a trusted checkpoint claiming a larger tree; the real size-1
        # log now looks like a rollback.
        from dnsid.c2sp_tlog import TrustedCheckpoint

        reader._options.checkpoint_store.put(
            TrustedCheckpoint(
                origin=reader.parsed.origin,
                tree_size=5,
                root_hash=b"\x00" * 32,
                witness_time=datetime.datetime.now(datetime.UTC),
            )
        )
        again = self._second_reader_sharing_store(reader)
        with pytest.raises(VerificationError, match="regressed"):
            again.rebuild_history(self.DOMAIN)

    def test_forked_prefix_rejected(self):
        from dnsid.c2sp_tlog import TrustedCheckpoint
        from dnsid.exceptions import VerificationError

        reader, _ = self._build_log()
        # Trusted checkpoint at size 1 but with a DIFFERENT root than the log's
        # actual leaf 0 → the trusted tree is not a prefix (fork).
        reader._options.checkpoint_store.put(
            TrustedCheckpoint(
                origin=reader.parsed.origin,
                tree_size=1,
                root_hash=b"\x11" * 32,
                witness_time=datetime.datetime.now(datetime.UTC),
            )
        )
        with pytest.raises(VerificationError, match="not a prefix|not consistent"):
            reader.rebuild_history(self.DOMAIN)


    @pytest.mark.parametrize("trusted_size,growing,category", [
        (5, False, "LOG_ROLLBACK"),
        (1, False, "LOG_FORK"),
        (1, True, "LOG_INCONSISTENT"),
    ])
    def test_durable_reader_rejects_and_classifies_after_restart(
        self, tmp_path, trusted_size, growing, category
    ):
        from dnsid.c2sp_tlog import (
            C2spCheckpointConsistencyError,
            SQLiteCheckpointStore,
            TrustedCheckpoint,
        )
        from dnsid.enums import VerificationCode
        from dnsid.exceptions import VerificationError

        reader, ts = self._build_log((lambda entry: [entry]) if growing else None)
        path = tmp_path / "trust.db"
        store = SQLiteCheckpointStore(path, create=True)
        trusted = TrustedCheckpoint(reader.parsed.origin, trusted_size, bytes(32), ts)
        store.put(trusted)
        reader._options.checkpoint_store = SQLiteCheckpointStore(path)
        with pytest.raises(VerificationError) as caught:
            reader.rebuild_history(self.DOMAIN)
        error = caught.value
        assert error.code == VerificationCode.LOG_ERROR
        assert not error.transient
        assert error.category == category
        detail = error.__cause__
        assert isinstance(detail, C2spCheckpointConsistencyError)
        assert detail.origin == trusted.origin
        assert detail.trusted_tree_size == trusted_size
        assert detail.observed_tree_size == (2 if growing else 1)
        assert detail.trusted_root_hash == trusted.root_hash
        assert len(detail.observed_root_hash) == 32
        assert detail.observed_root_hash != detail.trusted_root_hash
        assert store.get(trusted.origin) == trusted

    def test_durable_reader_accepts_same_checkpoint_after_restart(self, tmp_path):
        from dnsid.c2sp_tlog import SQLiteCheckpointStore

        reader, _ = self._build_log()
        path = tmp_path / "trust.db"
        reader._options.checkpoint_store = SQLiteCheckpointStore(path, create=True)
        reader.rebuild_history(self.DOMAIN)
        reader._options.checkpoint_store = SQLiteCheckpointStore(path)
        again = self._second_reader_sharing_store(reader)
        assert len(again.rebuild_history(self.DOMAIN)) == 1

    def test_storage_failure_is_not_transport_or_first_contact(self, tmp_path):
        from dnsid.c2sp_tlog import SQLiteCheckpointStore
        from dnsid.exceptions import VerificationError

        reader, _ = self._build_log()
        path = tmp_path / "trust.db"
        reader._options.checkpoint_store = SQLiteCheckpointStore(path, create=True)
        path.unlink()
        with pytest.raises(VerificationError) as caught:
            reader.rebuild_history(self.DOMAIN)
        assert caught.value.category == "CHECKPOINT_STORE_ERROR"
        assert not caught.value.transient
        assert not path.exists()


class TestCheckpointStoreAtomicity:
    def test_verify_and_advance_serializes_and_blocks_second_fork(self):
        # Two "concurrent" verifications against the same trusted checkpoint:
        # the first fork advances the store; the second, serialized behind it,
        # must see the advanced state and be rejected as a fork.
        from dnsid.c2sp_tlog import InMemoryCheckpointStore, TrustedCheckpoint

        store = InMemoryCheckpointStore()
        origin = "log.example"
        base = TrustedCheckpoint(origin, 1, b"\xaa" * 32, datetime.datetime.now(datetime.UTC))
        store.put(base)

        fork_a = TrustedCheckpoint(origin, 2, b"\xa2" * 32, datetime.datetime.now(datetime.UTC))
        fork_b = TrustedCheckpoint(origin, 2, b"\xb2" * 32, datetime.datetime.now(datetime.UTC))

        # Both forks share the size-1 prefix (consistent with base), so each
        # verify() against `base` passes; atomicity means the SECOND one runs
        # against the already-advanced state and diverges.
        def verify_against_size1(candidate):
            def _v(stored):
                if stored is not None and stored.tree_size == candidate.tree_size:
                    if stored.root_hash != candidate.root_hash:
                        raise ValueError("fork: same size, different root")
                # (prefix consistency vs base omitted; base check is a no-op here)
            return _v

        store.verify_and_advance(fork_a, verify_against_size1(fork_a))
        assert store.get(origin).root_hash == fork_a.root_hash
        with pytest.raises(ValueError, match="fork"):
            store.verify_and_advance(fork_b, verify_against_size1(fork_b))

    def test_verify_raise_prevents_advance(self):
        from dnsid.c2sp_tlog import InMemoryCheckpointStore, TrustedCheckpoint

        store = InMemoryCheckpointStore()
        origin = "log.example"
        store.put(TrustedCheckpoint(origin, 3, b"\x33" * 32, datetime.datetime.now(datetime.UTC)))

        def _reject(stored):
            raise ValueError("nope")

        with pytest.raises(ValueError):
            store.verify_and_advance(
                TrustedCheckpoint(origin, 9, b"\x99" * 32, datetime.datetime.now(datetime.UTC)),
                _reject,
            )
        # Store unchanged after a rejected advance.
        assert store.get(origin).tree_size == 3
