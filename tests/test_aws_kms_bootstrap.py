"""Independent #62 A-J acceptance tests from the clean declaration contract.

All KMS dependencies are fake; cryptographic expectations are independently
computed with cryptography/hashlib, never SDK private helpers. No lifecycle
claim is made about eventual disposition of losing or ambiguous resources.
"""

import base64
import hashlib
import json
import threading
from collections import Counter
from uuid import UUID

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils

from dnsid import (
    ArgumentError,
    AwsKmsBootstrapConfig,
    AwsKmsBootstrapFacade,
    AwsKmsBootstrapResult,
    AwsKmsConfig,
    AwsKmsKeyProvider,
    create_or_reuse_aws_kms_key_provider,
)

ALGORITHMS = ["ECDSA_SHA_256", "ED25519_SHA_512"]
SPECS = {"ECDSA_SHA_256": "ECC_NIST_P256", "ED25519_SHA_512": "ECC_NIST_EDWARDS25519"}
ALIAS = "alias/dnsid/Org/Agent"
PAYLOAD = b"independent caller-visible bootstrap proof"


class NativeNotFound(Exception):
    pass


class NativeAlreadyExists(Exception):
    pass


# Deliberately unrelated classes with the service spelling: names are not types.
UnrelatedNotFound = type("NotFoundException", (Exception,), {})
UnrelatedConflict = type("AlreadyExistsException", (Exception,), {})


def outcome(action):
    """Keep consumer outcome assertions RED even against the declaration stub."""
    try:
        return action(), None
    except Exception as error:
        return None, error


def bootstrap(client, algorithm, alias=ALIAS):
    return outcome(lambda: create_or_reuse_aws_kms_key_provider(
        client, AwsKmsBootstrapConfig(alias_name=alias, algorithm=algorithm)
    ))


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def material(private):
    public = private.public_key()
    if isinstance(private, ed25519.Ed25519PrivateKey):
        return {"crv": "Ed25519", "kty": "OKP", "x": b64(public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
    numbers = public.public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64(numbers.x.to_bytes(32, "big")),
            "y": b64(numbers.y.to_bytes(32, "big"))}


def thumbprint(private):
    canonical = json.dumps(material(private), sort_keys=True, separators=(",", ":")).encode()
    return b64(hashlib.sha256(canonical).digest())


def verify(private, signature):
    public = private.public_key()
    if isinstance(private, ed25519.Ed25519PrivateKey):
        assert len(signature) == 64
        public.verify(signature, PAYLOAD)
    else:
        assert len(signature) == 64
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                         int.from_bytes(signature[32:], "big"))
        public.verify(der, PAYLOAD, ec.ECDSA(hashes.SHA256()))


class Kms(AwsKmsBootstrapFacade):
    """A synchronous service ledger with native typed exceptions and real keys."""

    not_found_exception = NativeNotFound
    already_exists_exception = NativeAlreadyExists

    def __init__(self, algorithm):
        self.algorithm = algorithm
        self.keys = {}
        self.aliases = {}
        self.calls = []
        self.hook = None
        self.created_id = "normal"
        self.lock = threading.RLock()
        self.read_barrier = None
        self.acquired = threading.Event()
        self.winner_thread = None

    def record(self, operation, *args):
        with self.lock:
            self.calls.append((threading.current_thread().name, operation, *args))
        if self.hook:
            replacement = self.hook(operation, *args)
            if replacement is not None:
                return replacement
        return None

    def seed(self, ref=None):
        with self.lock:
            ref = ref or str(UUID(int=len(self.keys) + 1))
            private = (ec.generate_private_key(ec.SECP256R1())
                       if self.algorithm == "ECDSA_SHA_256" else ed25519.Ed25519PrivateKey.generate())
            self.keys[ref] = private
            return ref

    def response(self, ref):
        return {"key_id": ref, "public_key": self.keys[ref].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            "key_spec": SPECS[self.algorithm], "key_usage": "SIGN_VERIFY",
            "signing_algorithms": [self.algorithm]}

    def get_public_key(self, key_id):
        replacement = self.record("read", key_id)
        if replacement is not None:
            return replacement
        with self.lock:
            ref = self.aliases.get(key_id, key_id)
            missing = ref not in self.keys
        if missing:
            if self.read_barrier and key_id == ALIAS:
                self.read_barrier.wait(timeout=3)
            raise NativeNotFound(key_id)
        return self.response(ref)

    def create_signing_key(self, key_spec, description=None, tags=None):
        self.record("create", key_spec, description, tags)
        assert key_spec == SPECS[self.algorithm]
        assert description is None and tags is None
        ref = self.seed()
        return ref if self.created_id == "normal" else self.created_id

    def create_alias(self, alias_name, target_key_id):
        self.record("acquire", alias_name, target_key_id)
        if self.winner_thread and threading.current_thread().name != self.winner_thread:
            assert self.acquired.wait(timeout=3), "winner did not acquire within finite wait"
        with self.lock:
            if alias_name in self.aliases:
                raise NativeAlreadyExists(alias_name)
            assert target_key_id in self.keys
            self.aliases[alias_name] = target_key_id
        self.acquired.set()

    def sign(self, key_id, message, signing_algorithm, message_type):
        self.record("sign", key_id, signing_algorithm, message_type)
        private = self.keys[key_id]
        if isinstance(private, ed25519.Ed25519PrivateKey):
            assert message_type == "RAW"
            signature = private.sign(message)
        else:
            digest = hashes.SHA256() if message_type == "RAW" else utils.Prehashed(hashes.SHA256())
            signature = private.sign(message, ec.ECDSA(digest))
        return {"key_id": key_id, "signature": signature, "signing_algorithm": signing_algorithm}

    def schedule_key_deletion(self, *args, **kwargs):
        self.record("schedule", args, kwargs)
        raise AssertionError("bootstrap must not schedule retirement")

    def delete_key(self, *args, **kwargs):
        self.record("delete", args, kwargs)
        raise AssertionError("bootstrap must not delete")

    def disable_key(self, *args, **kwargs):
        self.record("disable", args, kwargs)
        raise AssertionError("bootstrap must not disable")

    def update_alias(self, *args, **kwargs):
        self.record("retarget", args, kwargs)
        raise AssertionError("bootstrap must not retarget")

    def count(self, operation):
        return sum(call[1] == operation for call in self.calls)

    def alias_reads(self):
        return sum(call[1:3] == ("read", ALIAS) for call in self.calls)


def safe_ledger(client):
    assert {call[1] for call in client.calls} <= {"read", "create", "acquire", "sign"}


def usable(result, client, ref):
    assert isinstance(result, AwsKmsBootstrapResult)
    assert result.key_ref == ref
    provider = result.key_provider
    state = provider.state_snapshot()
    assert state.active_key_id == ref
    assert state.pending_key_ids == [] and state.retained_key_ids == []
    jwk = provider.signing_key()
    expected = material(client.keys[ref])
    public = jwk.to_dict()
    for name, value in expected.items():
        assert public[name] == value
    assert jwk.alg == ("ES256" if client.algorithm == "ECDSA_SHA_256" else "EdDSA")
    assert not {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}.intersection(public)
    assert jwk.kid == thumbprint(client.keys[ref]) and jwk.kid != ref
    assert provider.list_key_ids() == [jwk.kid]
    assert provider.jwk(jwk.kid) == jwk
    verify(client.keys[ref], provider.sign(PAYLOAD))
    verify(client.keys[ref], provider.sign_key(jwk.kid, PAYLOAD))
    safe_ledger(client)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_A_first_create_fresh_caller_and_canonical_open(algorithm):
    """Mode: real-capable. Given absence, when explicit bootstrap repeats, then reuse."""
    client = Kms(algorithm)
    first, error = bootstrap(client, algorithm)
    assert error is None, f"consumer expected a usable key result, got {error!r}"
    ref = first.key_ref
    usable(first, client, ref)
    assert client.count("create") == client.count("acquire") == 1
    assert client.alias_reads() == 2
    second, error = bootstrap(client, algorithm)
    assert error is None
    usable(second, client, ref)
    reopened = AwsKmsKeyProvider.load(client, AwsKmsConfig(active_key_id=ref, algorithm=algorithm))
    assert reopened.signing_key().kid == first.key_provider.signing_key().kid
    verify(client.keys[ref], reopened.sign(PAYLOAD))
    assert client.count("create") == client.count("acquire") == 1
    assert client.alias_reads() == 3


REFERENCES = [str(UUID(int=9)), "mrk-0123456789abcdef0123456789ABCDEF",
              "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000009",
              "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("ref", REFERENCES)
def test_B_existing_compatible_canonical_winner(algorithm, ref):
    """Mode: real-capable. Given a compatible alias, when opened, then no allocation."""
    client = Kms(algorithm)
    client.aliases[ALIAS] = client.seed(ref)
    result, error = bootstrap(client, algorithm)
    assert error is None, f"expected existing usable winner, got {error!r}"
    usable(result, client, ref)
    assert client.count("create") == client.count("acquire") == 0
    assert client.alias_reads() == 1


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("winner", ["replica-left", "replica-right"])
def test_C_both_controlled_winner_orders_and_later_fresh_caller(algorithm, winner):
    """Mode: fake-only. Given two absent reads, when acquisition races, then converge."""
    client = Kms(algorithm)
    client.read_barrier = threading.Barrier(2)
    client.winner_thread = winner
    results = {}
    def run():
        results[threading.current_thread().name] = bootstrap(client, algorithm)
    threads = [threading.Thread(target=run, name=name, daemon=True)
               for name in ("replica-left", "replica-right")]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
    finally:
        client.acquired.set()
        client.read_barrier.abort()
        for thread in threads:
            thread.join(timeout=4)
    assert all(not thread.is_alive() for thread in threads), "all owned threads must close"
    assert set(results) == {thread.name for thread in threads}
    assert all(error is None for _, error in results.values()), f"expected both successful: {results!r}"
    ref = client.aliases[ALIAS]
    for result, _ in results.values():
        usable(result, client, ref)
    candidates = [call[3] for call in client.calls if call[1] == "acquire" and call[0] == winner]
    assert candidates == [ref]
    loser = next(key for key in client.keys if key != ref)
    for result, _ in results.values():
        signature = result.key_provider.sign(PAYLOAD)
        with pytest.raises(InvalidSignature):
            verify(client.keys[loser], signature)
    counts = Counter((call[0], call[1]) for call in client.calls)
    for thread in threads:
        assert counts[thread.name, "create"] == counts[thread.name, "acquire"] == 1
        assert sum(call[0] == thread.name and call[1:3] == ("read", ALIAS)
                   for call in client.calls) == 2
    client.read_barrier = None
    later, error = bootstrap(client, algorithm)
    assert error is None
    usable(later, client, ref)
    assert client.count("create") == client.count("acquire") == 2
    safe_ledger(client)


ERROR_FACTORIES = [PermissionError, TimeoutError, RuntimeError, UnrelatedNotFound, UnrelatedConflict,
                   NativeNotFound, NativeAlreadyExists]


@pytest.mark.parametrize("stage,error_type", [
    (stage, error_type)
    for stage in ["initial", "create", "acquire", "winner", "canonical", "sign"]
    for error_type in ERROR_FACTORIES
    if not ((stage == "initial" and error_type is NativeNotFound)
            or (stage == "acquire" and error_type is NativeAlreadyExists))
])
def test_D_native_error_identity_by_stage(stage, error_type):
    """Mode: fake-only. Given a stage fault, when invoked, then preserve its identity."""
    client = Kms(ALGORITHMS[0])
    ref = client.seed()
    if stage in {"initial", "canonical", "sign"}:
        client.aliases[ALIAS] = ref
    fault = error_type("native sentinel")
    alias_reads = 0
    def hook(operation, *args):
        nonlocal alias_reads
        if operation == "read" and args[0] == ALIAS:
            alias_reads += 1
        hit = ((stage == "initial" and operation == "read" and alias_reads == 1)
               or (stage in {"create", "acquire", "sign"} and operation == stage)
               or (stage == "winner" and operation == "read" and args[0] == ALIAS and alias_reads == 2)
               or (stage == "canonical" and operation == "read" and args[0] == ref))
        if hit:
            raise fault
    client.hook = hook
    result, error = bootstrap(client, ALGORITHMS[0])
    if stage == "sign" and error is None:
        _, error = outcome(lambda: result.key_provider.sign(PAYLOAD))
    assert error is fault, f"expected exact native {stage} exception, got {error!r}"
    assert client.count("create") <= 1 and client.count("acquire") <= 1
    assert client.alias_reads() <= 2
    safe_ledger(client)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_E_response_loss_is_failed_attempt_then_explicit_recovery(algorithm):
    """Mode: fake-only. Given committed acquisition response loss, then no presumed success."""
    client = Kms(algorithm)
    fault = TimeoutError("response lost after commit")
    def hook(operation, *args):
        if operation == "acquire":
            client.aliases[args[0]] = args[1]
            raise fault
    client.hook = hook
    result, error = bootstrap(client, algorithm)
    assert result is None and error is fault, f"expected ambiguous native failure, got {error!r}"
    assert client.alias_reads() == 1
    assert client.count("create") == client.count("acquire") == 1
    safe_ledger(client)
    client.hook = None
    later, error = bootstrap(client, algorithm)
    assert error is None
    usable(later, client, client.aliases[ALIAS])
    assert client.count("create") == client.count("acquire") == 1


@pytest.mark.parametrize("fault_type", [NativeNotFound, PermissionError, TimeoutError])
def test_F_conflict_then_one_failed_winner_resolution(fault_type):
    """Mode: fake-only. Given conflict and unavailable winner, then fail without polling."""
    client = Kms(ALGORITHMS[0])
    fault = fault_type("winner unavailable")
    reads = 0
    def hook(operation, *args):
        nonlocal reads
        if operation == "acquire":
            raise NativeAlreadyExists("another caller won")
        if operation == "read" and args[0] == ALIAS:
            reads += 1
            if reads == 2:
                raise fault
    client.hook = hook
    result, error = bootstrap(client, ALGORITHMS[0])
    assert result is None and error is fault, f"expected native winner read failure, got {error!r}"
    assert client.alias_reads() == 2
    assert client.count("create") == client.count("acquire") == 1
    safe_ledger(client)


INVALID_REFS = [None, "", " ", "alias/dnsid/other", "arn:aws:kms:us-east-1:123456789012:alias/test",
                "arbitrary-service-string", "mrk-123", str(UUID(int=9)) + "#fragment"] + [
                    str(UUID(int=9)) + end for end in (" ", "\n", "\r", "\r\n", "\u2028", "\u2029")]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("bad_ref", INVALID_REFS)
def test_G_invalid_returned_reference_is_not_normalized(algorithm, bad_ref):
    """Mode: fake-only. Given noncanonical remote identity, then ArgumentError, no replacement."""
    client = Kms(algorithm)
    ref = client.seed()
    def hook(operation, *args):
        if operation == "read":
            return dict(client.response(ref), key_id=bad_ref)
    client.hook = hook
    result, error = bootstrap(client, algorithm)
    assert result is None and isinstance(error, ArgumentError), f"expected ArgumentError, got {error!r}"
    assert client.count("create") == client.count("acquire") == 0
    safe_ledger(client)


@pytest.mark.parametrize("bad_ref", [None, "", " ", "alias/invalid", str(UUID(int=3)) + "\n"])
def test_G_invalid_candidate_id_never_acquires(bad_ref):
    """Mode: fake-only. Given invalid creation ID, then no alias acquisition."""
    client = Kms(ALGORITHMS[0])
    client.created_id = bad_ref
    result, error = bootstrap(client, ALGORITHMS[0])
    assert result is None and isinstance(error, ArgumentError), f"expected ArgumentError, got {error!r}"
    assert client.count("create") == 1 and client.count("acquire") == 0
    safe_ledger(client)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("defect", ["usage", "spec", "advertised", "malformed", "wrong-type", "wrong-curve",
                                    "other-algorithm", "cross-id", "cross-material"])
def test_G_remote_metadata_spki_and_cross_read_binding(algorithm, defect):
    """Mode: fake-only. Given incompatible remote evidence, then reject rather than substitute."""
    client = Kms(algorithm)
    ref, other = client.seed(), client.seed()
    client.aliases[ALIAS] = ref
    def hook(operation, *args):
        if operation != "read":
            return None
        response = client.response(ref)
        if defect == "usage":
            response["key_usage"] = "ENCRYPT_DECRYPT"
        elif defect == "spec":
            response["key_spec"] = "RSA_2048"
        elif defect == "advertised":
            response["signing_algorithms"] = []
        elif defect == "malformed":
            response["public_key"] = b"not DER SPKI"
        elif defect in {"wrong-type", "wrong-curve", "other-algorithm"}:
            private = (rsa.generate_private_key(public_exponent=65537, key_size=2048)
                       if defect == "wrong-type" else ec.generate_private_key(ec.SECP384R1())
                       if defect == "wrong-curve" else ed25519.Ed25519PrivateKey.generate()
                       if algorithm == "ECDSA_SHA_256" else ec.generate_private_key(ec.SECP256R1()))
            response["public_key"] = private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        elif args[0] != ALIAS:
            if defect == "cross-id":
                response["key_id"] = other
            else:
                response["public_key"] = client.response(other)["public_key"]
        return response
    client.hook = hook
    result, error = bootstrap(client, algorithm)
    assert result is None and isinstance(error, ArgumentError), f"expected binding rejection, got {error!r}"
    assert client.count("create") == client.count("acquire") == 0
    assert client.alias_reads() == 1
    safe_ledger(client)


INVALID_ALIASES = [None, 123, "", " ", "dnsid/agent", "alias/", "alias/aws/reserved", "alias/a#b",
                   " " + ALIAS] + [ALIAS + end for end in (" ", "\n", "\r", "\r\n", "\u2028", "\u2029")]


@pytest.mark.parametrize("alias", INVALID_ALIASES)
def test_H_invalid_alias_rejected_before_any_dependency(alias):
    """Mode: real-capable. Given invalid alias, when bootstrap, then reject before calls."""
    client = Kms(ALGORITHMS[0])
    result, error = bootstrap(client, ALGORITHMS[0], alias)
    assert result is None and isinstance(error, ArgumentError), f"expected input rejection, got {error!r}"
    assert client.calls == []


@pytest.mark.parametrize("algorithm", [None, "", "ES256", "EdDSA", "ECDSA_SHA_384", 123])
def test_H_invalid_algorithm_rejected_before_any_dependency(algorithm):
    """Mode: real-capable. Given invalid algorithm, then no downgrade or dependency calls."""
    client = Kms(ALGORITHMS[0])
    result, error = bootstrap(client, algorithm)
    assert result is None and isinstance(error, ArgumentError), f"expected input rejection, got {error!r}"
    assert client.calls == []


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_H_distinct_exact_aliases_stay_distinct(algorithm):
    """Mode: real-capable. Given distinct exact aliases, then allocate separate identities."""
    client = Kms(algorithm)
    aliases = [ALIAS, "alias/dnsid/org/agent"]
    refs = []
    for alias in aliases:
        result, error = bootstrap(client, algorithm, alias)
        assert error is None, f"expected exact alias success, got {error!r}"
        usable(result, client, client.aliases[alias])
        refs.append(result.key_ref)
    assert refs[0] != refs[1]
    assert [call[2] for call in client.calls if call[1] == "acquire"] == aliases
    safe_ledger(client)


def test_H_additional_service_alias_restriction_is_native():
    """Mode: fake-only. Given AWS rejects an extra restriction, then preserve native error."""
    client = Kms(ALGORITHMS[0])
    fault = RuntimeError("service alias restriction")
    def hook(operation, *args):
        if operation == "acquire":
            raise fault
    client.hook = hook
    _, error = bootstrap(client, ALGORITHMS[0], "alias/dnsid/service!restriction")
    assert error is fault, f"expected native service rejection, got {error!r}"
    safe_ledger(client)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_J_ordinary_missing_open_remains_existing_only(algorithm):
    """Mode: real-capable. Given missing ordinary key, when load, then fail without create."""
    client = Kms(algorithm)
    fault = NativeNotFound("ordinary missing")
    def hook(operation, *args):
        if operation == "read":
            raise fault
    client.hook = hook
    result, error = outcome(lambda: AwsKmsKeyProvider.load(
        client, AwsKmsConfig(active_key_id=str(UUID(int=99)), algorithm=algorithm)))
    assert result is None and error is fault
    assert client.count("create") == client.count("acquire") == 0
    safe_ledger(client)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_J_explicit_generation_is_fresh_pending_without_switching_signer(algorithm):
    """Mode: real-capable. Given ordinary open, when generate, then fresh pending only."""
    client = Kms(algorithm)
    ref = client.seed()
    provider = AwsKmsKeyProvider.load(client, AwsKmsConfig(active_key_id=ref, algorithm=algorithm))
    original = provider.signing_key()
    pending = [provider.generate_key(), provider.generate_key()]
    assert len({original.kid, *pending}) == 3
    assert provider.signing_key() == original
    assert provider.list_key_ids() == [original.kid]
    state = provider.state_snapshot()
    assert state.active_key_id == ref and state.retained_key_ids == []
    assert len(state.pending_key_ids) == 2 and ref not in state.pending_key_ids
    for kid in pending:
        pending_ref = next(key for key in client.keys if thumbprint(client.keys[key]) == kid)
        assert provider.jwk(kid).kid == kid
        verify(client.keys[pending_ref], provider.sign_key(kid, PAYLOAD))
    verify(client.keys[ref], provider.sign(PAYLOAD))
    assert client.count("create") == 2 and client.count("acquire") == 0
    safe_ledger(client)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_I_standalone_key_bootstrap_never_constructs_publication_authority(algorithm, monkeypatch):
    """Mode: fake-only. Given key-only bootstrap, then no implicit manager/registry flow."""
    from dnsid import IdentityManager, RegistryClient

    publication_calls = []
    def forbidden(*args, **kwargs):
        publication_calls.append((args, kwargs))
        raise AssertionError("key bootstrap has no implicit publication authority")
    monkeypatch.setattr(IdentityManager, "__init__", forbidden)
    monkeypatch.setattr(RegistryClient, "__init__", forbidden)
    client = Kms(algorithm)
    result, error = bootstrap(client, algorithm)
    assert error is None, f"expected standalone key success, got {error!r}"
    usable(result, client, client.aliases[ALIAS])
    assert publication_calls == []
    safe_ledger(client)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_A_successful_acquisition_resolves_actual_winner_not_candidate(algorithm):
    """Mode: fake-only. Given acquired alias resolves elsewhere, then return validated winner."""
    client = Kms(algorithm)
    winner = client.seed()
    def hook(operation, *args):
        if operation == "acquire":
            # Alias acquisition accepted, but subsequent service evidence is
            # authoritative: never presume the candidate's unvalidated identity.
            client.aliases[args[0]] = winner
    client.hook = hook
    # Override only the fake service action, not any SDK behavior.
    def acquired(alias_name, target_key_id):
        client.record("acquire", alias_name, target_key_id)
    client.create_alias = acquired
    result, error = bootstrap(client, algorithm)
    assert error is None, f"expected resolved usable winner, got {error!r}"
    usable(result, client, winner)
    assert client.alias_reads() == 2
    assert client.count("create") == client.count("acquire") == 1
    loser = next(key for key in client.keys if key != winner)
    with pytest.raises(InvalidSignature):
        verify(client.keys[loser], result.key_provider.sign(PAYLOAD))
    safe_ledger(client)
