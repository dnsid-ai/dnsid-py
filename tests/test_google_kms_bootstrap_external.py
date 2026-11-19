"""Named-key bootstrap validates and reuses the initial Google signing identity.

All dependencies are fake. No product-private imports or observed expectations.
Ordinary opening, generation and rotation have separate regression tests.
"""

import base64
import hashlib
import json
import threading
from concurrent.futures import CancelledError
from dataclasses import FrozenInstanceError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from google.api_core import exceptions as gexc
from google.cloud import kms_v1

from dnsid import (
    ArgumentError,
    GoogleKmsBootstrapResult,
    GoogleKmsKeyProvider,
    create_or_reuse_google_kms_key_provider,
)

PARENT = "projects/project-A/locations/global/keyRings/ring-A"
KEY_ID = "Agent_01-key"
PAYLOAD = b"known62 independent application payload\x00\xff"
ALGORITHM = kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519
SOFTWARE = kms_v1.ProtectionLevel.SOFTWARE
PURPOSE = kms_v1.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN
ENABLED = kms_v1.CryptoKeyVersion.CryptoKeyVersionState.ENABLED
ROUTES = ("reuse", "create", "winner")
TIMEOUT = 5


def crc32c(data):
    """Test-owned reflected Castagnoli CRC, independent of product/helpers."""
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def field(request, name):
    """Accept official request messages and equivalent request dictionaries."""
    return request.get(name) if isinstance(request, dict) else getattr(request, name)


def private_key(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


class Material:
    def __init__(self, parent=PARENT, key_id=KEY_ID, seed=17):
        self.parent = parent
        self.key_id = key_id
        self.name = f"{parent}/cryptoKeys/{key_id}"
        self.version = f"{self.name}/cryptoKeyVersions/1"
        self.private = private_key(seed)
        self.public = self.private.public_key()
        self.pem = self.public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.x = b64url(self.public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        canonical = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": self.x},
            sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        self.kid = b64url(hashlib.sha256(canonical).digest())

    def key(self):
        # Deliberately advertise a different mutable primary. It is not identity.
        return kms_v1.CryptoKey(
            name=self.name, purpose=PURPOSE,
            version_template=kms_v1.CryptoKeyVersionTemplate(
                algorithm=ALGORITHM, protection_level=SOFTWARE,
            ),
            primary=kms_v1.CryptoKeyVersion(name=f"{self.name}/cryptoKeyVersions/8"),
        )

    def metadata(self):
        return kms_v1.CryptoKeyVersion(
            name=self.version, state=ENABLED,
            algorithm=ALGORITHM, protection_level=SOFTWARE,
        )

    def public_response(self):
        return kms_v1.PublicKey(
            name=self.version, pem=self.pem, algorithm=ALGORITHM,
            protection_level=SOFTWARE, pem_crc32c=crc32c(self.pem.encode("ascii")),
        )


class FakeKms:
    """Synchronous remote boundary; nothing outside five allowed methods is usable.

    Repeated required reads are permitted, without prescribing incidental order.
    Route 'winner' represents a competing creator committing after our miss.
    """

    def __init__(self, route="reuse", material=None):
        self.material = material or Material()
        self.route = route
        self.exists = route == "reuse"
        self.calls = []
        self.creates = 0
        self.closed = 0
        self.exited = 0
        self.faults = {}
        self.corruption = None
        self.sign_corruption = None
        self.uncertain = None
        self.initial_reads = 0
        self.lock = threading.RLock()
        self.barrier = None
        self.local = threading.local()

    def __getattr__(self, name):
        raise AssertionError(f"Forbidden/unrequired client operation: {name}")

    def close(self):
        self.closed += 1
        raise AssertionError("Injected client belongs to caller")

    def __enter__(self):
        raise AssertionError("Bootstrap must not enter caller client context")

    def __exit__(self, *args):
        self.exited += 1
        raise AssertionError("Bootstrap must not exit caller client context")

    def record(self, stage, request):
        with self.lock:
            self.calls.append((stage, request))
        if stage in self.faults:
            raise self.faults[stage]

    def reply(self, stage, message):
        if self.corruption and self.corruption[0] == stage:
            return corrupt(message, self.corruption[1], self.material)
        return message

    def get_crypto_key(self, *, request):
        assert field(request, "name") == self.material.name
        # Each concurrent caller observes absence BEFORE any named creation.
        if self.barrier is not None and not getattr(self.local, "looked", False):
            self.local.looked = True
            self.record("lookup", request)
            self.barrier.wait(timeout=TIMEOUT)
            raise gexc.NotFound("exact named key absent")
        stage = "winner" if self.creates else "lookup"
        self.record(stage, request)
        self.initial_reads += 1
        if not self.exists:
            raise gexc.NotFound("exact named key absent")
        # Create-route corruption applies only to the successful create return.
        if self.route == "create":
            return self.material.key()
        return self.reply("key", self.material.key())

    def create_crypto_key(self, *, request):
        self.record("create", request)
        assert field(request, "parent") == self.material.parent
        assert field(request, "crypto_key_id") == self.material.key_id
        typed = kms_v1.CreateCryptoKeyRequest(request) if isinstance(request, dict) else request
        assert typed.crypto_key.purpose == PURPOSE
        assert typed.crypto_key.version_template.algorithm == ALGORITHM
        assert typed.crypto_key.version_template.protection_level == SOFTWARE
        assert typed.skip_initial_version_creation is False
        assert not kms_v1.CryptoKey.pb(typed.crypto_key).HasField("rotation_period")
        assert not kms_v1.CryptoKey.pb(typed.crypto_key).HasField("next_rotation_time")
        with self.lock:
            self.creates += 1
            if self.exists:
                raise gexc.AlreadyExists("concurrent named winner")
            self.exists = True
            if self.uncertain is not None:
                raise self.uncertain
            if self.route == "winner":
                raise gexc.AlreadyExists("other caller committed")
            return self.reply("key", self.material.key())

    def get_crypto_key_version(self, *, request):
        self.record("version", request)
        assert field(request, "name") == self.material.version
        return self.reply("version", self.material.metadata())

    def get_public_key(self, *, request):
        self.record("public", request)
        assert field(request, "name") == self.material.version
        return self.reply("public", self.material.public_response())

    def asymmetric_sign(self, *, request):
        self.record("sign", request)
        assert field(request, "name") == self.material.version
        data = field(request, "data")
        typed = kms_v1.AsymmetricSignRequest(request) if isinstance(request, dict) else request
        assert kms_v1.AsymmetricSignRequest.pb(typed).HasField("data_crc32c")
        assert typed.data_crc32c == crc32c(data)
        signature = self.material.private.sign(data)
        response = kms_v1.AsymmetricSignResponse(
            name=self.material.version, signature=signature,
            signature_crc32c=crc32c(signature), verified_data_crc32c=True,
            protection_level=SOFTWARE,
        )
        if self.sign_corruption:
            return corrupt(response, self.sign_corruption, self.material)
        return response


class InvalidInputReadKms(FakeKms):
    """Record any invalid-input dependency call so zero-call checks expose it."""

    def get_crypto_key(self, *, request):
        self.record("lookup", request)
        return self.material.key()

    def get_crypto_key_version(self, *, request):
        self.record("version", request)
        return self.material.metadata()

    def get_public_key(self, *, request):
        self.record("public", request)
        return self.material.public_response()

    def create_crypto_key(self, *, request):
        self.creates += 1
        self.record("forbidden-create", request)
        raise AssertionError("Invalid arguments must not mutate resources")

    def asymmetric_sign(self, *, request):
        self.record("forbidden-sign", request)
        raise AssertionError("Invalid arguments must not yield a usable signer")

    def __getattr__(self, name):
        self.record("forbidden-operation", name)
        raise AssertionError(f"Forbidden/unrequired client operation: {name}")


def bootstrap(client):
    return create_or_reuse_google_kms_key_provider(
        client, parent=client.material.parent, crypto_key_id=client.material.key_id,
    )


def assert_owned(client):
    assert client.closed == 0
    assert client.exited == 0


def assert_usable(result, client):
    assert isinstance(result, GoogleKmsBootstrapResult)
    assert result.key_version_name == client.material.version
    assert isinstance(result.provider, GoogleKmsKeyProvider)
    jwk = result.provider.signing_key().to_dict()
    # Public JWK dictionary and RFC 7638 ID, not cloud reference as kid.
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["x"] == client.material.x
    assert jwk["kid"] == client.material.kid
    assert "d" not in jwk
    assert jwk["kid"] != result.key_version_name
    assert result.provider.list_key_ids() == [client.material.kid]
    assert result.provider.jwk(client.material.kid).to_dict() == jwk
    for signature in (
        result.provider.sign(PAYLOAD),
        result.provider.sign_key(client.material.kid, PAYLOAD),
    ):
        assert isinstance(signature, bytes)
        client.material.public.verify(signature, PAYLOAD)
    assert_owned(client)


def assert_no_repair(client):
    assert client.creates <= (0 if client.route == "reuse" else 1)
    assert not any(stage == "sign" for stage, _ in client.calls)
    assert_owned(client)


def test_fixture_crc32c_known_castagnoli_vector():
    """GIVEN a published CRC vector WHEN evaluated THEN fixtures use Castagnoli."""
    assert crc32c(b"123456789") == 0xE3069283
    assert crc32c(b"") == 0


def test_case1_absent_named_key_and_fresh_existing_reference():
    """Mode: real-capable. GIVEN absence WHEN bootstrap THEN usable version 1."""
    client = FakeKms("create")
    result = None
    error = None
    # Capture only this expected-success operation, not imports or fixture setup.
    try:
        result = bootstrap(client)
    except CancelledError:
        raise
    except Exception as caught:
        error = caught
    assert error is None, f"Expected successful bootstrap; got {type(error).__name__}: {error!r}"
    assert_usable(result, client)
    assert client.creates == 1
    again = bootstrap(client)
    assert_usable(again, client)
    assert client.creates == 1
    ordinary = GoogleKmsKeyProvider(client, result.key_version_name)
    client.material.public.verify(ordinary.sign(PAYLOAD), PAYLOAD)
    assert ordinary.signing_key().to_dict() == result.provider.signing_key().to_dict()
    with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
        result.key_version_name = "replacement"


def test_case2_fresh_reuse_preserves_public_identity_without_create():
    """Mode: real-capable. GIVEN version 1 WHEN repeated opens THEN stable identity."""
    material = Material()
    first = FakeKms(material=material)
    second = FakeKms(material=material)
    left, right = bootstrap(first), bootstrap(second)
    assert_usable(left, first)
    assert_usable(right, second)
    assert left.key_version_name == right.key_version_name
    assert left.provider.signing_key().to_dict() == right.provider.signing_key().to_dict()
    assert first.creates == second.creates == 0


def test_case3_deterministic_named_creation_race():
    """Mode: fake-only. GIVEN simultaneous misses WHEN creates race THEN one identity."""
    count = 4
    client = FakeKms("create")
    client.barrier = threading.Barrier(count)
    results, failures = [], []
    finished = [threading.Event() for _ in range(count)]

    def worker(index):
        try:
            value = bootstrap(client)
            with client.lock:
                results.append(value)
        except BaseException as error:
            with client.lock:
                failures.append(error)
        finally:
            finished[index].set()

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(count)]
    try:
        for thread in threads:
            thread.start()
        for done in finished:
            assert done.wait(TIMEOUT), "bounded concurrent bootstrap did not finish"
    finally:
        client.barrier.abort()
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=TIMEOUT)
    assert not any(thread.is_alive() for thread in threads)
    assert failures == []
    assert len(results) == count
    assert client.creates == count
    assert sum(stage == "winner" for stage, _ in client.calls) >= count - 1
    for result in results:
        assert_usable(result, client)
    fresh = FakeKms(material=client.material)
    assert_usable(bootstrap(fresh), fresh)
    assert fresh.creates == 0


ERROR_TYPES = (
    gexc.PermissionDenied, gexc.Unauthenticated, gexc.ServiceUnavailable,
    gexc.DeadlineExceeded, gexc.InternalServerError, gexc.Cancelled,
    gexc.Conflict, gexc.Forbidden, RuntimeError, CancelledError,
)
ERROR_STAGES = ("lookup", "create", "winner", "version", "public")


@pytest.mark.parametrize("error_type", ERROR_TYPES)
@pytest.mark.parametrize("stage", ERROR_STAGES)
def test_case4_native_error_identity(stage, error_type):
    """Mode: fake-only. GIVEN native error WHEN bootstrap THEN same exception escapes."""
    route = "winner" if stage == "winner" else "create" if stage == "create" else "reuse"
    client = FakeKms(route)
    error = error_type("NotFound AlreadyExists 404 409 misleading error text")
    client.faults[stage] = error
    with pytest.raises(error_type) as caught:
        bootstrap(client)
    assert caught.value is error
    assert_no_repair(client)
    assert sum(item[0] == stage for item in client.calls) == 1
    if stage == "lookup":
        assert client.creates == 0
    if stage == "create":
        assert not any(item[0] == "winner" for item in client.calls)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("stage", ("version", "public"))
def test_case4_child_not_found_never_authorizes_creation(route, stage):
    """Mode: fake-only. GIVEN absent version/public WHEN read THEN fail without repair."""
    client = FakeKms(route)
    error = gexc.NotFound("missing immutable child")
    client.faults[stage] = error
    with pytest.raises(gexc.NotFound) as caught:
        bootstrap(client)
    assert caught.value is error
    assert_no_repair(client)


def test_case5_uncertain_commit_is_failure_then_separate_explicit_reuse():
    """Mode: fake-only. GIVEN commit then timeout WHEN fresh call THEN reuse committed key."""
    client = FakeKms("create")
    error = gexc.DeadlineExceeded("commit outcome not reported")
    client.uncertain = error
    with pytest.raises(gexc.DeadlineExceeded) as caught:
        bootstrap(client)
    assert caught.value is error
    assert client.exists
    assert client.creates == 1
    assert [stage for stage, _ in client.calls].count("create") == 1
    assert not any(stage in ("winner", "version", "public") for stage, _ in client.calls)
    assert_owned(client)
    # Separate explicit operation, not an implicit retry hidden in first result.
    later = FakeKms(material=client.material)
    assert_usable(bootstrap(later), later)
    assert later.creates == 0


def corrupt(message, defect, material):
    """Only mutate test-owned official responses, never product objects."""
    if defect == "none":
        return None
    if defect == "empty-message":
        return type(message)()
    if defect == "missing-name":
        type(message).pb(message).ClearField("name")
    elif defect == "empty-name":
        message.name = ""
    elif defect == "wrong-parent":
        message.name = message.name.replace("project-A", "other-project")
    elif defect == "wrong-version":
        message.name = f"{material.name}/cryptoKeyVersions/2"
    elif defect == "mutable-name":
        message.name = f"{material.name}/cryptoKeyVersions/latest"
    elif defect == "wrong-key-name":
        message.name = f"{material.parent}/cryptoKeys/other"
    elif defect == "absent-template":
        type(message).pb(message).ClearField("version_template")
    elif defect.startswith("template-algorithm:"):
        message.version_template.algorithm = int(defect.split(":")[1])
    elif defect.startswith("template-protection:"):
        message.version_template.protection_level = int(defect.split(":")[1])
    elif defect.startswith("purpose:"):
        message.purpose = int(defect.split(":")[1])
    elif defect.startswith("state:"):
        message.state = int(defect.split(":")[1])
    elif defect.startswith("algorithm:"):
        message.algorithm = int(defect.split(":")[1])
    elif defect.startswith("protection:"):
        message.protection_level = int(defect.split(":")[1])
    elif defect == "absent-crc":
        field_name = "pem_crc32c" if isinstance(message, kms_v1.PublicKey) else "signature_crc32c"
        type(message).pb(message).ClearField(field_name)
    elif defect == "mismatched-crc":
        field_name = "pem_crc32c" if isinstance(message, kms_v1.PublicKey) else "signature_crc32c"
        setattr(message, field_name, getattr(message, field_name) ^ 1)
    elif defect.startswith("crc:"):
        field_name = "pem_crc32c" if isinstance(message, kms_v1.PublicKey) else "signature_crc32c"
        setattr(message, field_name, int(defect.split(":")[1]))
    elif defect.startswith("pem:"):
        kind = defect.split(":")[1]
        if kind == "empty":
            message.pem = ""
        elif kind == "malformed":
            message.pem = "-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n"
        elif kind == "private-pkcs8":
            message.pem = material.private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")
        elif kind == "rsa-spki":
            message.pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
        elif kind == "rsa-pkcs1":
            message.pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.PKCS1,
            ).decode("ascii")
        message.pem_crc32c = crc32c(message.pem.encode("ascii"))
    elif defect == "unverified-data":
        message.verified_data_crc32c = False
    elif defect.startswith("signature-length:"):
        message.signature = b"x" * int(defect.split(":")[1])
        message.signature_crc32c = crc32c(message.signature)
    else:
        raise AssertionError(f"Unknown fixture defect: {defect}")
    return message


KEY_DEFECTS = (
    "none", "empty-message", "missing-name", "empty-name", "wrong-parent",
    "wrong-key-name", "purpose:0", "purpose:1", "purpose:999",
    "absent-template", "template-algorithm:0", "template-algorithm:1",
    "template-algorithm:999", "template-protection:0", "template-protection:2",
    "template-protection:999",
)
# Enumerate every official declared non-enabled state, plus future unknown numeric.
VERSION_DEFECTS = (
    "none", "empty-message", "missing-name", "empty-name", "wrong-parent",
    "wrong-version", "mutable-name", "algorithm:0", "algorithm:1", "algorithm:999",
    "protection:0", "protection:2", "protection:999",
) + tuple(
    f"state:{int(state)}" for state in kms_v1.CryptoKeyVersion.CryptoKeyVersionState
    if state != ENABLED
) + ("state:999",)
PUBLIC_DEFECTS = (
    "none", "empty-message", "missing-name", "empty-name", "wrong-parent",
    "wrong-version", "mutable-name", "algorithm:0", "algorithm:1", "algorithm:999",
    "protection:0", "protection:2", "protection:999", "absent-crc",
    "crc:-1", "crc:4294967296", "mismatched-crc", "pem:empty", "pem:malformed",
    "pem:private-pkcs8", "pem:rsa-spki", "pem:rsa-pkcs1",
)
CORRUPTIONS = (
    [("key", value) for value in KEY_DEFECTS]
    + [("version", value) for value in VERSION_DEFECTS]
    + [("public", value) for value in PUBLIC_DEFECTS]
)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("stage,defect", CORRUPTIONS)
def test_case6_each_corrupt_response_on_every_success_route(route, stage, defect):
    """Mode: fake-only. GIVEN corrupt resource WHEN bootstrap THEN no provider/repair."""
    # Independently prove the same route with valid material before varying one response.
    baseline = FakeKms(route)
    assert_usable(bootstrap(baseline), baseline)
    client = FakeKms(route)
    client.corruption = (stage, defect)
    # Public bootstrap docs require ArgumentError for incompatible returned material.
    # Fixture assertions and unrelated crashes cannot satisfy this oracle.
    with pytest.raises(ArgumentError):
        bootstrap(client)
    assert_no_repair(client)


def test_case6_winner_disappears_without_recreate_loop():
    """Mode: fake-only. GIVEN AlreadyExists then NotFound WHEN reread THEN native failure."""
    client = FakeKms("winner")
    error = gexc.NotFound("winner no longer readable")
    client.faults["winner"] = error
    with pytest.raises(gexc.NotFound) as caught:
        bootstrap(client)
    assert caught.value is error
    assert client.creates == 1
    assert_no_repair(client)


def prepared_sign_response(material, defect):
    """Build and verify the intended defect before entering any rejection catch."""
    signature = material.private.sign(PAYLOAD)
    material.public.verify(signature, PAYLOAD)
    response = corrupt(kms_v1.AsymmetricSignResponse(
        name=material.version, signature=signature,
        signature_crc32c=crc32c(signature), verified_data_crc32c=True,
        protection_level=SOFTWARE,
    ), defect, material)
    expected_name = {
        "wrong-version": f"{material.name}/cryptoKeyVersions/2",
        "wrong-parent": material.version.replace("project-A", "other-project"),
        "empty-name": "",
    }.get(defect, material.version)
    assert response.name == expected_name
    assert response.verified_data_crc32c is (defect != "unverified-data")
    assert response.protection_level == SOFTWARE
    if defect.startswith("signature-length:"):
        length = int(defect.split(":")[1])
        assert response.signature == b"x" * length
        assert len(response.signature) == length
    else:
        assert response.signature == signature
        material.public.verify(response.signature, PAYLOAD)
    present = kms_v1.AsymmetricSignResponse.pb(response).HasField("signature_crc32c")
    assert present is (defect != "absent-crc")
    if defect == "absent-crc":
        assert response.signature_crc32c is None
    elif defect.startswith("crc:"):
        assert response.signature_crc32c == int(defect.split(":")[1])
        assert not 0 <= response.signature_crc32c <= 0xFFFFFFFF
    elif defect == "mismatched-crc":
        assert response.signature_crc32c == crc32c(response.signature) ^ 1
        assert response.signature_crc32c != crc32c(response.signature)
    else:
        assert response.signature_crc32c == crc32c(response.signature)
    return response


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("defect", (
    "wrong-version", "wrong-parent", "empty-name", "unverified-data", "absent-crc",
    "mismatched-crc", "crc:-1", "crc:4294967296", "signature-length:0",
    "signature-length:63", "signature-length:65",
))
@pytest.mark.parametrize("method", ("sign", "sign_key"))
def test_case6_sign_response_integrity(route, defect, method):
    """Mode: fake-only. GIVEN valid bootstrap WHEN signing response corrupt THEN fail."""
    client = FakeKms(route)
    result = bootstrap(client)
    assert_usable(result, client)
    response = prepared_sign_response(client.material, defect)
    requests = []
    delivered = []

    def deliver(*, request):
        # No assertions, crypto or protobuf work inside the rejection context.
        client.calls.append(("sign", request))
        requests.append(request)
        delivered.append(response)
        return response

    client.asymmetric_sign = deliver
    calls_before = len(client.calls)
    with pytest.raises(Exception) as caught:
        if method == "sign":
            result.provider.sign(PAYLOAD)
        else:
            result.provider.sign_key(client.material.kid, PAYLOAD)
    assert not isinstance(caught.value, (AssertionError, AttributeError, TypeError))
    assert len(delivered) == 1
    assert delivered[0] is response
    assert len(requests) == 1
    assert client.calls[calls_before:] == [("sign", requests[0])]
    request = requests[0]
    assert field(request, "name") == client.material.version
    assert field(request, "data") == PAYLOAD
    typed = kms_v1.AsymmetricSignRequest(request) if isinstance(request, dict) else request
    assert kms_v1.AsymmetricSignRequest.pb(typed).HasField("data_crc32c")
    assert typed.data_crc32c == crc32c(PAYLOAD)
    assert_owned(client)


INVALID_PARENTS = (
    None, 1, False, b"projects/p/locations/l/keyRings/r", [], {}, "", " ",
    "projects//locations/l/keyRings/r", "projects/p/locations//keyRings/r",
    "projects/p/locations/l/keyRings/", "projects/p/locations/l/keyRings/r/",
    "projects/p/locations/l/keyRings/r/cryptoKeys/x", "projects/p/locations/l/keyRings/r#x",
    "projects/p/locations/l/keyRings/r/latest", " projects/p/locations/l/keyRings/r",
    "projects/p/locations/l/keyRings/r ", "projects/p/locations/l/keyRings/r\n",
    "projects/p\tt/locations/l/keyRings/r", "projects/p/locations/l/keyrings/r",
    "projects/p/locations/l/keyRings/r/cryptoKeyVersions/1",
)
INVALID_IDS = (
    None, 1, False, b"agent", [], {}, "", " ", " a", "a ", "a\n", "a\tb",
    "a/b", "a#b", "a.b", "a:b", "é", "a" * 64,
)


@pytest.mark.parametrize("parent", INVALID_PARENTS)
def test_case7_invalid_parent_before_mutation(parent):
    """Mode: real-capable. GIVEN invalid parent WHEN bootstrap THEN no dependency calls."""
    client = InvalidInputReadKms()
    with pytest.raises(ArgumentError):
        create_or_reuse_google_kms_key_provider(client, parent=parent, crypto_key_id=KEY_ID)
    assert client.creates == 0
    assert client.calls == []
    assert_owned(client)


@pytest.mark.parametrize("key_id", INVALID_IDS)
def test_case7_invalid_id_before_mutation(key_id):
    """Mode: real-capable. GIVEN invalid ID WHEN bootstrap THEN no dependency calls."""
    client = InvalidInputReadKms()
    with pytest.raises(ArgumentError):
        create_or_reuse_google_kms_key_provider(client, parent=PARENT, crypto_key_id=key_id)
    assert client.creates == 0
    assert client.calls == []
    assert_owned(client)


def test_case7_none_client_is_not_ambient_credentials():
    """Mode: real-capable. GIVEN None client WHEN bootstrap THEN ArgumentError."""
    with pytest.raises(ArgumentError):
        create_or_reuse_google_kms_key_provider(None, parent=PARENT, crypto_key_id=KEY_ID)


def test_case7_missing_ancestor_is_native_failure_not_ancestor_creation():
    """Mode: real-capable. GIVEN absent ring WHEN named create fails THEN native error."""
    client = FakeKms("create")
    error = gexc.NotFound("prerequisite key ring absent")
    client.faults["create"] = error
    with pytest.raises(gexc.NotFound) as caught:
        bootstrap(client)
    assert caught.value is error
    assert [stage for stage, _ in client.calls] == ["lookup", "create"]
    assert_owned(client)


def test_case7_each_scope_component_is_independently_significant():
    """Mode: real-capable. GIVEN five scopes WHEN bootstrap THEN five exact identities."""
    scopes = (
        (PARENT, KEY_ID),
        ("projects/project-B/locations/global/keyRings/ring-A", KEY_ID),
        ("projects/project-A/locations/us-east1/keyRings/ring-A", KEY_ID),
        ("projects/project-A/locations/global/keyRings/ring-B", KEY_ID),
        (PARENT, "other-ID"),
    )
    refs, kids = set(), set()
    for index, (parent, key_id) in enumerate(scopes):
        material = Material(parent, key_id, seed=30 + index)
        client = FakeKms("create", material)
        first = bootstrap(client)
        assert_usable(first, client)
        second = bootstrap(client)
        assert_usable(second, client)
        assert first.key_version_name == second.key_version_name
        assert first.provider.signing_key().to_dict() == second.provider.signing_key().to_dict()
        assert client.creates == 1
        refs.add(first.key_version_name)
        kids.add(material.kid)
    assert len(refs) == len(kids) == len(scopes)


@pytest.mark.parametrize("key_id", ("a", "Z" * 63, "_", "-", "Aa_09-z"))
def test_case7_valid_id_boundaries_are_preserved(key_id):
    """Mode: real-capable. GIVEN valid boundary ID WHEN create THEN exact spelling."""
    client = FakeKms("create", Material(key_id=key_id))
    assert_usable(bootstrap(client), client)
    assert client.creates == 1


@pytest.mark.parametrize("route", ROUTES)
def test_case8_explicit_application_key_first_composition(route):
    """Mode: fake-only. GIVEN app composition WHEN success THEN explicit agent step later.

    This is a test-owned application action, NOT a proposed SDK agent API or a server.
    """
    client = FakeKms(route)
    events = []

    def application_agent_action(key_result):
        # The action can use the completed provider, and only the caller invokes it.
        assert_usable(key_result, client)
        events.append("agent-action")
        return "application-owned-agent-id"

    events.append("key-start")
    key_result = bootstrap(client)
    assert events == ["key-start"]  # Bootstrap alone did not invoke our agent action.
    events.append("key-complete")
    agent_id = application_agent_action(key_result)
    assert agent_id == "application-owned-agent-id"
    assert events == ["key-start", "key-complete", "agent-action"]
    assert_owned(client)
    client.material.public.verify(key_result.provider.sign(PAYLOAD), PAYLOAD)


@pytest.mark.parametrize("stage", ERROR_STAGES)
def test_case8_key_failure_prevents_application_agent_step(stage):
    """Mode: fake-only. GIVEN failed key operation WHEN composed THEN no agent action."""
    route = "winner" if stage == "winner" else "create" if stage == "create" else "reuse"
    client = FakeKms(route)
    error = RuntimeError("explicit key operation failed")
    client.faults[stage] = error
    events = []

    def application():
        result = bootstrap(client)
        events.append(("agent-action", result.key_version_name))

    with pytest.raises(RuntimeError) as caught:
        application()
    assert caught.value is error
    assert events == []
    assert_owned(client)
