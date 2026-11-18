"""Local initial creation preserves a reusable identity; real filesystem and crypto.

Only public LocalKeyProvider methods and JWK.to_dict are used. Workers are
separate processes so a stalled load can be bounded without leaking threads.
Run through pytest; direct script invocation is reserved for the worker below.
"""

import base64
import json
import selectors
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from dnsid import LocalKeyProvider

WORKERS = 6
BUDGET_SECONDS = 30.0
ALGORITHMS = ("EdDSA", "ES256")


def _unbase64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _identity(jwk, algorithm):
    assert isinstance(jwk, dict)
    assert "d" not in jwk, "signing_key must expose public material only"
    assert jwk["alg"] == algorithm
    assert isinstance(jwk["kid"], str) and jwk["kid"]
    if algorithm == "EdDSA":
        assert (jwk["kty"], jwk["crv"]) == ("OKP", "Ed25519")
        assert len(_unbase64(jwk["x"])) == 32
        fields = ("kty", "crv", "x", "alg", "kid")
    else:
        assert (jwk["kty"], jwk["crv"]) == ("EC", "P-256")
        assert len(_unbase64(jwk["x"])) == 32
        assert len(_unbase64(jwk["y"])) == 32
        fields = ("kty", "crv", "x", "y", "alg", "kid")
    return {field: jwk[field] for field in fields}


def _verify(jwk, payload, signature):
    """Independent cryptography verification, never SDK verification."""
    assert isinstance(signature, bytes) and len(signature) == 64
    if jwk["alg"] == "EdDSA":
        ed25519.Ed25519PublicKey.from_public_bytes(_unbase64(jwk["x"])).verify(
            signature, payload
        )
    else:
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_unbase64(jwk["x"]), "big"),
            int.from_bytes(_unbase64(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        # JOSE ES256 is r || s (32 bytes each), not ASN.1 DER.
        der = utils.encode_dss_signature(
            int.from_bytes(signature[:32], "big"),
            int.from_bytes(signature[32:], "big"),
        )
        public.verify(der, payload, ec.ECDSA(hashes.SHA256()))


def _error(error):
    return {"type": type(error).__name__, "message": str(error)}


def _worker(path, algorithm, index):
    print("READY", flush=True)
    if sys.stdin.readline() != "GO\n":
        raise RuntimeError("worker release missing")
    result = {"attempt": int(index), "status": "started"}
    try:
        provider = LocalKeyProvider.load(path, create_if_missing=True, algorithm=algorithm)
    except Exception as error:
        result.update(status="load_exception", error=_error(error))
    else:
        result["status"] = "load_success"
        try:
            result["jwk"] = provider.signing_key().to_dict()
            payload = f"known62-initial-convergence/{algorithm}/{index}".encode()
            result["payload"] = base64.b64encode(payload).decode("ascii")
            result["signature"] = base64.b64encode(provider.sign(payload)).decode("ascii")
        except Exception as error:
            result.update(status="post_load_exception", error=_error(error))
    print(json.dumps(result, sort_keys=True), flush=True)


def _race(path, algorithm, evidence):
    processes = []
    deadline = time.monotonic() + BUDGET_SECONDS

    def remaining():
        return max(0.0, deadline - time.monotonic())

    try:
        with selectors.DefaultSelector() as selector:
            for index in range(WORKERS):
                evidence.append({"attempt": index, "status": "not_started"})
                # Fixed interpreter/repository worker; remaining argv is test-owned.
                process = subprocess.Popen(  # noqa: S603
                    [sys.executable, str(Path(__file__).resolve()), "--worker",
                     str(path), algorithm, str(index)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                processes.append(process)
                evidence[index]["status"] = "waiting_ready"
                selector.register(process.stdout, selectors.EVENT_READ, index)
            ready = set()
            while len(ready) < WORKERS:
                events = selector.select(remaining())
                if not events:
                    raise TimeoutError("workers did not become ready within shared budget")
                for key, _ in events:
                    index = key.data
                    line = key.fileobj.readline()
                    if line != "READY\n":
                        evidence[index].update(status="setup_error", stdout=line)
                        raise RuntimeError(f"worker {index} failed readiness")
                    ready.add(index)
                    evidence[index]["status"] = "ready"
                    selector.unregister(key.fileobj)
            # No worker can invoke load before all workers have reached this gate.
            assert not path.exists(), "store must still be absent at release"
            for index, process in enumerate(processes):
                process.stdin.write("GO\n")
                process.stdin.flush()
                evidence[index]["status"] = "released"
            for index, process in enumerate(processes):
                try:
                    stdout, stderr = process.communicate(timeout=remaining())
                except subprocess.TimeoutExpired:
                    evidence[index]["status"] = "timeout"
                    continue
                evidence[index].update(stdout=stdout, stderr=stderr, returncode=process.returncode)
                if process.returncode != 0:
                    evidence[index]["status"] = "worker_error"
                    continue
                try:
                    result = json.loads(stdout)
                    assert result["attempt"] == index
                    assert result["status"] in {
                        "load_success", "load_exception", "post_load_exception"
                    }
                except (ValueError, KeyError, AssertionError, TypeError) as error:
                    evidence[index].update(status="protocol_error", error=_error(error))
                else:
                    evidence[index].update(result)
    finally:
        original_error = sys.exc_info()[1]
        cleanup_errors = []

        def cleanup_error(index, stage, error):
            detail = {"stage": stage, **_error(error)}
            evidence[index].setdefault("cleanup_errors", []).append(detail)
            cleanup_errors.append({"attempt": index, **detail})

        # Attempt every termination before waiting on any child. A failed poll
        # leaves liveness unknown, so still attempt to kill that owned child.
        for index, process in enumerate(processes):
            needs_kill = True
            try:
                needs_kill = process.poll() is None
            except BaseException as error:
                cleanup_error(index, "poll", error)
            if needs_kill:
                try:
                    process.kill()
                    evidence[index]["killed_by_harness"] = True
                except BaseException as error:
                    cleanup_error(index, "kill", error)

        # Collection is individually bounded; failures cannot skip later children.
        for index, process in enumerate(processes):
            evidence[index]["cleanup_collected"] = False
            try:
                stdout, stderr = process.communicate(timeout=5)
                evidence[index].setdefault("stdout", stdout)
                evidence[index].setdefault("stderr", stderr)
                evidence[index]["returncode"] = process.returncode
                if process.returncode is None:
                    raise RuntimeError("child return code unavailable after collection")
                evidence[index]["cleanup_collected"] = True
            except BaseException as error:
                cleanup_error(index, "communicate/collection", error)

        if cleanup_errors:
            message = "owned-child cleanup had errors; completeness not assured: " + json.dumps(
                cleanup_errors, sort_keys=True
            )
            if original_error is not None:
                original_error.add_note(message)
            else:
                raise RuntimeError(message)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_overlapping_explicit_initial_loads_converge(tmp_path, record_property, algorithm):
    """GIVEN absent store WHEN concurrent opt-in loads THEN all successes agree.

    Mode: real-capable. Load exceptions remain evidence, not a fixed loser API.
    """
    path = tmp_path / "identity.json"
    evidence = []
    errors = []
    try:
        _race(path, algorithm, evidence)
        successes = [item for item in evidence if item["status"] == "load_success"]
        assert successes, "zero successful loads cannot establish convergence"
        shared = successes[0]["jwk"]
        expected = _identity(shared, algorithm)
        for item in evidence:
            if item["status"] == "load_exception":
                continue
            if item["status"] != "load_success":
                errors.append(f"attempt {item['attempt']}: {item['status']}")
                continue
            try:
                assert _identity(item["jwk"], algorithm) == expected
                _verify(shared, base64.b64decode(item["payload"]),
                        base64.b64decode(item["signature"]))
            except Exception as error:
                errors.append(f"attempt {item['attempt']}: {_error(error)}")
        # Ordinary reopen must retain the same identity, not repair/create one.
        reopened = LocalKeyProvider.load(path)
        assert _identity(reopened.signing_key().to_dict(), algorithm) == expected
        payload = b"known62-ordinary-reopen"
        _verify(shared, payload, reopened.sign(payload))
        assert not errors, "\n".join(errors)
    finally:
        report = json.dumps({"algorithm": algorithm, "attempts": evidence,
                             "verification_errors": errors}, sort_keys=True)
        record_property("known62_attempts", report)
        print("KNOWN62_ATTEMPTS " + report, flush=True)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("as_string", (False, True), ids=("Path", "str"))
def test_explicit_load_reuses_existing_identity(tmp_path, algorithm, as_string):
    """GIVEN existing key WHEN opt-in requests opposite algorithm THEN reuse.

    Mode: real-capable. Creation is explicit and precedes reuse; no agent action.
    """
    path = tmp_path / "existing.json"
    argument = str(path) if as_string else path
    first = LocalKeyProvider.load(argument, create_if_missing=True, algorithm=algorithm)
    shared = first.signing_key().to_dict()
    expected = _identity(shared, algorithm)
    payload = b"known62-original"
    _verify(shared, payload, first.sign(payload))
    other = "ES256" if algorithm == "EdDSA" else "EdDSA"
    reused = LocalKeyProvider.load(argument, create_if_missing=True, algorithm=other)
    assert _identity(reused.signing_key().to_dict(), algorithm) == expected
    payload = b"known62-explicit-reuse"
    _verify(shared, payload, reused.sign(payload))
    reopened = LocalKeyProvider.load(argument)
    assert _identity(reopened.signing_key().to_dict(), algorithm) == expected
    payload = b"known62-reuse-ordinary-reopen"
    _verify(shared, payload, reopened.sign(payload))


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("as_string", (False, True), ids=("Path", "str"))
def test_ordinary_absent_load_never_creates_signing_store(tmp_path, algorithm, as_string):
    """GIVEN absent path WHEN ordinary load THEN FileNotFoundError, still absent.

    Mode: real-capable. No assertion about lock sidecars or cleanup internals.
    """
    path = tmp_path / "absent.json"
    argument = str(path) if as_string else path
    assert not path.exists()
    with pytest.raises(FileNotFoundError):
        LocalKeyProvider.load(argument, algorithm=algorithm)
    assert not path.exists(), "ordinary load created the requested signing store"


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--worker":
        raise SystemExit("Run with pytest; script mode is only for isolated workers")
    _worker(*sys.argv[2:])
