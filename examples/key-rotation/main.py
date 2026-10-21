"""Rotate one local operational key on the DNSid testnet; rerun to resume."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import uuid
from dataclasses import asdict, replace
from pathlib import Path

from dnsid import (
    JWK,
    KeyRotationResult,
    LocalKeyProvider,
    SubmissionResult,
    VerificationCode,
    construct_identity_manager,
    load_environment,
    registry_client_from_environment,
)
from dnsid.exceptions import VerificationError
from dnsid.jose import JoseProfile


def sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save(destination: Path, value: object) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".rotation-")
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        sync_directory(destination.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> None:
    if not os.environ.get("DNSID_CONFIG_DIR") or not os.environ.get("DNSID_LOG_POLICY_URL"):
        raise SystemExit("run with dnsid local run")
    config_dir = Path(os.environ["DNSID_CONFIG_DIR"])
    directory = (config_dir / "rotation-py").resolve()
    directory.mkdir(mode=0o700, exist_ok=True)
    sync_directory(directory.parent)
    key_path, journal_path = directory / "keys.json", directory / "rotation.json"
    rotation = None
    if journal_path.exists():
        data = json.loads(journal_path.read_text())
        data["entry_bytes"] = base64.b64decode(data["entry_bytes"], validate=True)
        data["previous_public_key"] = JWK.from_dict(data["previous_public_key"])
        if data["submission"] is not None:
            data["submission"] = SubmissionResult(**data["submission"])
        rotation = replace(KeyRotationResult(**data), application_signing_paused=True)
    if not key_path.exists():
        if rotation is not None:
            raise RuntimeError("saved provider is missing; do not generate a replacement")
        active = json.loads((config_dir / "private.jwk").read_text())
        save(key_path, {"active": active, "retained": [], "pending": []})
    # shortcut: one process owns this store; add a cross-process lock before sharing it.
    provider = LocalKeyProvider.load(key_path)
    paused = True  # Restart begins closed, including after a completed rotation.

    def persist(state: KeyRotationResult) -> None:
        nonlocal rotation
        if rotation is not None and (
            state.entry_hash != rotation.entry_hash
            or state.idempotency_key != rotation.idempotency_key
        ):
            raise RuntimeError("recovery changed the signed operation")
        data = vars(state).copy()
        data["entry_bytes"] = base64.b64encode(state.entry_bytes).decode("ascii")
        assert state.previous_public_key is not None
        data["previous_public_key"] = state.previous_public_key.to_dict()
        data["submission"] = asdict(state.submission) if state.submission is not None else None
        save(journal_path, data)
        rotation = state
        status = state.submission.state if state.submission else "prepared"
        print(
            f"saved: {status}, activated={state.activated}, paused={state.application_signing_paused}"
        )

    def set_paused(value: bool) -> None:
        nonlocal paused
        if not value and (rotation is None or not rotation.activated):
            raise RuntimeError("activation must be durable before unpausing")
        paused = value  # All example signatures use sign(); no requests to drain.

    hooks = dict(
        persist_rotation=persist,
        set_application_signing_paused=set_paused,
        previous_provider_reference=str(key_path),
        target_provider_reference=str(key_path),
    )
    loaded = load_environment()
    identity = loaded.dnsid.identity
    if (
        identity is None
        or not identity.domain.endswith(".test")
        or not identity.log_ref.startswith("c2sp-tlog:testnet:")
    ):
        raise RuntimeError("this example only rotates testnet identities")
    # Inject the reopened saved provider. Deployment configuration must not replace it.
    with construct_identity_manager(loaded, key_provider=provider) as manager:
        domain = manager.local_domain
        profile = JoseProfile(manager, provider, domain)

        def sign() -> str:
            if paused:
                raise RuntimeError("application signing is paused")
            return profile.create_jws(b"rotation example")

        with registry_client_from_environment() as registry:
            if rotation is None:
                before = manager.refresh_domain(domain)
                assert before.record.lr == manager.config.identity.log_ref, (
                    "CLI log reference does not match publication"
                )
                assert (
                    provider.signing_key().kid
                    == before.jwks.current_operational_signing_key(before.record.v).kid
                )
                paused = False
                old_message = sign()
                profile.verify_jws(old_message)
                save(directory / "old-message.json", old_message)
                print("old key signs and verifies")
                rotation = manager.rotate_operational_key(
                    registry, idempotency_key=str(uuid.uuid4()), **hooks
                )
            else:
                assert rotation.domain == domain
                assert rotation.log_reference == manager.config.identity.log_ref
                rotation = manager.resume_key_rotation(registry, rotation, **hooks)
            for _ in range(60):
                if rotation.activated:
                    break
                time.sleep(1)
                rotation = manager.resume_key_rotation(registry, rotation, **hooks)
        assert rotation.activated and not paused, "rotation unresolved; rerun the same command"
        observed = manager.refresh_domain(domain)
        assert len(observed.jwks.keys) == 1
        assert (
            observed.jwks.current_operational_signing_key(observed.record.v).kid == rotation.new_kid
        )
        assert rotation.previous_kid not in provider.list_key_ids()
        profile.verify_jws(sign())
        try:
            profile.verify_jws(json.loads((directory / "old-message.json").read_text()))
        except VerificationError as error:
            assert error.code == VerificationCode.SIGNATURE_INVALID
        else:
            raise AssertionError("old-key application signature was accepted after refresh")
        print(f"rotation verified: {rotation.previous_kid} -> {rotation.new_kid}")
        print("new key signs and verifies; old key is absent from live JWKS and provider")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(
            f"rotation: {error}\nRerun the same command to recover; do not delete the saved state."
        ) from None
