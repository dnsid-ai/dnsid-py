"""Testnet setup, durable files, and a single-process signing gate."""

from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from dnsid import (
    JWK,
    IdentityManager,
    KeyRotationResult,
    LocalKeyProvider,
    LogRef,
    SubmissionResult,
    VerificationCode,
    construct_identity_manager,
    load_environment,
)
from dnsid.exceptions import VerificationError
from dnsid.jose import JoseProfile


class Demo:
    def __init__(self) -> None:
        if not os.environ.get("DNSID_CONFIG_DIR") or not os.environ.get("DNSID_LOG_POLICY_URL"):
            raise RuntimeError("run with dnsid local run")
        config_dir = Path(os.environ["DNSID_CONFIG_DIR"])
        self.directory = (config_dir / "rotation-py").resolve()
        self.directory.mkdir(mode=0o700, exist_ok=True)
        sync_directory(self.directory.parent)
        self.key_path = self.directory / "keys.json"
        self.journal_path = self.directory / "rotation.json"
        self.rotation = read_rotation(self.journal_path)
        if not self.key_path.exists():
            if self.rotation is not None:
                raise RuntimeError("saved provider is missing; do not generate a replacement")
            active = json.loads((config_dir / "private.jwk").read_text())
            save(self.key_path, {"active": active, "retained": [], "pending": []})
        self.provider = LocalKeyProvider.load(self.key_path)

        loaded = load_environment()
        identity = loaded.dnsid.identity
        if (identity is None or not identity.domain.endswith(".test")
                or not identity.log_ref.startswith("c2sp-tlog:testnet:")):
            raise RuntimeError("this example only rotates testnet identities")
        if self.rotation is not None:
            assert self.rotation.domain == identity.domain
            assert self.rotation.log_reference == identity.log_ref
        # Terminal recovery must not run network-backed configuration discovery.
        self.manager = (
            IdentityManager(loaded.dnsid, self.provider)
            if self.rotation is not None and self.rotation.activated
            else construct_identity_manager(loaded, key_provider=self.provider)
        )
        # shortcut: one process owns this store; add locking and request draining before sharing it.
        self.paused = self.rotation is not None
        self.profile = JoseProfile(self, self.provider, self.manager.local_domain)

    def persist_rotation(self, state: KeyRotationResult) -> None:
        data = vars(state).copy()
        data["entry_bytes"] = base64.b64encode(state.entry_bytes).decode("ascii")
        assert state.previous_public_key is not None
        data["previous_public_key"] = state.previous_public_key.to_dict()
        data["submission"] = asdict(state.submission) if state.submission is not None else None
        save(self.journal_path, data)
        self.rotation = state
        status = state.submission.state if state.submission else "prepared"
        print(f"saved: {status}, activated={state.activated}, paused={state.application_signing_paused}")

    def set_paused(self, value: bool) -> None:
        if not value and (self.rotation is None or not self.rotation.activated):
            raise RuntimeError("activation must be durable before unpausing")
        self.paused = value

    def verify_domain(self, requested, peer_cert=None):
        assert requested == self.manager.local_domain
        return self.publication  # Local self-checks do not apply counterparty policy.

    def sign_and_verify(self, evidence) -> str:
        if self.paused:
            raise RuntimeError("application signing is paused")
        assert evidence.record.lr == self.manager.config.identity.log_ref, (
            "CLI log reference does not match publication"
        )
        self.publication = evidence
        message = self.profile.create_jws(b"rotation example")
        self.profile.verify_jws(message)
        return message

    def save_old_message(self, message: str) -> None:
        save(self.directory / "old-message.json", message)

    def reject_old_message(self) -> None:
        message = json.loads((self.directory / "old-message.json").read_text())
        try:
            self.profile.verify_jws(message)
        except VerificationError as error:
            assert error.code == VerificationCode.KEY_NOT_FOUND
        else:
            raise AssertionError("old-key application signature was accepted after refresh")


def read_rotation(path: Path) -> KeyRotationResult | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    data["entry_bytes"] = base64.b64decode(data["entry_bytes"], validate=True)
    data["previous_public_key"] = JWK.from_dict(data["previous_public_key"])
    if data["submission"] is not None:
        reference = data["submission"]["log_ref"]
        if reference is not None:
            data["submission"]["log_ref"] = LogRef(**reference)
        data["submission"] = SubmissionResult(**data["submission"])
    return KeyRotationResult(**data)


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
