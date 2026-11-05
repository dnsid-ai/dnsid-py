"""Rotate one testnet key; rerun the same command to recover."""

import uuid

from support import Demo

from dnsid import registry_client_from_environment


def main() -> None:
    demo = Demo()
    restoring = demo.rotation is not None and demo.rotation.activated
    hooks = dict(
        persist_rotation=demo.persist_rotation,
        set_application_signing_paused=demo.set_paused,
        previous_provider_reference=str(demo.key_path),
        target_provider_reference=str(demo.key_path),
    )

    with demo.manager as manager, registry_client_from_environment() as registry:
        if demo.rotation is not None:
            # Resume the saved operation, never prepare a replacement.
            rotation = manager.resume_key_rotation(registry, demo.rotation, **hooks)
        else:
            # Show that the current key works before rotating it.
            before = manager.verify_local_publication()
            old_message = demo.sign_and_verify(before)
            demo.save_old_message(old_message)
            print("old key signs and verifies")

            rotation = manager.rotate_operational_key(
                registry, idempotency_key=str(uuid.uuid4()), **hooks
            )

        if not rotation.activated or rotation.application_signing_paused:
            raise RuntimeError("rotation pending; rerun the same command to resume")
        if restoring:
            print("saved rotation restored; no network checks")
            return

        # Fetch current evidence: the new key must work and the old key must fail.
        after = manager.verify_local_publication()
        if len(after.jwks.keys) != 1:
            raise RuntimeError("expected only the new operational key in live JWKS")
        if after.jwks.current_operational_signing_key(after.record.v).kid != rotation.new_kid:
            raise RuntimeError("published operational key does not match rotation")
        if rotation.previous_kid in demo.provider.list_key_ids():
            raise RuntimeError("previous key is still in the provider")
        demo.sign_and_verify(after)
        demo.reject_old_message()

        print(f"rotation verified: {rotation.previous_kid} -> {rotation.new_kid}")
        print("new key signs and verifies; old key is absent from live JWKS and provider")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(
            f"rotation: {error}\nRerun the same command to recover; do not delete the saved state."
        ) from None
