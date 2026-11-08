"""Explicit AWS KMS first-key setup; does not issue or activate a DNSid identity."""

from __future__ import annotations

import json
import os
from dataclasses import asdict

from dnsid import (
    AwsKmsConfig,
    AwsKmsKeyProvider,
    AwsKmsKeyState,
    BotoKmsFacade,
    DnsidConfig,
    IdentityConfig,
    IdentityManager,
)


def main() -> None:
    # Resolve required application settings before creating a billable remote key.
    region = os.environ["AWS_REGION"]
    config = DnsidConfig(identity=IdentityConfig(
        domain=os.environ["DNSID_DOMAIN"],
        governance_id=os.environ["DNSID_GOVERNANCE_ID"],
        log_ref=os.environ["DNSID_LOG_REF"],
        status_url=os.environ["DNSID_STATUS_URL"],
        ek_url=os.environ["DNSID_EK_URL"],
        ku_url=os.environ["DNSID_KU_URL"],
    ))

    import boto3

    # The application owns this client. No local key provider or state file is used.
    client = boto3.client("kms", region_name=region)
    try:
        facade = BotoKmsFacade(client)
        provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(
            algorithm="ED25519_SHA_512",
            state=AwsKmsKeyState(active_key_id=""),
        ))
        kid = provider.generate_key()  # KMS CreateKey, then public-key validation; pending.
        print("pending public JWK:", json.dumps(provider.jwk(kid).to_dict()))
        print("pending state:", json.dumps(asdict(provider.state_snapshot())))
        proof_payload = b"DNSid AWS first-key example: pending possession only"
        proof = provider.sign_key(kid, proof_payload)
        print("pending SignKey signature bytes:", len(proof))

        provider.activate(kid)  # Local signer selection, NOT protocol ISSUANCE/ACTIVE.
        state = provider.state_snapshot()
        print("application-owned state handoff:", json.dumps(asdict(state)))

        # Reopen precisely the canonical reference, not an alias; no second CreateKey.
        reopened = AwsKmsKeyProvider.load(facade, AwsKmsConfig(
            algorithm="ED25519_SHA_512",
            state=AwsKmsKeyState(active_key_id=state.active_key_id),
        ))
        if reopened.signing_key().thumbprint() != provider.signing_key().thumbprint():
            raise RuntimeError("reopened key does not match the created key")

        # Python's supported injection seam is the key_provider argument.
        with IdentityManager(config, key_provider=reopened) as manager:
            print("public JWKS for the configured ku endpoint:", json.dumps(
                manager.get_key_set().to_dict(),
            ))
        # Stop here: the accountable entity/issuer owns record signing and issuance.
    finally:
        client.close()


if __name__ == "__main__":
    main()
