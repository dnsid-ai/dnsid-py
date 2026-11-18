"""Explicit Google KMS first-key setup; stops before protocol issuance."""

from __future__ import annotations

import json
import os

from dnsid import DnsidConfig, GoogleKmsKeyProvider, IdentityConfig, IdentityManager


def main() -> None:
    # Read required settings before any billable remote mutation.
    parent = os.environ["GOOGLE_KMS_CRYPTO_KEY"]
    config = DnsidConfig(identity=IdentityConfig(
        domain=os.environ["DNSID_DOMAIN"],
        governance_id=os.environ["DNSID_GOVERNANCE_ID"],
        log_ref=os.environ["DNSID_LOG_REF"],
        status_url=os.environ["DNSID_STATUS_URL"],
        ek_url=os.environ["DNSID_EK_URL"],
        ku_url=os.environ["DNSID_KU_URL"],
    ))

    from google.cloud import kms_v1

    # The application owns the client, including cleanup after failed creation.
    with kms_v1.KeyManagementServiceClient() as client:
        provider, kid, reference = GoogleKmsKeyProvider.create(client, parent)
        print("pending public JWK:", json.dumps(provider.jwk(kid).to_dict()))
        proof = provider.sign_key(kid, b"DNSid Google first-key example: pending possession only")
        print("pending SignKey signature bytes:", len(proof))
        print("application-owned immutable version handoff:", reference)
        provider.activate(kid)  # Local selection, NOT protocol ISSUANCE/ACTIVE.

        reopened = GoogleKmsKeyProvider(client, reference)
        if reopened.signing_key().thumbprint() != kid:
            raise RuntimeError("reopened key does not match the created key")
        with IdentityManager(config, key_provider=reopened) as manager:
            print("public JWKS for the configured ku endpoint:", json.dumps(
                manager.get_key_set().to_dict(),
            ))
        # The distinct accountable entity/issuer owns record signing and issuance.


if __name__ == "__main__":
    main()
