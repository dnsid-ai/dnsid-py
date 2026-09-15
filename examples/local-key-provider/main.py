"""Local key provider example.

Demonstrates the LocalKeyProvider key lifecycle:
- Load an existing key store or create one on first run
- List key IDs, retrieve a JWK by kid
- Generate a pending key and activate it (key rotation)
- Construct a public JWKS
- Create and decode a signed JWT via JoseProfile
"""

from __future__ import annotations

import json
from pathlib import Path

from dnsid import LocalKeyProvider
from dnsid._utils import b64url_decode
from dnsid.interfaces import IdentityResolver
from dnsid.jose import JoseProfile
from dnsid.models import JWTOptions, VerifiedDomain

KEY_STORE_PATH = Path("keys.json")


def decode_jwt_part(jwt: str, part: int) -> object:
    return json.loads(b64url_decode(jwt.split(".")[part]))


class _DummyResolver(IdentityResolver):
    """Stub resolver — this example only signs; verification needs a real DNSid resolver."""

    def verify_domain(self, domain: str) -> VerifiedDomain:
        raise NotImplementedError(
            "This example only signs; verification would use a real DNSid resolver."
        )


def main() -> None:
    # Load existing key store, or create one on first run
    key_provider = LocalKeyProvider.load(KEY_STORE_PATH, create_if_missing=True)
    print("loaded active key:", key_provider.signing_key())
    print("visible key ids:", key_provider.list_key_ids())

    # Retrieve the active signing key and look it up by kid
    signing_key = key_provider.signing_key()
    print("\nget jwk by kid:", key_provider.jwk(signing_key.kid))

    # Generate a new key in pending state
    pending_kid = key_provider.generate_key()
    print("\ngenerated pending kid:", pending_kid)
    print("visible key ids before activation:", key_provider.list_key_ids())

    # Activate the new key; old active moves to retained
    key_provider.activate(pending_kid)
    print("\nvisible key ids after activation:", key_provider.list_key_ids())
    print("new active key:", key_provider.signing_key())

    # Build the public JWKS — what should be hosted at /.well-known/jwks.json
    jwks = {"keys": [key_provider.jwk(kid) for kid in key_provider.list_key_ids()]}
    print("\npublic JWKS:", jwks)

    # Create a JoseProfile and sign a JWT
    jose = JoseProfile(
        resolver=_DummyResolver(),
        key_provider=key_provider,
        domain="alice.example.com",
    )
    jwt = jose.create_jwt(
        JWTOptions(
            audience="bob.example.com",
            additional_claims={"example": "local-key-provider"},
        )
    )
    print("\nsigned JWT:", jwt)
    print("\ndecoded JWT header:", decode_jwt_part(jwt, 0))
    print("decoded JWT payload:", decode_jwt_part(jwt, 1))


if __name__ == "__main__":
    main()
