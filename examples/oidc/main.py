"""OIDC profile example.

Demonstrates the two halves of OIDCProfile:

1. Offline (always runs): create a signed JWT bearer assertion — the
   credential the profile posts to an OIDC issuer's token endpoint.
2. Online (opt-in): exchange the assertion for a DNSid OIDC access
   token via mint_oidc_token. Requires a reachable token endpoint;
   enable with DNSID_EXAMPLE_MINT=1.

Configuration via environment variables (defaults in parentheses):
- DNSID_EXAMPLE_DOMAIN   agent FQDN (agent-a.org-a.example)
- DNSID_EXAMPLE_ISSUER   OIDC issuer (https://oidc.dnsid.ai)
- DNSID_EXAMPLE_AUDIENCE token audience (https://gateway.org-b.example)
- DNSID_EXAMPLE_MINT     set to 1 to perform the live token exchange
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx

from dnsid import (
    LocalKeyProvider,
    OIDCAssertionOptions,
    OIDCConfig,
    OIDCProfile,
    OIDCTokenExchangeOptions,
)
from dnsid._utils import b64url_decode
from dnsid.interfaces import IdentityResolver
from dnsid.models import VerifiedDomain

KEY_STORE_PATH = Path("keys.json")

DOMAIN = os.environ.get("DNSID_EXAMPLE_DOMAIN", "agent-a.org-a.example")
ISSUER = os.environ.get("DNSID_EXAMPLE_ISSUER", "https://oidc.dnsid.ai")
AUDIENCE = os.environ.get("DNSID_EXAMPLE_AUDIENCE", "https://gateway.org-b.example")


def decode_jwt_part(jwt: str, part: int) -> object:
    return json.loads(b64url_decode(jwt.split(".")[part]))


class _DummyResolver(IdentityResolver):
    """Stub resolver — assertion creation only signs; token verification
    (verify_oidc_token) needs a real DNSid resolver."""

    def verify_domain(self, domain: str) -> VerifiedDomain:
        raise NotImplementedError(
            "This example only signs; verification would use a real DNSid resolver."
        )


def main() -> None:
    # Keep the signing key on the server; never mint DNSid OIDC tokens
    # in browser, mobile, or other client-side code.
    key_provider = LocalKeyProvider.load(KEY_STORE_PATH, create_if_missing=True)

    with httpx.Client(timeout=5.0) as http:
        oidc = OIDCProfile(
            resolver=_DummyResolver(),
            key_provider=key_provider,
            domain=DOMAIN,
            config=OIDCConfig(default_issuer=ISSUER, http_client=http),
        )

        # 1. Offline: the signed JWT bearer assertion posted to the issuer
        assertion = oidc.create_oidc_assertion(OIDCAssertionOptions(issuer=ISSUER))
        print("assertion:", assertion[:60] + "...")
        print("\ndecoded header:", decode_jwt_part(assertion, 0))
        print("decoded claims:", json.dumps(decode_jwt_part(assertion, 1), indent=2))

        # 2. Online: exchange the assertion for a DNSid OIDC access token.
        # Needs the DNSid identity published (DNS record, JWKS, status) and a
        # reachable token endpoint, so it is opt-in.
        if os.environ.get("DNSID_EXAMPLE_MINT") == "1":
            token_response = oidc.mint_oidc_token(
                OIDCTokenExchangeOptions(audience=AUDIENCE, scope=["openid", "dnsid"])
            )
            print("\naccess token:", token_response.access_token[:60] + "...")
            print("token type:", token_response.token_type)
            print("expires in:", token_response.expires_in, "seconds")
            # Use it: {"Authorization": f"Bearer {token_response.access_token}"}
        else:
            print("\nset DNSID_EXAMPLE_MINT=1 to exchange the assertion for an access token")


if __name__ == "__main__":
    main()
