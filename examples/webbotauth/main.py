"""Web Bot Auth example.

Demonstrates the WebBotAuthProfile signing side, fully offline:
- Load (or create) a local Ed25519 key store
- Declare the bot's identity metadata (BotIdentity)
- Create a DNSid bot JWT for a target URL
- Sign an httpx.Request — returns a new signed copy with Authorization
  and User-Agent headers (the original request is not modified)
- Decode the token to show the claims a verifier would see

Verification (WebBotAuthProfile.verify_bot_request) resolves the
issuer's DNSid identity over DNS, so it needs a real resolver — see the
snippet at the bottom of this file.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from dnsid import BotIdentity, LocalKeyProvider, WebBotAuthProfile
from dnsid._utils import b64url_decode
from dnsid.interfaces import IdentityResolver
from dnsid.models import VerifiedDomain

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

    # Bot metadata included in every signed token
    bot = BotIdentity(
        name="AcmeSearchBot",
        version="2.1",
        purpose="search-indexing",
        operator_url="https://acme.example/bot-info",
    )

    bot_auth = WebBotAuthProfile(
        resolver=_DummyResolver(),
        key_provider=key_provider,
        domain="acmebot.acme.example",
        bot=bot,
    )

    # Option 1: create a token directly (for use with any HTTP library)
    token = bot_auth.create_bot_token("https://target.example/api/data")
    print("bot token:", token[:60] + "...")
    print("\ndecoded header:", decode_jwt_part(token, 0))
    print("decoded claims:", json.dumps(decode_jwt_part(token, 1), indent=2))

    # Option 2: sign an httpx.Request — returns a new signed copy
    request = httpx.Request("GET", "https://target.example/api/data")
    signed = bot_auth.sign_bot_request(request)
    print("\nsigned request headers:")
    print("  Authorization:", signed.headers["Authorization"][:40] + "...")
    print("  User-Agent:", signed.headers["User-Agent"])

    # Verifying inbound requests requires a real DNSid resolver, e.g.:
    #
    #   manager = IdentityManager(config, key_provider)
    #   verifier = WebBotAuthProfile.from_identity_manager(
    #       manager, config=BotAuthConfig(require_bot_claim=True))
    #   result = verifier.verify_bot_request(
    #       headers=dict(inbound.headers),
    #       expected_audience="https://target.example")  # aud is the origin, not the full URL
    #   print(result.domain, result.bot.name)
    #
    # See examples/a2a/ for a full two-agent verification setup.


if __name__ == "__main__":
    main()
