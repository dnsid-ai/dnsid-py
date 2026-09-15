# Web Bot Auth Example

Demonstrates the signing side of `WebBotAuthProfile`: authenticating outbound
bot/agent HTTP requests with DNSid-issued JWTs.

The example runs entirely offline. It loads (or creates) a local Ed25519 key
store, declares the bot's metadata with `BotIdentity`, creates a bot token for
a target URL, signs an `httpx.Request` (returning a new signed copy — the
original is not modified), and decodes the token to show the claims a
verifier would see. Token `aud` is the target's origin, not the full URL.

Verifying inbound requests (`verify_bot_request`) resolves the issuer's DNSid
identity over DNS, so it needs a real resolver — the verification wiring is
shown in a comment at the bottom of `main.py`, and a full two-agent
verification setup lives in [examples/a2a/](../a2a/).

## Run Example

From the repo root:

```sh
pip install -e .
python examples/webbotauth/main.py
```

Note: The key file is written to `./keys.json` in the current directory.
Delete that file to reset the example.
