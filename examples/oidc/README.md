# OIDC Profile Example

Demonstrates `OIDCProfile` for server-side agents that need a DNSid OIDC
access token for outbound calls (for example, an Org A agent calling an
Org B gateway/tool).

The example has two parts:

1. **Offline (always runs)** — creates the signed JWT bearer assertion the
   profile posts to an OIDC issuer's token endpoint, and decodes it so you
   can see the `iss`/`sub`/`fqdn`/`aud` claims.
2. **Online (opt-in)** — exchanges the assertion for a DNSid OIDC access
   token via `mint_oidc_token`. This requires the agent's DNSid identity to
   be published (DNS record, JWKS, status endpoint) and a reachable token
   endpoint, so it only runs when `DNSID_EXAMPLE_MINT=1` is set.

Minting a token only proves the agent could sign a DNSid assertion at
exchange time — relying parties must still verify the returned OIDC token
and perform the DNSid subject status/revocation checks their trust policy
requires. Keep the signing key on the server; never mint DNSid OIDC tokens
in client-side code.

## Run Example

From the repo root:

```sh
pip install -e .
python examples/oidc/main.py
```

Configuration (environment variables, all optional):

| Variable | Default | Description |
|---|---|---|
| `DNSID_EXAMPLE_DOMAIN` | `agent-a.org-a.example` | Agent FQDN (`iss`/`sub`/`fqdn` claims) |
| `DNSID_EXAMPLE_ISSUER` | `https://oidc.dnsid.ai` | OIDC issuer (assertion audience) |
| `DNSID_EXAMPLE_AUDIENCE` | `https://gateway.org-b.example` | Audience for the minted token |
| `DNSID_EXAMPLE_MINT` | unset | Set to `1` to perform the live token exchange |

Note: The key file is written to `./keys.json` in the current directory.
Delete that file to reset the example.
