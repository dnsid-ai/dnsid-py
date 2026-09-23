# DNSid A2A example (Python)

Runs two A2A agents, Alice and Bob, on the local DNSid testnet. Each agent gets a DNSid
identity from `dnsid testnet run` and exchanges A2A 1.0 JSON-RPC messages signed with
RFC 9421 HTTP Message Signatures.

Mirrors [dnsid-ts/examples/a2a](../../../dnsid-ts/examples/a2a). Python and TypeScript agents
are cross-compatible — Alice can be Python while Bob is TypeScript and vice versa.

## Dependencies

Install the example's additional requirements from the project root:

```bash
pip install fastapi uvicorn dnspython a2a-sdk sse-starlette
```

(`httpx` is already a dependency of the dnsid SDK.)

Install the `dnsid` CLI ([installation
guide](https://docs.dnsid.ai/cli-installation)) and make sure Docker is
running. The CLI manages the testnet directly. By default it pulls `ghcr.io/identity-digital/dnsid-testnet-registry:latest`
(override with `DNSID_TESTNET_IMAGE`).

## Run

Prepare both identities and submit their operationally countersigned C2SP
ISSUANCE entries before starting either agent (`dnsid log issue` is
idempotent, so this is safe to rerun for existing identities):

```sh
dnsid testnet up
dnsid testnet agent ensure bob --upstream http://localhost:3002 -- \
  dnsid log issue --domain bob.dev.dnsid.test
dnsid testnet agent ensure alice --upstream http://localhost:3001 -- \
  dnsid log issue --domain alice.dev.dnsid.test
```

Then, from the `dnsid-py` project root, in two terminal panes:

```sh
# Terminal 1 — start Bob (stays running, listens on :3002)
dnsid testnet run bob --upstream http://localhost:3002 -- \
  python examples/a2a/main.py

# Terminal 2 — start Alice, send one message to Bob, then exit
dnsid testnet run alice --upstream http://localhost:3001 -- \
  python examples/a2a/main.py bob.dev.dnsid.test
```

`dnsid testnet run` starts the local testnet if needed, creates/reuses agent identity
files under `~/.dnsid-testnet`, registers each local upstream, and injects the full
`DNSID_*` environment: DNS routing (`DNSID_DNS_SERVER`), TLS trust (`DNSID_CA_BUNDLE`),
the registry session credential (`DNSID_API_KEY`), the independently trusted C2SP
policy location (`DNSID_LOG_POLICY_URL`), and the provisioned identity directory
(`DNSID_CONFIG_DIR`) whose `private.jwk` carries the RFC 7638 thumbprint `kid` the
registry requires. The SDK's `load_environment()` reads all of it and `construct_identity_manager()`
wires the key files and the C2SP policy fetch; the example adds only the agent-card
URL as a code overlay. The policy URL is never derived from `DNSID_LOG_REF` or the
log prefix. Production applications must likewise keep official or pinned policy
trust independently configured rather than discovering it from log-provided data.

The CLI also owns the testnet lifecycle and state:

```sh
dnsid testnet up
dnsid testnet agent list
dnsid testnet env alice
dnsid testnet down
dnsid testnet reset --hard
```

Or run `bash examples/a2a/run.sh` to execute the whole flow (testnet up, Bob, one
message from Alice) in a single script. If the CLI is not the `dnsid` on your `PATH`,
set `DNSID_CLI=/path/to/dnsid`.

## Expected output

**Bob's terminal** (stays running):
```
bob.dev.dnsid.test -> https://bob.dev.dnsid.test
bob.dev.dnsid.test published identity record
```
Then when Alice connects:
```
[bob.dev.dnsid.test] verified signed POST / from alice.dev.dnsid.test
[bob.dev.dnsid.test] handling message from verified sender alice.dev.dnsid.test: "hello from alice.dev.dnsid.test"
[bob.dev.dnsid.test] sending response to alice.dev.dnsid.test: "[from: bob.dev.dnsid.test; verified sender: alice.dev.dnsid.test] hello from alice.dev.dnsid.test"
```

**Alice's terminal** (exits after sending):
```
alice.dev.dnsid.test -> https://alice.dev.dnsid.test
alice.dev.dnsid.test published identity record
verified: alice.dev.dnsid.test -> bob.dev.dnsid.test

reply: "[from: bob.dev.dnsid.test; verified sender: alice.dev.dnsid.test] hello from alice.dev.dnsid.test"
```

On subsequent runs (without a testnet reset), both agents show `already published (READY)`
instead of `published identity record`.

## How it works

| Step | What happens |
|------|-------------|
| Startup | `load_environment()` → `merge_loaded_config()` → `construct_identity_manager()` builds the `IdentityManager`: Ed25519 key from the `DNSID_CONFIG_DIR` identity directory, log trust from the independently supplied `DNSID_LOG_POLICY_URL` |
| Registration | `RegistryClient.register_agent()` registers with the registry |
| Verification | The agent requests verification, polls the status document for the challenge nonce, signs the decoded nonce with its active key, and submits it via `RegistryClient.submit_challenge_signature()`; the registry transitions `VERIFICATION → VERIFIED` |
| Publish | `IdentityManager.publish_to_registry()` validates and signs the registry's canonical content, then submits the signature |
| Self-verify | `idm.verify_domain(own_domain)` confirms the published record is DNS-resolvable |
| Send (Alice) | `agent.create_client()` returns an `A2AClient` that builds a signed A2A 1.0 `SendMessage` JSON-RPC request via `create_signed_http_client` (RFC 9421) |
| Receive (Bob) | FastAPI middleware calls `HttpSignatureProfile.verify_signed_http_request()` on every inbound POST and stores the verified sender as a `VerifiedSenderUser` on the request; the a2a-sdk `DefaultRequestHandler` dispatches the JSON-RPC method to the `AgentExecutor` |
| Echo (Bob) | `echo_executor` (an a2a-sdk `AgentExecutor`) reads the sender from `RequestContext`, builds a reply, and publishes it to the `EventQueue` |
