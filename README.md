# dnsid-py

Python SDK for the [DNSid Protocol](https://datatracker.ietf.org/doc/draft-ihsanullah-dnsid/) — agent identity management and verification.

DNSid lets agents publish a cryptographically signed identity record in DNS and verify the identities of other agents before exchanging data.

## Installation

```bash
pip install dnsid
```

For AWS KMS-backed signing keys, install the `aws` extra:

```bash
pip install "dnsid[aws]"
```

If the release is not yet available on PyPI, install directly from GitHub.
Replace `main` with a [release tag](https://github.com/dnsid-ai/dnsid-py/releases)
to pin a version; the `[aws]` extra works the same way:

```bash
pip install "dnsid @ git+https://github.com/dnsid-ai/dnsid-py@main"
```

Requires Python 3.11+. CI-tested against Python 3.11, 3.12, and 3.13. Dependencies: `idna`, `httpx`, `cryptography`, `dnspython`. The package ships a `py.typed` marker (PEP 561), so mypy and other type checkers see its full strict-mode annotations.

See **[COMPATIBILITY.md](https://github.com/dnsid-ai/dnsid-py/blob/main/COMPATIBILITY.md)** for the full runtime and dependency compatibility matrix,
including tested Python versions, dependency version ranges, optional extras, and platform support.

## First verification

```python
from pathlib import Path

from dnsid import DnsidConfig, IdentityConfig, IdentityManager, LocalKeyProvider

manager = IdentityManager(
    DnsidConfig(
        identity=IdentityConfig(
            domain="billing-agent.acme.example", governance_id="acme.example",
            log_ref="microledger:abc123",
            status_url="https://billing-agent.acme.example/status",
        ),
    ),
    LocalKeyProvider.load(Path("~/.dnsid/keys.json").expanduser(), create_if_missing=True),
)

# Verify a counterparty's identity — fetches DNS, JWKS, and status endpoint
# The default "auto" DNSSEC policy accepts system resolvers that cannot report
# validation state, while still rejecting an explicit validation failure.
vd = manager.verify_domain("payments-agent.acme.example")
print(vd.domain, vd.cached_state())   # payments-agent.acme.example ACTIVE
```

Draft-01 verification is strict and fails closed: beyond the snippet above it
needs a log reader registered for the domain's `lr` method (see the
[transparency-log reference](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/transparency-log.md)). The
[Quickstart](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/quickstart.md) walks through the full setup. The default
`auto` DNSSEC policy works with the built-in resolver; `validated` and
`required` need a DNSSEC-aware resolver injected through
`IdentityManagerDependencies.dns_resolver`.

## What's in the SDK

- **Core protocol** — `IdentityManager` drives every protocol operation: domain verification, TXT-record creation and publication, key rotation, and lifecycle-event signing.
- **Application profiles** (not part of the core protocol): JWT/JWS ([JOSE](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/profile-jose.md)), [RFC 9421 HTTP Message Signatures](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/profile-http-signatures.md), [Web Bot Auth](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/profile-web-bot-auth.md), and [OIDC](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/profile-oidc.md).
- **Key management** — private keys stay behind the `KeyProvider` interface: file-backed with `LocalKeyProvider`, or externalized entirely with `AwsKmsKeyProvider` or your own KMS/HSM-backed implementation.
- **Transparency log** — a ready-made C2SP tile-log `LogReader` (`dnsid.c2sp_tlog`).
- **Registry client** — operator-side registration and publication workflows.

**Import surface.** Everything is importable from the package root (`from dnsid import IdentityManager, JoseProfile`), mirroring the TypeScript SDK's umbrella package. The profile classes are also importable from their home submodules (`dnsid.jose`, `dnsid.http_signatures`) — both paths refer to the same classes. The transparency-log integration is the exception: import it from `dnsid.c2sp_tlog`.

**Synchronous by design.** The public API is synchronous; async support is limited to the httpx transport plumbing (custom transports may implement `handle_async_request`) and the `async_retry_transient` helper. Call the SDK from async code via `asyncio.to_thread` or an executor.

## Documentation

- **[docs.dnsid.ai](https://docs.dnsid.ai/)** — hosted guides, concepts, and the product CLI documentation
- **[Quickstart Guide](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/quickstart.md)** — installation, prerequisites, and core workflows (resolve, sign, verify)
- **[API Reference](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/overview.md)** — generated from docstrings ([also on docs.dnsid.ai](https://docs.dnsid.ai/reference/py/overview/)); regenerate with `python scripts/gen_docs.py`
- **[Security](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/security.md)** — threat model, key-rotation/JWT-overlap guidance, and production operations notes

## Quick start

### Authenticating with JWT

```python
from dnsid import JWTOptions
from dnsid.jose import JoseProfile

jose = JoseProfile.from_identity_manager(manager)

# Create a signed JWT to send to a counterparty
token = jose.create_jwt(JWTOptions(audience="payments-agent.acme.example"))

# Verify a JWT received from a counterparty
vd = jose.verify_jwt(token)
```

### Minting DNSid OIDC tokens from server-side code

Use `OIDCProfile` when a server-side agent needs a DNSid OIDC access token for
an outbound call, for example an AgentCore-hosted Org A agent calling an Org B
AgentCore Gateway/tool. Keep the signing key on the server; do not mint DNSid
OIDC tokens in browser, mobile, or other client-side code.

```python
import httpx
from pathlib import Path

from dnsid import (
    DnsidConfig,
    IdentityConfig,
    IdentityManager,
    LocalKeyProvider,
    OIDCConfig,
    OIDCProfile,
    OIDCTokenExchangeOptions,
)

key_provider = LocalKeyProvider.load(Path("/var/lib/dnsid/agent-signing-key.jwk"))
manager = IdentityManager(
    DnsidConfig(
        identity=IdentityConfig(
            domain="agent-a.org-a.example",
            governance_id="org-a.example",
            log_ref="microledger:abc123",
            status_url="https://agent-a.org-a.example/status",
        ),
    ),
    key_provider,
)

with httpx.Client(timeout=5.0) as http:
    oidc = OIDCProfile.from_identity_manager(
        manager,
        OIDCConfig(
            default_issuer="https://oidc.dnsid.ai",
            http_client=http,
            timeout=5.0,
        ),
    )
    token_response = oidc.mint_oidc_token(
        OIDCTokenExchangeOptions(
            audience="https://gateway.org-b.example",
            scope=["openid", "dnsid"],
        )
    )

headers = {"Authorization": f"Bearer {token_response.access_token}"}
```

The issuer is configurable. For local/proxy-style deployments that mirror the
CLI behavior, pass `server_url="http://127.0.0.1:3001"`; the SDK discovers the
issuer there but posts the assertion to `server_url + "/token"`. For explicit
issuer mode, pass `issuer`, `discovery_url`, or `token_endpoint` as needed.

Minting a token only proves the agent could sign a DNSid assertion at exchange
time. Relying parties must still verify the returned OIDC token and perform the
DNSid subject status/revocation checks required by their trust policy.

### Signing and verifying HTTP requests (RFC 9421)

```python
from dnsid import HttpRequest, HttpSigningOptions
from dnsid.http_signatures import HttpSignatureProfile

http_sig = HttpSignatureProfile.from_identity_manager(manager)

# Sign an outbound request
req = HttpRequest(method="POST", url="https://payments-agent.acme.example/charge", body=b'{"amount":100}')
signed = http_sig.create_signed_http_request(req)

# Verify an inbound request
vd = http_sig.verify_signed_http_request(signed)
```

### Web bot authentication

Authenticate outbound bot/agent HTTP requests with DNSid-issued JWTs, and
verify inbound bot identity from the `Authorization: Bearer` header.

```python
from dnsid import WebBotAuthProfile, BotIdentity, BotAuthConfig
import httpx

# Configure the bot's identity metadata
bot = BotIdentity(
    name="AcmeSearchBot",
    version="2.1",
    purpose="search-indexing",
    operator_url="https://acme.example/bot-info",
)

# Create the bot auth profile from an IdentityManager
bot_auth = WebBotAuthProfile.from_identity_manager(manager, bot=bot)

# --- Signing outbound requests ---

# Option 1: Sign a single request
request = httpx.Request("GET", "https://target.example/api/data")
signed_request = bot_auth.sign_bot_request(request)
# signed_request now has Authorization: Bearer <dnsid-jwt> and User-Agent headers

# Option 2: Create a token directly (for use with any HTTP library)
token = bot_auth.create_bot_token("https://target.example/api/data")
headers = {"Authorization": f"Bearer {token}"}

# Option 3: Auto-signing httpx client
client = bot_auth.create_signed_bot_client()
response = client.get("https://target.example/api/data")  # auto-signed

# --- Verifying inbound requests ---

# Verify a bot request (e.g. in a web framework middleware)
from dnsid import WebBotAuthProfile, BotAuthConfig

verifier = WebBotAuthProfile.from_identity_manager(
    manager,
    config=BotAuthConfig(require_bot_claim=True),
)

result = verifier.verify_bot_request(
    headers={"Authorization": "Bearer <jwt-from-request>"},
    expected_audience="https://my-server.example",  # configured server origin, not request Host
)
print(result.domain)       # "acmebot.acme.example"
print(result.bot.name)     # "AcmeSearchBot"
print(result.bot.purpose)  # "search-indexing"
```

### Publishing your agent's identity

Draft 01 publication uses two key providers: the agent (operational) provider
passed to `IdentityManager`, and an accountable-entity provider supplied via
`IdentityManagerDependencies.entity_key_provider` that signs the TXT record
and entity lifecycle events. The two current public keys must be distinct.

```python
from dnsid.models import IssuanceEvent
import datetime

# 1. Publish the agent JWKS at the ku URL and the entity JWKS at the ek URL
ku_jwks = manager.get_key_set()         # exactly one current operational key
ek_jwks = manager.get_entity_key_set()  # exactly one current entity key

# 2. Write the ISSUANCE event to the ledger (requires a LogRegistry with a Log
#    implementation; signed by the entity key + operational countersignature)
event = IssuanceEvent(
    domain=config.domain,
    kid=key_provider.signing_key().kid,
    public_key=key_provider.signing_key(),
    thumbprint=key_provider.signing_key().thumbprint(),
    governance_id=config.governance_id,
    timestamp=datetime.datetime.now(datetime.UTC),
)
manager.sign_and_write_event(event)

# 3. Publish the signed TXT record at _dnsid.{domain}
txt_record = manager.create_txt_record()
# → "v=dnsid-draft-01;gi=acme.example;ek=https://...;ku=https://...;lr=...;su=...;sg=..."
```

## Architecture

```
dnsid/
├── manager.py           # IdentityManager — all protocol operations
├── models.py            # All data types (DnsidConfig, IdentityConfig, VerificationConfig, TransportConfig, RegistryConfig, JWK, JWKS, DnsIdTxtRecord, VerifiedDomain, …)
├── interfaces.py        # ABCs to implement: KeyProvider, Log, LogReader, DNSResolver, IdentityCache
├── registry.py          # LogRegistry — plug in ledger method implementations
├── registry_client.py   # RegistryClient — operator-side registry workflows
├── config_loading.py    # load_environment / load_file / load_cli_directory → merge → construct
├── c2sp_tlog/           # C2SP tile-log LogReader binding (lr=c2sp-tlog:...)
├── web_bot_auth.py      # WebBotAuthProfile — web bot/agent HTTP authentication
├── _crypto.py           # JWK thumbprint (RFC 7638) and signature verification
├── _https_client.py     # HTTPS fetching with redirect enforcement and TLS cert capture
├── _default_resolver.py # Default DNS resolver (DoH or system via dnspython)
└── _utils.py            # FQDN normalisation, base64 helpers, algorithm maps
```

## AWS KMS key provider

`AwsKmsKeyProvider` keeps private key material in AWS KMS and exposes public
keys as JWKs. Install the `aws` extra, then construct a `BotoKmsFacade` around
a boto3 KMS client:

```python
import boto3
from dnsid import AwsKmsConfig, AwsKmsKeyProvider, AwsKmsKeyState, BotoKmsFacade

facade = BotoKmsFacade(boto3.client("kms", region_name="us-east-1"))

# Load from a previously persisted state (or supply active_key_id directly)
state = AwsKmsKeyState(
    active_key_id="alias/dnsid-current",   # ARN, key ID, or alias
    retained_key_ids=[],
    pending_key_ids=[],
)

provider = AwsKmsKeyProvider.load(
    facade,
    AwsKmsConfig(
        state=state,
        algorithm="ECDSA_SHA_256",   # or "ED25519_SHA_512"
    ),
)
```

`load()` resolves aliases to canonical KMS key IDs and warms the JWK cache.

**Persisting state** — `AwsKmsKeyProvider` owns the active/pending/retained
lifecycle but does not persist state itself. Save the snapshot after any
lifecycle change and restore it on the next process start:

```python
# After generate_key(), activate(), or supersede():
snapshot = provider.state_snapshot()
save_to_database(snapshot)   # your persistence layer

# On next start, load saved state back into AwsKmsKeyState and pass to load()
```

**Key rotation**:

```python
new_kid = provider.generate_key()   # creates a new KMS key in pending state
provider.activate(new_kid)          # promotes to active; old active → retained
provider.supersede(old_kid)         # removes a retained key (optionally schedules KMS deletion)
save_to_database(provider.state_snapshot())
```

IAM permissions required at runtime: `kms:GetPublicKey`, `kms:Sign`. Add
`kms:CreateKey` for `generate_key()` and `kms:ScheduleKeyDeletion` if
`schedule_key_deletion_on_supersede=True`.

## Implementing KeyProvider

All private-key operations go through the `KeyProvider` interface — supply one that wraps your KMS or HSM to keep key material out of the process entirely:

```python
from dnsid.interfaces import KeyProvider
from dnsid import JWK

class MyKeyProvider(KeyProvider):
    def signing_key(self) -> JWK: ...
    def jwk(self, kid: str) -> JWK: ...
    def list_key_ids(self) -> list[str]: ...
    def sign(self, payload: bytes) -> bytes: ...
    def generate_key(self) -> str: ...
    def activate(self, kid: str) -> None: ...
    def supersede(self, kid: str) -> None: ...
```

## Plugging in a ledger

Register a factory for each ledger method you support:

```python
from dnsid import LogRegistry, IdentityManagerDependencies, IdentityManager

registry = LogRegistry()
registry.register("microledger", lambda lr: MyMicroledgerReader(lr))

deps = IdentityManagerDependencies(log_registry=registry)
manager = IdentityManager(config, key_provider, deps)
```

`LogReader` implementations must verify cryptographic inclusion proofs and append-only consistency. See [interfaces.py](https://github.com/dnsid-ai/dnsid-py/blob/main/dnsid/interfaces.py) for the full interface.

### C2SP tile-log binding

The SDK ships a ready-made `LogReader` for [C2SP](https://github.com/C2SP/C2SP)
tile-log transparency logs, wire-compatible with the other DNSid SDKs. The
convenience factory returns a registry ready for `verify_domain`:

```python
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    create_c2sp_tlog_verification_registry,
)

registry = create_c2sp_tlog_verification_registry(
    C2spTlogVerificationOptions(
        policy_url="https://policy.example/dnsid-policy",
        checkpoint_freshness_ms=5 * 60 * 1000,
        max_clock_skew_ms=30 * 1000,
    )
)
```

The policy URL is independently trusted caller configuration and is never
derived from an unverified identity record, its `lr`, or its log prefix. Pass
trusted policy bytes with `policy_document` instead when appropriate. The
factory uses verified per-domain stream bundles when configured with a trust
profile, falling back to its bounded complete scanner when the bundle endpoint
is unavailable or a valid newer bundle needs raw consistency evidence. The
complete scan must prove both the stored and bundle checkpoint roots.

For an explicit application decision to trust DNSid-managed logs,
use the separately named managed factory:

```python
from dnsid.c2sp_tlog import create_dnsid_managed_verification_registry

registry = create_dnsid_managed_verification_registry()
```

It selects SDK-embedded reviewed trust only for exact canonical `public`
references to `https://log.dnsid.dev` or `https://log.dnsid.ai`; unknown scopes
and prefixes fail closed. Both managed logs prefer verified signed stream bundles
with bounded raw-scan fallback. The generic factory never selects these roots.

Both factories use a restart-ephemeral in-memory checkpoint store
by default; inject a durable `CheckpointStore` when rollback protection must
survive restarts. If `checkpoint_freshness_ms` is omitted,
non-revocation checks fail closed. Custom resource fetchers must implement the
bounded-fetch capability contract documented in the API reference. Lower-level
policy parsing, custom source construction, registration, and checkpoint-store
injection remain available
for advanced deployments.

The reader authenticates checkpoints against the pinned log and witness keys
(with anti-rollback via a checkpoint store), verifies Merkle inclusion, and
for records using `dnsid-draft-01` or pre-RFC `DNSid1` verifies the logged
lifecycle: bilateral ISSUANCE binding
of the `ek`/`ku` keys and operational-key continuity. Draft 01 verification
fails closed without a log reader capable of these checks. Current
non-revocation is operation policy, not part of `verify_domain`: callers
gating high-value or irreversible operations should call
`result.log_reader.verify_non_revocation(domain, at)` themselves (liveness is
otherwise covered by the `su` status check).
See the [transparency-log reference](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/transparency-log.md)
and [examples/a2a/startup.py](https://github.com/dnsid-ai/dnsid-py/blob/main/examples/a2a/startup.py) for a complete setup.

## Registry client (authenticated)

**Local (default).** `RegistryClient()` talks to the local registry from
`dnsid local up` at `http://127.0.0.1:7755` unless told otherwise:

```sh
dnsid local up                                # local registry, DNS, and CA in Docker
dnsid local run my-agent -- python app.py     # registers my-agent if needed, runs with DNSID_* set
```

```python
from dnsid import AgentRegistrationInput, registry_client_from_environment

# DNSID_REGISTRY_URL and DNSID_API_KEY when set; otherwise the local registry, no credential.
client = registry_client_from_environment()
client.register_agent(AgentRegistrationInput(domain="agent.example.com"))
client.verify_agent("agent.example.com")
```

To export the same variables into your shell instead of wrapping one command:
`eval "$(dnsid local env my-agent)"`. If nothing is listening, calls fail with
`no registry at 127.0.0.1:7755; run `dnsid local up` or set DNSID_REGISTRY_URL`.

**Hosted.** Set `DNSID_REGISTRY_URL` and `DNSID_API_KEY` from the console; the
same code then talks to the hosted registry. Or pass them explicitly:

```python
from dnsid import RegistryClient

client = RegistryClient("https://api.dnsid.ai", api_key="<console-issued key>")
# Legacy status reads need no credential:
RegistryClient("https://api.dnsid.ai").get_agent_status("agent.example.com")
```

`base_url` must be HTTPS, or HTTP on loopback. Constructors never read the
environment; only `registry_client_from_environment()` does.

Registration defaults to production: `AgentRegistrationInput(domain=...)` for a
domain you control, `zone_id=...` for a delegated zone, `register_live_agent()`
for Live. Pass `environment="sandbox"` for a sandbox agent. `managed=True`
without `zone_id` is rejected.

Mutation calls require owner credentials: an organization session or API key,
passed as `api_key` and sent as an `Authorization: Bearer` header. An agent
bearer token is not sufficient. This also applies to `prepare_key_rotation()`
and the other transparency-log preparation operations.

Self-managed agents prove key possession through a challenge handshake: after
`verify_agent()`, the status document exposes a single-use nonce
(`get_agent_status(domain).raw["challenge"]`); sign the base64url-decoded nonce
bytes with the active key and submit via
`submit_challenge_signature(domain, nonce, signature)`, then poll with
`wait_for_status(domain, target_state="VERIFIED")`. See
[examples/a2a/startup.py](https://github.com/dnsid-ai/dnsid-py/blob/main/examples/a2a/startup.py) for the complete
register → verify → challenge → publish sequence.

Managed Live uses the separate `register_live_agent()` operation. Sign the exact
bytes obtained by base64url-decoding its `challenge_message`, and send proof to
its derived `domain`. A successful `reissue_live_proof()` response supersedes all
older challenges: only the latest challenge and message may be signed or submitted.

Live status requires owner/session/API-key authentication because it can expose
its proof challenge; only legacy status is public. Calling a mutation without
`api_key` raises `ArgumentError` before any request is sent. The credential never
appears in `repr()`/`str()`, exceptions, or logs. See the
[registry reference](https://github.com/dnsid-ai/dnsid-py/blob/main/docs/reference/registry.md) for the full method list and how to
inspect the registry-managed signed record (effective `ku`/`su`).

## Configuration reference

`DnsidConfig` is the single core configuration entry point:

| Section | Type | Default | Description |
|---|---|---|---|
| `identity` | `IdentityConfig` | `None` | Local identity publication settings. Omit for a verification-only manager (no key providers allowed). |
| `verification` | `VerificationConfig` | defaults | Protocol verification policy and counterparty acceptance. Same defaults with or without `identity`. |
| `transport` | `TransportConfig` | defaults | SDK-managed DNS and HTTPS settings. Never mutates injected dependencies. |

`IdentityConfig` fields:

| Field | Required | Default | Description |
|---|---|---|---|
| `domain` | yes | — | Agent FQDN (e.g. `billing-agent.acme.example`) |
| `governance_id` | yes | — | Registrant domain (`gi` tag) |
| `log_ref` | yes | — | Log reference, format `method:entry-ref` |
| `status_url` | yes | — | HTTPS URL for the agent's status endpoint |
| `policy_flags` | no | `""` | Comma-separated flags, e.g. `mtls,logchk` |
| `max_key_age` | no | `""` | Max signing key age: `24h`, `7d`, `30d`, `90d` |
| `ek_url` | no | `""` | Accountable-entity JWKS URL (`ek` tag); required for draft-01 publishing |
| `ku_url` | no | `""` | Agent operational JWKS URL; required for draft-01 publishing |
| `capabilities_url` | no | `""` | HTTPS URL for AGENTS.md or Agent Card |
| `publish_profile` | no | `""` (= `dnsid-draft-01`) | Wire profile emitted when creating records |

`VerificationConfig` fields:

| Field | Default | Description |
|---|---|---|
| `status_check_interval` | `0` (spec-strict) | Cache freshness interval for status re-checks; must be non-negative |
| `dnssec_mode` | `auto` | `auto`, `validated`, or `required` |
| `trusted_entities` | `None` | Counterparty allowlist of `TrustedEntity(governance_id, entity_key_thumbprints=None)`. `None` makes no acceptance decision; `[]` denies all. Matching is exact on the verified `gi` (no wildcard/suffix); optional pins are RFC 7638 SHA-256 thumbprints of the current record-signing key. Denials raise a permanent `VerificationError(COUNTERPARTY_NOT_ACCEPTED)` carrying only the observed `verified_governance_id` / `verified_entity_key_thumbprint`. Acceptance runs on every `verify_domain` call, including cache hits; evidence is cached before acceptance and denials are never cached. |

DNSSEC policy is explicit: `auto` accepts `VALID`, `UNSIGNED`, and `UNKNOWN`
but always rejects `FAILED`; `validated` additionally rejects `UNKNOWN`; and
`required` accepts only `VALID`. Use a custom `DNSResolver` that can distinguish
all four states when selecting `validated` or `required`.

Configuration is validated and snapshotted at construction (invalid values,
duplicate normalized entities, or malformed pins raise `ArgumentError` before
any network work). Transport settings with no SDK-managed consumer are rejected:
`dns_server` when both `dns_resolver` and `https_fetcher` are injected,
`ca_bundle_path` when `https_fetcher` is injected. Constructors never read files
or environment variables; loading is a separate step, below.

`TransportConfig` fields:

| Field | Default | Description |
|---|---|---|
| `dns_server` | `""` | Custom DNS server (e.g. `"8.8.8.8:53"`) |
| `ca_bundle_path` | `""` | Path to custom CA bundle for TLS verification |
| `private_address_hosts` | `frozenset()` | Hostnames allowed to resolve to private addresses; exact, or `.suffix` for a whole zone |

`RegistryConfig` fields:

| Field | Default | Description |
|---|---|---|
| `registry_url` | `""` | DNSid registry base URL; absent lets `RegistryClient` default to the local registry (`http://127.0.0.1:7755`), set `DNSID_REGISTRY_URL` for hosted |

### Loading configuration

Loaders parse; constructors default. Each source has one loader returning a
`LoadedConfig` with only the fields the source actually carries; `merge_loaded_config`
combines them field-wise (later wins, lists replace, `log_trust` is atomic);
`construct_identity_manager` fills `deps.log_registry` from `log_trust` and key providers from
`key_source` when the caller did not supply them, then calls the ordinary
`IdentityManager` constructor. The one-call constructors are exactly
`construct_identity_manager(merge_loaded_config(load_…(), LoadedConfig(dnsid=overlay)), key_provider, deps)`.

```python
from dnsid import (
    identity_manager_from_environment,  # DNSID_* variables
    identity_manager_from_dnsid,        # ~/.dnsid or a DNSid CLI identity directory
    identity_manager_from_file,         # JSON deployment file {"dnsid", "logTrust", "registry"}
    load_environment, load_file, load_cli_directory, merge_loaded_config, construct_identity_manager, LoadedConfig,
)

idm = identity_manager_from_environment()          # under `dnsid local run`: keys, transport, log trust
idm = construct_identity_manager(merge_loaded_config(load_file("dnsid.json"), load_environment()))
```

| Variable | Maps to |
|---|---|
| `DNSID_DOMAIN`, `DNSID_GOVERNANCE_ID`, `DNSID_STATUS_URL`, `DNSID_LOG_REF`, `DNSID_EK_URL`, `DNSID_KU_URL`, `DNSID_PUBLISH_PROFILE`, `DNSID_CAPABILITIES_URL` | `dnsid.identity.*` |
| `DNSID_DNSSEC_MODE` | `dnsid.verification.dnssec_mode` (`auto`, `validated`, `required`) |
| `DNSID_DNS_SERVER`, `DNSID_CA_BUNDLE`, `DNSID_PRIVATE_HOSTS` (comma-separated) | `dnsid.transport.*` |
| `DNSID_LOG_POLICY_URL`, `DNSID_LOG_POLICY_FILE`, `DNSID_LOG_TRUST_PROFILE_FILE` | `log_trust` (exactly one variant; `{"managed": true}` is file/code only) |
| `DNSID_REGISTRY_URL` | `registry.registry_url` |
| `DNSID_API_KEY` | Read directly by `registry_client_from_environment()`; never included in loaded configuration |
| `DNSID_CONFIG_DIR`, `DNSID_KEY_STORE` | `key_source.cli_directory`, `key_source.key_store_path` |

Empty or whitespace-only values are absent. No loader defaults or derives a
value: without `DNSID_DOMAIN` the manager is verification-only; with
`DNSID_DOMAIN` but no `DNSID_LOG_REF`, construction fails with `ArgumentError`
(no placeholder log reference, no `status_url` derived from the registry URL).
Tooling variables (`DNSID_PUBLIC_URL`, `DNSID_AGENT_PORT`, `DNSID_SERVER`, …)
are ignored. In `merge_loaded_config`, default-valued overlays cannot clear
loaded identity strings, `transport.dns_server`/`ca_bundle_path`,
`registry.registry_url` (`""`), `verification.status_check_interval` (zero),
`transport.private_address_hosts` (empty), or `key_source` paths (`None`).
`verification.dnssec_mode=None` is also absent; set `AUTO` explicitly to
replace another mode. To clear a loaded field, edit the merged config before
`construct_identity_manager`. `trusted_entities=[]` is present and denies all.

## Examples

Runnable examples live in [examples/](https://github.com/dnsid-ai/dnsid-py/tree/main/examples). Each subdirectory is self-contained.

| Example | Description | Prerequisites |
|---|---|---|
| [examples/local-key-provider/](https://github.com/dnsid-ai/dnsid-py/tree/main/examples/local-key-provider) | File-backed local key provider demo | None — fully self-contained |
| [examples/a2a/](https://github.com/dnsid-ai/dnsid-py/tree/main/examples/a2a) | Two agents (Alice + Bob) exchanging RFC 9421-signed A2A messages | Testnet environment |
| [examples/validate-domain/](https://github.com/dnsid-ai/dnsid-py/tree/main/examples/validate-domain) | Verify a domain's DNSid identity | None — uses DNSid's public test log |
| [examples/webbotauth/](https://github.com/dnsid-ai/dnsid-py/tree/main/examples/webbotauth) | Sign and verify bot HTTP requests with `WebBotAuthProfile` | None — fully self-contained |
| [examples/oidc/](https://github.com/dnsid-ai/dnsid-py/tree/main/examples/oidc) | Mint and inspect a DNSid OIDC token with `OIDCProfile` | OIDC token endpoint (defaults to `https://oidc.dnsid.ai`) |

### Self-contained example (no testnet needed)

The local-key-provider example runs entirely offline — it demonstrates key
lifecycle, JWKS construction, and JWT signing without any network dependencies:

```bash
source .venv/bin/activate
python examples/local-key-provider/main.py
```

### Testnet-dependent examples

The `a2a` example requires the local testnet managed by the `dnsid` CLI
([installation guide](https://docs.dnsid.ai/cli-installation);
`dnsid testnet up` / `dnsid testnet run`), which provides local DNS, a
CA, and a registry. See
[examples/a2a/README.md](https://github.com/dnsid-ai/dnsid-py/blob/main/examples/a2a/README.md) for full prerequisites and
step-by-step instructions.

### Validate-domain example (no testnet needed)

Verifies a domain's DNSid identity against DNSid's public test log:

```bash
source .venv/bin/activate
python examples/validate-domain/main.py
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check dnsid/

# Type check
mypy dnsid/
```

## Security & trust

**Official sources.** Source: `github.com/dnsid-ai/dnsid-py`. Package: `dnsid` on PyPI. Releases: GitHub Releases on
this repository, each with a CycloneDX SBOM attached. Forks, mirrors, and similarly named packages
are not maintained by us. Report vulnerabilities per [SECURITY.md](SECURITY.md); never in a public issue.

**Software is not identity.** This SDK ships no keys, credentials, or trust. A DNSid identity is proven
by control of a DNS zone, an agent private key, and the registry's published status. Possessing, forking,
or modifying this code grants none of those: an unofficial build cannot mint or inherit anyone's identity.

**What it does on the network.** Only when you call it, and only to hosts you or the domain being verified
chose:

- DNS TXT lookup of `_dnsid.<domain>` through your system resolver (no hardcoded resolver)
- HTTPS GET to the JWKS and status URLs published in that TXT record
- Opt-in only, never contacted unless you configure them: `https://api.dnsid.ai` (registry client), `https://log.dnsid.ai` / `log.dnsid.dev` (C2SP transparency log, bundled public trust roots), cloud KMS endpoints
- No telemetry, usage reporting, update checks, or crash reporting

**Logging.** None today. A standard-library `logging` logger under the `dnsid` namespace is declared for future
use; if it ever emits, it will carry key thumbprints and verification states, never private keys, tokens, or
signatures. Errors are raised to the caller.

**Hosted endpoints.** `api.dnsid.ai` and `log.dnsid.ai` are operated separately from this SDK under their
own terms. Nothing in this repository is an availability, uptime, or support commitment for them.

**For your privacy notice.** Using this SDK causes your system to make DNS and HTTPS requests to the domains
you verify and to the JWKS/status hosts they publish. It sends them nothing about your users. If you enable
the registry or transparency-log clients, requests also go to DNSid-operated endpoints; disclose that where
your notice requires it.

## License

[Apache License 2.0](https://github.com/dnsid-ai/dnsid-py/blob/main/LICENSE.txt)
