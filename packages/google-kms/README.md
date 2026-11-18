# DNSid Google Cloud KMS provider

Optional synchronous software Ed25519 signing support for the Python DNSid SDK.

```sh
pip install dnsid-google-kms
```

```python
from google.cloud import kms_v1
from dnsid_google_kms import GoogleKmsKeyProvider

provider = GoogleKmsKeyProvider(
    kms_v1.KeyManagementServiceClient(),
    "projects/my-project/locations/global/keyRings/agents/cryptoKeys/agent/cryptoKeyVersions/7",
)
signature = provider.sign(b"application payload")
public_jwk = provider.signing_key()
```

Use an existing immutable numeric `CryptoKeyVersion` with software
`EC_SIGN_ED25519`. Credentials come from Google's ambient Application Default
Credentials chain, not from deployment settings. KMS permissions must allow
public-key access and signing. The base `dnsid` distribution does not install
Google dependencies or export this provider.

Configuration selects `provider="google-kms"` with `key_ref` set to the full
version name (`keySource.keyRef` in deployment JSON). Optional
`settings={"algorithm": "EdDSA"}` is the only supported setting; never put raw
credentials or private keys in configuration. Construction opens the existing
version and verifies published identity bindings; it never generates a key or
falls back to another signer.

`generate_key()` creates a pending version under the configured parent using its
version template. The returned version must be enabled software Ed25519. The
active signer and current-only `list_key_ids()` are unchanged until explicit
`activate(kid)`. Pending `jwk(kid)` and `sign_key(kid, payload)` support rotation
proof. Previous or superseded keys cannot sign. `supersede(kid)` changes only
local eligibility, never disables or destroys a cloud version.

State is process-local. Application-owned persistence, publication, rotation
authorization and recovery orchestration are outside this package. Reopening an
explicit version selects it as the initial signer; it does not restore earlier
pending or superseded state. Native service failures propagate without signer
fallback. Signing uses raw data, with immutable-version and CRC32C checks; public
JWK IDs are RFC 7638 thumbprints and contain no private material.

See the [SDK README](https://github.com/dnsid-ai/dnsid-py#google-cloud-kms-key-provider)
and [API reference](https://docs.dnsid.ai/reference/py/key-providers/).

## Explicit initial named-key bootstrap

```python
from dnsid_google_kms import create_or_reuse_google_kms_key_provider

client = kms_v1.KeyManagementServiceClient()  # caller owns and closes this client
result = create_or_reuse_google_kms_key_provider(
    client,
    parent="projects/my-project/locations/global/keyRings/agents",
    crypto_key_id="stable-org-agent-name",
)
# Persist result.key_version_name; use result.provider for operational signing.
# Only AFTER success, separately invoke your application's explicit agent-ID
# create/reuse action. Bootstrap itself never performs that action.
```

Choose a stable collision-free ID per identity; no normalization is applied.
The existing project/location/key ring and read/create/sign permissions are
prerequisites. This opt-in operation reuses the exact named CryptoKey or creates
it only after a typed NotFound, rereading a concurrent AlreadyExists winner once.
All routes require enabled software Ed25519 version **1** and validated public
material. No polling, extra version, ancestor creation, repair or fallback occurs;
native failures propagate, including uncertain create outcomes. The SDK adds no
retry policy. A separate explicit invocation can reuse a committed key later.
The returned result is frozen, and the injected client remains caller-owned.

For rotated identities, reopen the persisted authorized immutable version with
`GoogleKmsKeyProvider`, not bootstrap. Construction, config loading and explicit
pending-version generation remain unchanged. Keys come first; agent IDs are a
separate explicit application step. The server never creates these keys.
