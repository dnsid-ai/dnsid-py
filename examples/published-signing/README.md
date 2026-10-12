# Published signing identity

Load one deployment file, select its existing operational key provider, verify
the identity's public DNSid evidence, and sign an RFC 9421 HTTP request without
sending it. The application code is the same for both custody configurations.

This example does not register identities, generate keys, rotate keys, delete
keys, or recover failed operations.

## Prerequisites and placeholders

- Python 3.11 or later and this checkout.
- An already published, ACTIVE DNSid draft-01 identity, with its DNS record,
  entity and operational JWKS endpoints, status endpoint, and verified lifecycle
  log history available.
- Network access to DNS, HTTPS publication endpoints, and the trusted log.
  AWS custody also requires access to AWS KMS.
- The existing operational signing key and its published `kid`.

Both JSON files are templates, not runnable deployments. Replace
`agent.example`, `example.com`, and all corresponding URLs with the identity's
persisted publication settings. Replace `<persisted lifecycle-log reference>`
with its exact existing `lr` reference, including the identity-instance stream
ID. Do not invent a new reference or derive endpoint paths at startup.
Replace `<immutable signing-key ARN>` in `aws-kms.json` with the existing
signing-key ARN, not an alias. In `file.json`, `./keys.json` is a placeholder
path to the existing SDK `LocalKeyProvider` key-store file, not a bare private
JWK. Relative paths resolve from the process working directory, not the
deployment file's directory.

This branch's deployment schema calls the entity JWKS URL `ekUrl` and the
operational JWKS URL `kuUrl`. These correspond to `entityKeyUrl` and `keyUrl`
in the conceptual deployment configuration.

These files are **alternative custody configurations**, not a way to switch
between two interchangeable keys. Each configuration must reference the key
already bound to the identity it describes. If the published key is in KMS,
an unrelated local key cannot sign for that identity.

## Log trust

`logTrust.managed: true` is valid **only** for an identity on a supported
DNSid-managed log. It selects the SDK's embedded managed trust catalog; it does
not make an arbitrary log trusted.

For another log, replace the whole `logTrust` section with an independently
trusted policy URL, for example:

```json
{
  "logTrust": {
    "policyUrl": "https://trusted-log-operator.example/tlog-policy"
  }
}
```

That URL is also a placeholder. Obtain the policy and its verification keys
through your deployment's trusted configuration, not the identity being
verified, its `lr`, or its log prefix. Alternatively, use `logTrust.profile`
with a complete independently trusted
`dnsid-c2sp-tlog-trust-profile@v1` document. Select exactly one trust variant.
Applications with a custom log binding can supply an independently configured
`IdentityManagerDependencies(log_registry=...)` to
`construct_identity_manager` instead.

## Installation and provider linking

Run from the repository root:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[aws]"
```

The editable install links this checkout. The AWS provider is built into
`dnsid`; the `aws` extra installs boto3. No provider registry call or separate
AWS provider package is needed. For file custody alone, `pip install -e .`
is sufficient. The loader selects the provider from `keySource.provider`;
it does not fall back to local keys if AWS is unavailable.

### AWS KMS

Use an existing enabled asymmetric `ECC_NIST_P256`, `SIGN_VERIFY` KMS key
for this ES256 configuration. Its public key and `kid` must match the
current operational JWKS. The SDK maps ES256 to KMS `ECDSA_SHA_256`.

Authentication uses boto3's ambient credential chain: for example, a workload
IAM role or a locally authenticated AWS profile. For a local profile:

```sh
aws sso login --profile signing-dev
AWS_PROFILE=signing-dev python examples/published-signing/main.py examples/published-signing/aws-kms.json
```

Replace `signing-dev` with your configured profile. On a workload with ambient
role credentials, omit `AWS_PROFILE`. The template selects `us-east-1`; use
the existing key's region.

The runtime principal needs `kms:GetPublicKey` and `kms:Sign` on the selected
key ARN, with access allowed by the KMS key policy as well as applicable IAM
policy. No `kms:CreateKey`, `kms:ScheduleKeyDeletion`, or rotation permission
is needed. Do not put AWS credentials in deployment JSON.

### Local files: development only

Point `keyRef` at the existing key store and restrict its filesystem permissions
(for example, `chmod 600 /path/to/keys.json`). Do not commit private keys or
embed them in deployment JSON. The SDK opens the existing file without creating
a key and emits a warning because local file custody is unsuitable for
production.

```sh
python examples/published-signing/main.py examples/published-signing/file.json
```

## Checks and output

`load_file` parses the selected deployment; `construct_identity_manager`
validates configuration, builds the selected trust binding, and opens the
existing provider. AWS loading calls `GetPublicKey` and validates key usage
and algorithm. Log-policy loading may perform HTTPS requests.

On this branch, construction does **not** automatically verify the published
identity or compare its operational key with the provider. The example
therefore calls `verify_domain` on its own domain, which verifies the public
record, JWKS, lifecycle binding, and ACTIVE status. It then requires one current
operational key and compares both `kid` and RFC 7638 thumbprint before signing.
Any failure stops signing; there is no recovery or fallback. Identities with
`fl=mtls` also require a real peer TLS certificate for verification; this minimal
example does not supply one.

The output contains the unsent request and its signature headers. The request
target `https://receiver.example/resource` is a placeholder and is never
contacted. "Without sending" applies to this HTTP request, not verification
traffic or the AWS KMS `Sign` call. The private AWS key never leaves KMS.

Changing `keyRef` does not authorize rotation. A different key will fail the
publication check unless it is already the identity's current, authorized
operational key. The normal lifecycle and publication process must happen
outside this example before using a replacement.

Offline regression check (verification is mocked; signing is real):

```sh
uv run --frozen --extra dev pytest -q tests/test_published_signing_example.py
```
