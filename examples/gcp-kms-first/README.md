# Google KMS first operational key

Explicit one-time setup, not normal startup or established-identity rotation.
Install `pip install -e ".[gcp]"` from the repository root. Use Google's ambient
credentials and an existing CryptoKey with `ASYMMETRIC_SIGN` purpose and a
`SOFTWARE` / `EC_SIGN_ED25519` version template; zero existing versions is valid.
Set `GOOGLE_KMS_CRYPTO_KEY` to its fully qualified `projects/.../locations/.../keyRings/.../cryptoKeys/...`
name, not an alias or version. Grant CryptoKey metadata read, version creation,
version metadata/public-key read, and asymmetric signing permissions. No parent
provisioning, import, export or deletion permissions are used.

Supply the same `DNSID_DOMAIN`, `DNSID_GOVERNANCE_ID`, `DNSID_LOG_REF`,
`DNSID_STATUS_URL`, `DNSID_EK_URL`, and `DNSID_KU_URL` settings documented in
[the AWS setup prerequisites](../aws-kms-first/#prerequisites). With valid settings
and explicit authorization to create a billable version:

```sh
python examples/gcp-kms-first/main.py
```

Every invocation creates another remote version. Required settings are read
first, but manager identity validation happens after creation: invalid settings
can leave a remote resource. Never blindly rerun after failure or an indeterminate
response. Reconcile resources explicitly; no automatic recreate/delete/fallback
or idempotence guarantee is provided. Readiness polling is bounded, not a promise
that every remote generation completes within that bound.

`create` returns `(provider, kid, immutable_version_reference)`. The public JWK
thumbprint `kid` is not the resource reference. The ready remote version remains
**locally pending**: `sign_key` can prove possession, but ordinary signing needs
explicit `activate(kid)`. The application must retain the reference and expected
public binding through its own deployment handoff. The script prints only public
material and does not write files or generate/import private keys locally. It
reopens exactly that immutable version and checks its thumbprint without creating
again. Subsequent startup uses only reopen, not `create`; normal configuration
remains open-only. The application closes its own client.

The actual manager injection is `IdentityManager(config, key_provider=reopened)`;
`get_key_set()` supplies public operational JWKS for the configured `ku` endpoint.
This is publication input, not verified publication or a protocol ACTIVE identity.
The [AWS publication boundary](../aws-kms-first/#publication-boundary) applies
unchanged: a **distinct owner-controlled entity signer**, signed `_dnsid` record,
public endpoints, verified log acceptance and externally verified issuance/status
convergence are still required. This script performs none of those steps, creates
no local entity key, and does not bypass established startup/publication checks.
