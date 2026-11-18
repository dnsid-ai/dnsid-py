# AWS KMS first operational key

Explicit, one-time setup using the existing AWS provider lifecycle. This is not
normal startup, authorized rotation, or a complete DNSid issuance workflow.
Running it creates a **billable remote key on every invocation**. Do not run it
against an established identity or blindly rerun it after an error.

## Prerequisites

Install from the repository root with `pip install -e ".[aws]"`. Use Python
3.11+ and boto3's ambient credential chain (for example, a workload IAM role).
Do not embed credentials in configuration. Select an AWS region supporting
`ECC_NIST_EDWARDS25519` signing keys and grant `kms:CreateKey`, `kms:GetPublicKey`
and `kms:Sign`, allowed by both IAM and the key policy. This example requests
`SIGN_VERIFY` / `ED25519_SHA_512`; no import, export or deletion permissions are
used. No cloud operations are needed merely to read this example.

Supply these application-owned publication settings before running:

- `AWS_REGION`: the selected KMS region.
- `DNSID_DOMAIN`: the agent FQDN; `DNSID_GOVERNANCE_ID`: its accountable entity.
- `DNSID_LOG_REF`: the exact, persisted identity-instance lifecycle reference
  assigned during provisioning, not an invented stream ID.
- `DNSID_STATUS_URL`, `DNSID_EK_URL`, `DNSID_KU_URL`: the planned explicit HTTPS
  status, entity JWKS, and operational JWKS URLs, respectively. The `ku` host
  must equal the agent FQDN; the `ek` host must equal or be beneath the entity.

With real, validated settings and explicit authorization to create a key:

```sh
python examples/aws-kms-first/main.py
```

The script reads required settings before creation; `IdentityManager` validates
the identity configuration later. Invalid settings can therefore still leave a
remote key. The application owns all client/resource lifetimes and recovery.

## Lifecycle and reference handoff

`AwsKmsKeyState(active_key_id="")` is deliberate: the direct provider's explicit
empty-state composition needs no existing key. Omitting `state` is not an
alternative bootstrap recipe. `load` opens configured references only;
`generate_key` explicitly calls KMS creation and validates the public key.

The new key is pending. `jwk(kid)` exposes its public JWK and `sign_key(kid,
payload)` demonstrates pending proof of possession; it does not issue an
identity. `activate(kid)` explicitly selects the local operational signer.
**Local activation is not protocol ISSUANCE or ACTIVE status.**

`kid` is the RFC 7638 public-key thumbprint, not the KMS resource reference.
`state_snapshot()` supplies canonical KMS references. The script prints public
JWKs and state only, does not write state/identity/key/temporary files, and does
not generate or import private material locally. Private key generation and
signing remain inside KMS. Unrelated AWS authentication caches are outside this
no-key-file guarantee.

The application must retain the canonical reference and expected public binding
through its own deployment/state handoff. The in-memory reopen uses exactly
`state.active_key_id` and checks the same thumbprint without another creation.
On subsequent process startup, use only that reopen path with the retained
reference and expected binding; never rerun empty-state generation. Ordinary
configuration construction remains open-only. Once issuance is complete, see
[the published-signing example](../published-signing/) for verified established
startup, including the fresh public-binding check; direct provider reopening
alone does not establish identity status or authorization.

## Publication boundary

Python injects this operational provider via
`IdentityManager(config, key_provider=reopened)`. `manager.get_key_set()` returns
the public JWKS to serve at the configured `ku` URL; the script prints it but
does not host or publish it. Construction/getting JWKS does not verify issuance.

Draft-01 record signing additionally requires a **distinct**, owner-controlled
entity provider via `IdentityManagerDependencies(entity_key_provider=...)`.
When the application owns that signer, the manager's `get_entity_key_set()` and
`create_txt_record()` can produce entity JWKS and the entity-signed record.
This example deliberately does not create an entity key or substitute the
operational signer for it. If an external accountable entity/issuer owns that
key, hand it the operational public JWKS and provisioning settings instead.

That owner/issuer and the deployment workflow must arrange the signed `_dnsid`
record, `ek`/`ku`/status publication, verification of externally served evidence,
and durable entity-signed and operationally countersigned ISSUANCE submission
with verified log acceptance before transitioning status to ACTIVE. This script
performs none of those steps and supplies no fake issuer or successful status.
It is an operational-key/publication-input handoff, not a complete first-run
identity service. Never bypass established startup/publication checks with it.

A failed or indeterminate create/public-key read may leave a billable remote
key, including when the creation response is lost. Stop and reconcile resources
explicitly; there is no automatic retry, local fallback, deletion, or idempotent
provisioning guarantee. Cleanup remains the operator's responsibility.
