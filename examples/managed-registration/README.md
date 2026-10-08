# Managed registration

One SDK call registers a named dev sandbox identity, completes ISSUANCE/publication,
and verifies fresh public `ACTIVE` evidence. The example creates no challenge server.

**Requires the managed-workflow server changes.** Their prerequisites remain
outstanding; this example is not validated against a deployed service.
Use Python 3.11+, durable POSIX local storage, public DNS/HTTPS access, and a dev
organization API key with verified onboarding for `dev.dnsid.ai` and entity delegation.

## Run

```sh
python -m pip install .
mkdir -p "$HOME/.dnsid-examples"
export DNSID_API_KEY="<dev-organization-api-key>"
python examples/managed-registration/main.py billing-agent \
  --state-dir "$HOME/.dnsid-examples/managed-registration-py"
```

Success prints the assigned domain and `status=ACTIVE`. This leaves a real identity
active and creates a permanent transparency-log entry.

The code fixes dev registry, expected GI/entity-key URL, and managed log trust.
Organization ID comes from verified onboarding. Name/public-key-only creation selects
the default sandbox. Other `DNSID_*` settings are ignored; only `DNSID_API_KEY` is read,
and the credential is neither saved nor printed. Local keys warn against production use.

## Recovery

Names are trimmed, case-sensitive handles of 1–255 Unicode code points.
Rerun with the **same name and directory**. The SDK owns locking, retries within one
five-minute deadline, exact-byte recovery, accepted-entry retrieval, and fresh checks.
Back up the entire directory, including `operations/` and private `keys/`.
Do not delete live lock sidecars or change names/directories after an unknown outcome.

Old manual files and schema versions 1/2 are not migrated; recover them with earlier
code. Missing keys, conflicts, and terminal identities fail without automatic replacement.
This example does not request replacement or support Live/client-controlled publication.

Retire through the registry before discarding the key. Success does not itself prove
authenticated DNSSEC.

## Offline checks

```sh
python -m pytest tests/test_managed_registration_example.py tests/test_managed_registration.py
```
