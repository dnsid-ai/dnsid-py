# Operational key rotation (Python)

Rotate the operational `ku` key using a file-backed local provider and the DNSid
local testnet. The accountable-entity `ek` key and signed TXT record do not change.
No KMS, hosted registry, or application server is needed.

## Run

Install the DNSid CLI and start Docker. Use a CLI containing the local lifecycle
stream-reference fix (Identity-Digital/dnsid commit `d3983568` or later); older
builds export the domain instead of the registry's immutable agent ID.

From this SDK's repository root:

```sh
uv sync --locked
dnsid local up
dnsid local agent ensure rotate-py --upstream http://localhost:7901 -- \
  dnsid log issue --domain rotate-py.test
sleep 3 # allow the local DNS zone to reload
dnsid local run rotate-py --upstream http://localhost:7901 -- \
  uv run python examples/key-rotation/main.py
```

The upstream is unused: the testnet registry hosts the managed public JWKS,
status, and log. Use the default testnet ports. Keep `DNSID_LOG_POLICY_URL`
independently configured by the CLI; never infer trust from the identity's `lr`.

## What is checked

1. The current local key signs a JWS that verifies against the published identity.
2. The SDK generates a pending successor and signs one KEY_ROTATION with the old
   key's authorization and the new key's proof of possession.
3. Before submission, the complete signed bytes and idempotency key are saved
   durably, then application signing is paused.
4. The registry publishes **only the new key** before appending the event. During
   this interval, continuity verification fails closed.
5. After acceptance, the SDK verifies fresh TXT/JWKS and log continuity for its
   own identity before local activation. Counterparty acceptance policy does not
   apply to this check. Activation is saved before signing resumes.
6. A new-key JWS verifies. After explicit identity refresh, the old-key JWS fails
   with `KeyNotFound`, and the old key is absent from the provider and live JWKS.

Expected state output:

```text
saved: prepared, activated=False, paused=True
saved: accepted, activated=False, paused=True
saved: accepted, activated=True, paused=True
saved: accepted, activated=True, paused=False
rotation verified: <old kid> -> <new kid>
```

Pending results retry the saved operation, not a new rotation. Network or local
reconciliation errors stop the example; rerun the **same command** to resume.
A saved state with `activated` true and `paused` false is terminal. Resuming it
only checks the local key; it does not pause signing or contact the registry,
DNS, or the log. A service archives that state and starts its next scheduled
rotation with a new one.

## Saved state and limits

State is under `$DNSID_CONFIG_DIR/rotation-py/`:

- `keys.json`: the durable active/pending key store, seeded once from the CLI's
  private JWK, never regenerated during recovery;
- `rotation.json`: exact signed bytes, hash, idempotency key, provider binding,
  acceptance, and activation/pause state;
- `old-message.json`: the pre-rotation signature used for the rejection check.

Files are written with owner-only permissions and atomic replacement plus file
and directory sync. Keep the directory private. **Do not delete or edit these
files to retry a failed rotation.** Use a different local agent name for another
independent demonstration.

Run only one process against this directory. The signing controller gates this
single-process example's signing function; a service must also block new signing
requests and drain in-flight signatures. Do not copy its Boolean gate into a
concurrent service without that coordination.

The original CLI bootstrap keys remain in the agent directory. They are not the
application signer after rotation; use the example's saved provider, not the
CLI's original key, for subsequent signing. Provider backup files can also contain
old private keys. This example does not securely erase archived key material.

Verifiers with cached pre-rotation evidence can accept old signatures or reject
new signatures until refresh/expiry. This is an immediate cutover, not an overlap
window. Historical log verification is separate from current application-signature
acceptance. Loss or suspected compromise of the previous key requires revocation
and reissuance, not this rotation flow.
