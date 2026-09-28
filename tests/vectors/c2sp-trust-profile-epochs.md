# Trust profile v2 (epochs) conformance vector

`c2sp-trust-profile-epochs-v1.json` (format `dnsid-c2sp-trust-profile-epochs@v1`) is the shared,
language-neutral vector for DNSid C2SP trust profile version 2. dnsid-go, dnsid-ts and dnsid-py
must all pass every case in this exact file. Do not hand-edit it. Regenerate it from dnsid-go:

```sh
DNSID_UPDATE_TRUST_EPOCH_VECTORS=1 go test -run TestTrustEpochVectors ./log/c2sptlog
```

The generator is `log/c2sptlog/trust_epoch_vectors_gen_test.go`. Output is deterministic:
Ed25519 keys come from fixed, published test seeds, and Ed25519 signatures are deterministic.
The Go test fails if the checked-in file differs from a fresh generation. **Every key in the file is
a disposable test key. None of them is, or protects, a DNSid deployment key.**

## Scenario

One log origin (`parameters.origin`, from `parameters.log_prefix`) rotates its log signing key,
its witness key and its stream-bundle key at tree size `N` (`parameters.n`). The tree is the same
before and after the rotation. The `legacy` epoch holds the old keys; the `successor` epoch holds
the new ones. Both witness keys use the same witness name and differ only in key hash, so a verifier
that matches witnesses by name alone fails the cross-epoch cases.

## Encodings

- Checkpoints (`checkpoint`) are complete C2SP signed notes, as UTF-8 text.
- Profiles (`profiles.*`, `profile_cases[].document`) are complete trust-profile JSON documents,
  carried as **raw text**, never as parsed JSON objects. Feed the exact string to the SDK's
  trust-profile parser, without parsing and re-serializing it first: several profile cases exist
  only to test a literal JSON token (for example `5.0` or `5e0` as a bound), which re-serialization
  would erase. The `tlog_policy` strings inside are the exact policy bytes that `policy_hash`
  covers.
- Bundles (`bundle`) are complete canonical-JCS stream bundles (`dnsid-c2sp-stream-bundle@v1`), as
  text.
- `tree.entries`, `tree.fork_entries`, `tree.roots`, `tree.fork_roots`, `consistency_proof[]` and
  `trusted_after.root_hash` use standard base64 with padding. `tree.roots` maps a decimal tree size
  to its RFC 6962 root. The fork tree differs from the main tree only at index `N-1`, so
  `fork_roots` lists sizes `N` and up.
- Times are Unix seconds. Use `parameters.now` as the verifier clock for every case.

## Verifier configuration

Every case runs with `checkpoint_max_age_seconds`, `max_bundle_lifetime_seconds` and
`clock_skew_seconds` from `parameters`, the scope and log prefix from the profile, and the reference
`parameters.lr`.

## Rules under test

1. **Profile.** `version: 1` is one unnamed epoch (id `""`) with no bounds, and must not contain
   `epochs`. `version: 2` must not contain top-level `tlog_policy` or `bundle_verifier_keys`, even
   empty, and has 1 to 8 `epochs`. Each epoch has `id` (1-64 of `A-Z a-z 0-9 . _ -`, unique),
   `tlog_policy` (exactly one `log` line, key named for the origin), `bundle_verifier_keys` (named
   `dnsid-stream-bundle`, distinct, and independent of that epoch's log and witness keys), and
   optional `min_tree_size` / `max_tree_size` (absent or `null` is open; min must not exceed max).
   A bound is **lexical**: its JSON value must be a number token matching `^[1-9][0-9]*$` whose
   value is at most 2^53-1 (`9007199254740991`). So `5.0`, `5e0`, `5E0`, `true`, `"5"`, `-1`, `0`,
   leading zeros and `9007199254740992` are all rejected, even where the value equals an accepted
   one. `JSON.parse` in JavaScript and `json.loads` in Python cannot see the token, so check it
   from the raw text (a JSON reviver with source access, or a raw-token check in TypeScript; in
   Python, `parse_int`/`parse_float` hooks plus rejecting `bool`). No two epochs may share both a bundle key ID and a `tlog_policy`.
   Member names match **exactly, including case**, at the top level and in every epoch. Version 1
   allows exactly `version`, `scope`, `log_prefix`, `tlog_policy`, `bundle_verifier_keys`; version
   2 allows exactly `version`, `scope`, `log_prefix`, `epochs`; an epoch allows exactly `id`,
   `tlog_policy`, `bundle_verifier_keys`, `min_tree_size`, `max_tree_size`. Any other member,
   including a case variant such as `Scope` or `Max_Tree_Size`, is rejected, and so is a document
   that pairs a member with its case variant (`member-case-*` cases). Decoders that match field
   names case-insensitively (Go `encoding/json`, some Python and TS schema libraries) must check the
   raw member names separately.
2. **Checkpoint.** Verify each epoch separately, using only that epoch's log and witness keys, in
   profile order. An epoch is *relevant* when the note carries at least one signature line whose
   name and key hash equal that epoch's log key, **whether or not the signature bytes verify**. For
   a relevant epoch, check in this order: the log signature (an invalid line under the epoch's log
   key fails here with `log_signature`), the tree-size bounds, the witness quorum (by witness name
   **and** key hash), then freshness. Accept on the first epoch that passes every check, and report
   its id. If none passes, the reason is the failure of the **first relevant epoch** in profile
   order, or `log_signature` when no epoch is relevant. An invalid line under one epoch's key must
   not fail the note for another epoch: ignore lines whose key the epoch being checked does not
   hold (`forged-legacy-line-*` cases).
3. **Bundle.** Candidate epochs are **all** epochs whose `bundle_verifier_keys` contain `sig.kid`,
   in profile order; none gives `bundle_signer`. A kid may be in several epochs (profile
   `v2-shared-bundle-key`), so do not stop at the first match. The bundle signature must verify
   under a candidate. The selected epoch is the candidate whose `tlog_policy` SHA-256 equals
   `policy_hash`; none gives `policy_hash`. The
   embedded checkpoint must then satisfy the selected epoch alone (rule 2 with one epoch), and the
   rest of bundle verification is unchanged from v1.
4. **Continuity.** Trusted state is `(origin, tree_size, root_hash)` with no key, so it carries
   across epochs. A smaller size is `rollback`; an equal size needs an equal root (`root_conflict`
   otherwise) and is a no-op; a larger size needs an RFC 6962 consistency proof from the stored size
   (`consistency_failed` otherwise). A checkpoint that fails rule 2 never touches the store.

## Case types

| Array | Run | Expected fields |
|---|---|---|
| `profile_cases` | Parse `document`. | `expect.result`; on accept, `epoch_ids` in order (`""` for version 1). |
| `checkpoint_cases` | Build the verifier from `profiles[profile]`, verify `checkpoint` statelessly. | `expect`; on accept, `expect.epoch` and the checkpoint size `tree_size`. |
| `bundle_cases` | Build bundle trust from `profiles[profile]`, verify `bundle` statelessly. | `expect`; on accept, `expect.epoch`. |
| `continuity_cases` | Start with an empty trusted store. For each step, verify `checkpoint`, then advance the store using `consistency_proof` as the proof from the stored size. | Per step `expect`, and `trusted_after` (the stored state after the step, or `null`). |

`expect.result` is `accept` or `reject`. On reject, `expect.reason` is one of `reason_codes`. Match
reasons to your SDK's errors in your own test harness; the codes, not error strings, are the
contract. `tags` mark coverage: `T7-6` is the dnsid-infra prod-account-cutover runbook gate
(legacy ≤ N verifies, successor ≥ N verifies, legacy past N fails with `max_tree_size = N`,
successor below N fails with `min_tree_size = N`).
