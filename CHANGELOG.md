
## [0.20.0] - 2026-09-22

### Features

- feat: verify against a private registry such as dnsid local ([#22](https://github.com/dnsid-ai/dnsid-py/pull/22))


## [0.19.4] - 2026-09-22

### Chores

- ci: publish to PyPI via trusted publishing; document GitHub install fallback ([#11](https://github.com/dnsid-ai/dnsid-py/pull/11))

### Other

- perf: Preload lifecycle history concurrently with the ku fetch ([#16](https://github.com/dnsid-ai/dnsid-py/pull/16))


## [0.19.3] - 2026-09-21

### Other

- registry: accept sandbox environment in agent registration ([#13](https://github.com/dnsid-ai/dnsid-py/pull/13))


## [0.19.2] - 2026-09-21

### Bug Fixes

- fix: set correct codeowners ([#3](https://github.com/dnsid-ai/dnsid-py/pull/3))

### Chores

- Bump taiki-e/install-action from 2.87.11 to 2.87.12 ([#1](https://github.com/dnsid-ai/dnsid-py/pull/1))
- ci: sign release PR commits via GitHub API ([#5](https://github.com/dnsid-ai/dnsid-py/pull/5))
- ci: sign regenerated-docs commits via GitHub API ([#7](https://github.com/dnsid-ai/dnsid-py/pull/7))
- Chore/public release cleanup ([#10](https://github.com/dnsid-ai/dnsid-py/pull/10))

### Documentation

- docs: describe registration positively ([#9](https://github.com/dnsid-ai/dnsid-py/pull/9))

### Features

- Add release-readiness check from dnsid-sdk-compliance ([#4](https://github.com/dnsid-ai/dnsid-py/pull/4))

### Other

- perf(manager): run post-sg identity and status work concurrently in verify_domain ([#6](https://github.com/dnsid-ai/dnsid-py/pull/6))
- registry: default register_agent environment to production ([#8](https://github.com/dnsid-ai/dnsid-py/pull/8))
- examples(validate-domain): support the local registry via dnsid local env ([#12](https://github.com/dnsid-ai/dnsid-py/pull/12))


## [0.19.1] - 2026-09-15

### Chores

- chore: add copyright line to NOTICE header ([#188](https://github.com/dnsid-ai/dnsid-py/pull/188))

### Other

- Feedback/ssrf suffix allowlist and design shoulds ([#230](https://github.com/dnsid-ai/dnsid-py/pull/230))


## [0.19.0] - 2026-09-15

### Bug Fixes

- fix: persist local key stores atomically under a transaction lock ([#223](https://github.com/dnsid-ai/dnsid-py/pull/223))
- fix: thumbprint kids for generated keys; registration id, JWK.from_dict, cancel_agent, typed registry errors ([#225](https://github.com/dnsid-ai/dnsid-py/pull/225))
- fix: read the peer TLS certificate from httpx's network stream ([#227](https://github.com/dnsid-ai/dnsid-py/pull/227))

### Chores

- chore(deps): bump taiki-e/install-action from 2.85.13 to 2.87.11 ([#228](https://github.com/dnsid-ai/dnsid-py/pull/228))

### Features

- feat: add durable checkpoint trust and recovery diagnostics ([#224](https://github.com/dnsid-ai/dnsid-py/pull/224))
- feat: consolidate DnsidConfig and add counterparty acceptance ([#229](https://github.com/dnsid-ai/dnsid-py/pull/229))


## [0.18.0] - 2026-09-09

### Bug Fixes

- fix: bind Live proof reissue to original key ([#211](https://github.com/dnsid-ai/dnsid-py/pull/211))
- fix: align verification and C2SP  ([#214](https://github.com/dnsid-ai/dnsid-py/pull/214))


## [0.17.0] - 2026-09-03

### Bug Fixes

- fix: enforce stream bundle policy in ReadEvent ([#202](https://github.com/dnsid-ai/dnsid-py/pull/202))
- fix: log evidence url policy ([#203](https://github.com/dnsid-ai/dnsid-py/pull/203))
- fix: close status and C2SP verifier gaps ([#205](https://github.com/dnsid-ai/dnsid-py/pull/205))
- fix: check in uv.lock file ([#207](https://github.com/dnsid-ai/dnsid-py/pull/207))
- fix: close predecessor verification gaps ([#208](https://github.com/dnsid-ai/dnsid-py/pull/208))

### Chores

- chore(deps): bump taiki-e/install-action from 2.85.10 to 2.85.13 ([#189](https://github.com/dnsid-ai/dnsid-py/pull/189))

### Features

- Add security baseline config ([#197](https://github.com/dnsid-ai/dnsid-py/pull/197))
- feat: add C2SP tlog trust profiles ([#199](https://github.com/dnsid-ai/dnsid-py/pull/199))
- feat: verify C2SP migrations recursively ([#206](https://github.com/dnsid-ai/dnsid-py/pull/206))
- feat: align registry client with Live API ([#209](https://github.com/dnsid-ai/dnsid-py/pull/209))
- feat: add production trust profile ([#210](https://github.com/dnsid-ai/dnsid-py/pull/210))

### Other

- perf: use C2SP stream bundles by default ([#201](https://github.com/dnsid-ai/dnsid-py/pull/201))


## [0.16.0] - 2026-08-27

### Features

- feat: expose runtime integration helpers ([#196](https://github.com/dnsid-ai/dnsid-py/pull/196))

### Other

- perf: coalesce verification and reuse HTTP connections ([#193](https://github.com/dnsid-ai/dnsid-py/pull/193))


## [0.15.0] - 2026-08-24

### Bug Fixes

- fix(examples): point validate-domain at a live sandbox domain ([#182](https://github.com/dnsid-ai/dnsid-py/pull/182))
- fix: trust testnet log policy URL from environment ([#191](https://github.com/dnsid-ai/dnsid-py/pull/191))
- fix: enforce mTLS verification correctness ([#192](https://github.com/dnsid-ai/dnsid-py/pull/192))

### Chores

- chore(deps): bump taiki-e/install-action from 2.85.5 to 2.85.10 ([#180](https://github.com/dnsid-ai/dnsid-py/pull/180))
- chore(deps): bump actions/attest-build-provenance from 4.1.1 to 4.2.2 ([#181](https://github.com/dnsid-ai/dnsid-py/pull/181))
- ci: fix never-running compliance gate; call the extracted compliance repo ([#184](https://github.com/dnsid-ai/dnsid-py/pull/184))
- chore: point CODEOWNERS at the sdk-maintainers team ([#187](https://github.com/dnsid-ai/dnsid-py/pull/187))

### Documentation

- Document SDK security operations guidance ([#179](https://github.com/dnsid-ai/dnsid-py/pull/179))
- docs: align signed-commits wording with actual enforcement ([#186](https://github.com/dnsid-ai/dnsid-py/pull/186))

### Features

- feat: add c2sp-tlog verification registry ([#190](https://github.com/dnsid-ai/dnsid-py/pull/190))


## [0.14.0] - 2026-08-07

### Bug Fixes

- fix: load authoritative publication configuration ([#169](https://github.com/dnsid-ai/dnsid-py/pull/169))
- fix: enforce authoritative publication key age ([#170](https://github.com/dnsid-ai/dnsid-py/pull/170))
- fix: align HTTP signatures with corrected profile ([#171](https://github.com/dnsid-ai/dnsid-py/pull/171))
- fix: a2a stuff ([#172](https://github.com/dnsid-ai/dnsid-py/pull/172))

### Chores

- chore(deps): bump taiki-e/install-action from 2.85.2 to 2.85.5 ([#161](https://github.com/dnsid-ai/dnsid-py/pull/161))
- ci: auto-regenerate reference docs on PR branches ([#173](https://github.com/dnsid-ai/dnsid-py/pull/173))
- chore: add NOTICE ([#174](https://github.com/dnsid-ai/dnsid-py/pull/174))

### Features

- feat!: remove dnsid-testpy package command ([#167](https://github.com/dnsid-ai/dnsid-py/pull/167))
- feat: prepare for public release ([#163](https://github.com/dnsid-ai/dnsid-py/pull/163))
- feat: add revoke ops ([#176](https://github.com/dnsid-ai/dnsid-py/pull/176))


## [0.13.0] - 2026-08-03

### Features

- feat: align registry and verifier APIs ([#164](https://github.com/dnsid-ai/dnsid-py/pull/164))

### Chores

- chore: adopt Apache-2.0 licensing and harden package/release publishing ([#163](https://github.com/dnsid-ai/dnsid-py/pull/163))


## [0.12.1] - 2026-08-03

### Chores

- chore: harden public release surface ([#160](https://github.com/dnsid-ai/dnsid-py/pull/160))


## [0.12.0] - 2026-07-31

### Bug Fixes

- fix: align c2sp lifecycle semantics ([#157](https://github.com/dnsid-ai/dnsid-py/pull/157))
- fix: add support for es256 ([#158](https://github.com/dnsid-ai/dnsid-py/pull/158))

### Chores

- chore(deps): bump taiki-e/install-action from 2.83.4 to 2.85.2 ([#143](https://github.com/dnsid-ai/dnsid-py/pull/143))
- chore(deps): bump actions/checkout from 7.0.0 to 7.0.1 ([#142](https://github.com/dnsid-ai/dnsid-py/pull/142))

### Documentation

- docs: fix method-heading rendering and Sphinx role leaks in the reference ([#154](https://github.com/dnsid-ai/dnsid-py/pull/154))

### Features

- feat: close SDK design conformance gaps ([#156](https://github.com/dnsid-ai/dnsid-py/pull/156))
- feat: enforce public C2SP transport guarantees ([#159](https://github.com/dnsid-ai/dnsid-py/pull/159))


## [0.11.0] - 2026-07-29

### Bug Fixes

- fix: preserve pre-1.0 breaking release bumps ([#152](https://github.com/dnsid-ai/dnsid-py/pull/152))
- fix: bugs identified during compliance testing ([#153](https://github.com/dnsid-ai/dnsid-py/pull/153))

### Documentation

- docs: generated API reference, Google docstrings, py.typed ([#148](https://github.com/dnsid-ai/dnsid-py/pull/148))

### Features

- feat: export all application profiles at package root (TS-SDK parity) ([#151](https://github.com/dnsid-ai/dnsid-py/pull/151))
- feat!: revise DNSSEC verification policy ([#150](https://github.com/dnsid-ai/dnsid-py/pull/150))


## [0.10.0] - 2026-07-28

### Features

- feat: enforce strict lifecycle state machine ([#146](https://github.com/dnsid-ai/dnsid-py/pull/146))


## [0.9.1] - 2026-07-27

### Bug Fixes

- fix: updates to address design conformance ([#144](https://github.com/dnsid-ai/dnsid-py/pull/144))


## [0.9.0] - 2026-07-27

### Bug Fixes

- fix: update to account for new design doc version handling ([#134](https://github.com/dnsid-ai/dnsid-py/pull/134))

### Other

- Align/compliance complete ([#141](https://github.com/dnsid-ai/dnsid-py/pull/141))


## [0.8.0] - 2026-07-22

### Bug Fixes

- fix: refuse v=DNSid1 signature verification (parse-only, fail-safe) ([#115](https://github.com/dnsid-ai/dnsid-py/pull/115))
- Fix DNSid1 signing canonicalization: sort all tags alphabetically (v= last) for dnsid-draft-01/DNSid1 ([#117](https://github.com/dnsid-ai/dnsid-py/pull/117))
- fix: SSRF host-pinning for su URL and restore VERIFY_X509_STRICT (#17, #18) ([#119](https://github.com/dnsid-ai/dnsid-py/pull/119))
- fix: allow registry-hosted su URLs; keep fetch-time SSRF bounds (revisits #17) ([#121](https://github.com/dnsid-ai/dnsid-py/pull/121))

### Chores

- chore: add security policy and ops docs ([#118](https://github.com/dnsid-ai/dnsid-py/pull/118))
- chore(deps): bump actions/setup-python from 6.3.0 to 7.0.0 ([#124](https://github.com/dnsid-ai/dnsid-py/pull/124))
- chore(deps): bump taiki-e/install-action from 2.83.2 to 2.83.4 ([#125](https://github.com/dnsid-ai/dnsid-py/pull/125))

### Features

- feat: registry challenge flow and a2a example port to the current testnet ([#120](https://github.com/dnsid-ai/dnsid-py/pull/120))
- feat(c2sp-tlog): C2SP tile-log binding with DNSid1 lifecycle verification ([#122](https://github.com/dnsid-ai/dnsid-py/pull/122))
- feat(core): entity-key foundation — entity KeyProvider, GetEntityKeySet, split event signing ([#126](https://github.com/dnsid-ai/dnsid-py/pull/126))
- feat(core): exact DNSid1 publication — entity-key signing, publish_profile, DNSid1 wire version ([#127](https://github.com/dnsid-ai/dnsid-py/pull/127))
- feat(core): DNSid1 profile support matrix + strict sg verification ([#128](https://github.com/dnsid-ai/dnsid-py/pull/128))
- feat(core): StatusUnavailable taxonomy; logchk/non-revocation become operation policy ([#129](https://github.com/dnsid-ai/dnsid-py/pull/129))
- feat(core): record-signing evidence retention + DomainLog lifecycle replay rules ([#130](https://github.com/dnsid-ai/dnsid-py/pull/130))
- feat(core): managed operational key rotation — supersede, registry prepare/submit, typed results ([#131](https://github.com/dnsid-ai/dnsid-py/pull/131))
- feat(wba): WBA profile conformance — Signature-Agent Dictionary, 64-byte nonces, directory serving ([#132](https://github.com/dnsid-ai/dnsid-py/pull/132))
- feat(core): interface & conformance metadata cleanup (LogReader, domain_boundary, DNSID_CONFIG_DIR, C2SP spec pins) ([#133](https://github.com/dnsid-ai/dnsid-py/pull/133))


## [0.7.0] - 2026-07-13

### Bug Fixes

- fix: validate() rejects malformed lr values locally with ValidationError ([#107](https://github.com/dnsid-ai/dnsid-py/pull/107))
- fix(jwks): reject encryption-only keys and duplicate kid values ([#109](https://github.com/dnsid-ai/dnsid-py/pull/109))

### Chores

- ci: expand test matrix to Python 3.11, 3.12, and 3.13 ([#112](https://github.com/dnsid-ai/dnsid-py/pull/112))
- chore(deps): bump taiki-e/install-action from 2.82.9 to 2.83.2 ([#113](https://github.com/dnsid-ai/dnsid-py/pull/113))

### Documentation

- docs: publish Python runtime and dependency compatibility matrix ([#110](https://github.com/dnsid-ai/dnsid-py/pull/110))

### Features

- feat(parse): accept submitted-spec wire literal v=DNSid1 (#106) ([#108](https://github.com/dnsid-ai/dnsid-py/pull/108))


## [0.6.0] - 2026-07-10

### Bug Fixes

- fix(parse): per-version required-tag dispatch; ek only on two-key profiles ([#99](https://github.com/dnsid-ai/dnsid-py/pull/99))
- fix(verify): branch verify_domain on single-key profiles; validate() rejects prohibited tags ([#99](https://github.com/dnsid-ai/dnsid-py/pull/99))
- fix: resolve __all__ gap for IssuanceEvent and update stale README examples ([#34](https://github.com/dnsid-ai/dnsid-py/pull/34))

### Chores

- ci: gate PRs on cross-SDK compliance ([#100](https://github.com/dnsid-ai/dnsid-py/pull/100))

### Documentation

- docs(security): expand SECURITY.md + add CodeQL scanning (#89) ([#95](https://github.com/dnsid-ai/dnsid-py/pull/95))
- docs: document signed commit setup ([#97](https://github.com/dnsid-ai/dnsid-py/pull/97))

### Features

- feat: enforce full pairwise ek≠ku RFC 7638 thumbprint distinctness ([#98](https://github.com/dnsid-ai/dnsid-py/pull/98))

### Testing

- test(verify): cover dnsid-draft01 alias end-to-end in verify_domain ([#32](https://github.com/dnsid-ai/dnsid-py/pull/32))
- test(verify): assert version stored as-is; neutral alias docstring ([#32](https://github.com/dnsid-ai/dnsid-py/pull/32))
- test(verify): assert single-key profile fetches ku JWKS exactly once ([#32](https://github.com/dnsid-ai/dnsid-py/pull/32))
- test(verify): cover dnsid-draft01 alias end-to-end in verify_domain (#32) ([#103](https://github.com/dnsid-ai/dnsid-py/pull/103))


## [0.5.0] - 2026-07-09

### Bug Fixes

- fix(verify): accept spec-conformant detached compact JWS sg= (#74) ([#85](https://github.com/dnsid-ai/dnsid-py/pull/85))

### Features

- feat(registry-client): authenticated RegistryClient support (#46) ([#92](https://github.com/dnsid-ai/dnsid-py/pull/92))
- feat(issuance): dual-signed bilateral binding + unconditional step-5 check (#76) ([#90](https://github.com/dnsid-ai/dnsid-py/pull/90))
- feat: draft-01 two-key model (ek tag; verify sg via ek, not ku) ([#77](https://github.com/dnsid-ai/dnsid-py/pull/77))


## [0.4.3] - 2026-07-09

### Bug Fixes

- fix(parse): reject required tags with empty values ([#78](https://github.com/dnsid-ai/dnsid-py/pull/78))
- fix(parse): reject required tags with empty values (#78) ([#81](https://github.com/dnsid-ai/dnsid-py/pull/81))
- fix(utils): strip trailing dot after UTS#46 mapping ([#79](https://github.com/dnsid-ai/dnsid-py/pull/79))
- fix(parse): reject cross-version tags ek/oi on draft-01-20260504 ([#80](https://github.com/dnsid-ai/dnsid-py/pull/80))

### Documentation

- docs: add quickstart guide and SDK reference documentation ([#68](https://github.com/dnsid-ai/dnsid-py/pull/68))


## [0.4.2] - 2026-06-30

### Bug Fixes

- fix: validate JWT claim types and reject duplicate Signature-Input labels ([#61](https://github.com/dnsid-ai/dnsid-py/pull/61))
- fix: web bot auth JWT claim-type validation and Signature-Input dedup ([#65](https://github.com/dnsid-ai/dnsid-py/pull/65))


## [0.4.1] - 2026-06-30

### Chores

- chore: reference LICENSE.txt from pyproject and fix casing ([#62](https://github.com/dnsid-ai/dnsid-py/pull/62))

### Other

- WBA signer: bridge DNSid RFC 9421 to Web Bot Auth spec ([#63](https://github.com/dnsid-ai/dnsid-py/pull/63))


## [0.4.0] - 2026-06-29

### Chores

- chore(deps): bump taiki-e/install-action from 2.81.10 to 2.82.2 ([#52](https://github.com/dnsid-ai/dnsid-py/pull/52))
- chore(deps): bump actions/checkout from 6.0.3 to 7.0.0 ([#51](https://github.com/dnsid-ai/dnsid-py/pull/51))
- chore(deps): bump taiki-e/install-action from 2.82.2 to 2.82.6 ([#59](https://github.com/dnsid-ai/dnsid-py/pull/59))
- chore(deps): bump actions/setup-python from 6.2.0 to 6.3.0 ([#60](https://github.com/dnsid-ai/dnsid-py/pull/60))

### Features

- feat: add convenience initializer from DNSid CLI config files ([#53](https://github.com/dnsid-ai/dnsid-py/pull/53))
- feat: add web bot auth support ([#57](https://github.com/dnsid-ai/dnsid-py/pull/57))
- feat: rename CLI binary from `dnsid` to `dnsid-testpy` ([#37](https://github.com/dnsid-ai/dnsid-py/pull/37))


## [0.3.0] - 2026-06-18

### Bug Fixes

- fix: remove dead code in config_from_environment and mark status_url … ([#50](https://github.com/dnsid-ai/dnsid-py/pull/50))

### Chores

- chore(deps): bump taiki-e/install-action from 2.81.8 to 2.81.10 ([#41](https://github.com/dnsid-ai/dnsid-py/pull/41))

### Features

- feat(version): accept dnsid-draft01 as primary wire version, treat da… ([#33](https://github.com/dnsid-ai/dnsid-py/pull/33))
- feat(examples): add validate-domain example and fix status endpoint c… ([#40](https://github.com/dnsid-ai/dnsid-py/pull/40))
- Add private DNSid evaluation license ([#39](https://github.com/dnsid-ai/dnsid-py/pull/39))
- Add programmatic OIDC token minting ([#43](https://github.com/dnsid-ai/dnsid-py/pull/43))
- feat: add oidc support ([#42](https://github.com/dnsid-ai/dnsid-py/pull/42))
- feat: add create_if_missing to LocalKeyProvider.load and local key pr… ([#44](https://github.com/dnsid-ai/dnsid-py/pull/44))
- feat: add AWS KMS-backed KeyProvider ([#48](https://github.com/dnsid-ai/dnsid-py/pull/48))
- feat: default server/base URL to https://api.dnsid.ai ([#49](https://github.com/dnsid-ai/dnsid-py/pull/49))

### Other

- Design conformance ([#30](https://github.com/dnsid-ai/dnsid-py/pull/30))


## [0.2.0] - 2026-06-10

### Chores

- ci: pin GitHub Actions to immutable commit SHAs [#19]
- refactor: split IdentityManager into core + application profiles ([#15](https://github.com/dnsid-ai/dnsid-py/pull/15))

### Features

- feat(cli): add dnsid CLI entry-point with resolve/sign/verify ([#22](https://github.com/dnsid-ai/dnsid-py/pull/22))
- feat: implement optional JWK alg and narrow algorithm allowlist ([#24](https://github.com/dnsid-ai/dnsid-py/pull/24))


## [0.1.1] - 2026-05-29

### Bug Fixes

- fix(workflow): updated workfloww ([#7](https://github.com/dnsid-ai/dnsid-py/pull/7))
- fix(workflow): check version existence ([#8](https://github.com/dnsid-ai/dnsid-py/pull/8))
- fix(workflow): dropped twine ([#9](https://github.com/dnsid-ai/dnsid-py/pull/9))
- fix(api): design deviations ([#10](https://github.com/dnsid-ai/dnsid-py/pull/10))
- fix(workflow): add CHANGELOG.md so git-cliff --prepend does not fail [#11]
- fix(workflow): add CHANGELOG.md so git-cliff --prepend does not fail … ([#11](https://github.com/dnsid-ai/dnsid-py/pull/11))
