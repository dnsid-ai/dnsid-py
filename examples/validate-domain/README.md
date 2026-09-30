# DNSid validate-domain example

Minimal Python example that verifies a DNSid-enabled domain whose lifecycle log
uses DNSid's managed production C2SP log (`https://log.dnsid.ai`). Pass the
second-level domain to verify explicitly:

```sh
python examples/validate-domain/main.py your-agent.example
```

Replace `your-agent.example` with a published DNSid-enabled domain.

The example opts into `create_dnsid_managed_verification_registry`, whose
embedded trust profile carries the log policy and the stream-bundle verifier
keys, so verification fetches one signed per-domain bundle instead of scanning
the whole log. Applications with different trust should select an independently
trusted policy through `C2spTlogVerificationOptions`. Never derive the policy
location from an unverified identity record, its `lr`, or its log prefix.

Against the local registry, provision `bob.test` and its ISSUANCE, then evaluate
`dnsid local env bob`. The agent-specific form includes the identity and key
paths as well as `DNSID_LOG_POLICY_URL`, `DNSID_DNS_SERVER`, `DNSID_CA_BUNDLE`, and
`DNSID_PRIVATE_HOSTS=.test`, which `load_environment()` reads and
`construct_identity_manager()` wires into the manager and its policy fetch.

```sh
dnsid local up --zone test
dnsid local agent ensure bob --upstream http://localhost:3002 -- \
  dnsid log issue --domain bob.test
eval "$(dnsid local env bob)"
python examples/validate-domain/main.py bob.test
```
