# DNSid validate-domain example

Minimal Python example that verifies a DNSid-enabled domain whose lifecycle log
uses DNSid's managed production C2SP log (`https://log.dnsid.ai`). With no
argument it verifies the DNSid sandbox identity `2a7bcd5330fd.sandbox.dnsid.ai`:

```sh
python examples/validate-domain/main.py
python examples/validate-domain/main.py your-agent.example.com
```

The example opts into `create_dnsid_managed_verification_registry`, whose
embedded trust profile carries the log policy and the stream-bundle verifier
keys, so verification fetches one signed per-domain bundle instead of scanning
the whole log. Applications with different trust should select an independently
trusted policy through `C2spTlogVerificationOptions`. Never derive the policy
location from an unverified identity record, its `lr`, or its log prefix.

Against the local registry, evaluate `dnsid local env` first; it exports
`DNSID_LOG_POLICY_URL`, `DNSID_DNS_SERVER`, and `DNSID_CA_BUNDLE`, which the
example picks up:

```sh
eval "$(dnsid local env)"
python examples/validate-domain/main.py bob.dev.dnsid.test
```
