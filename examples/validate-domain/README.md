# DNSid validate-domain example

Minimal Python example that verifies a DNSid-enabled domain whose lifecycle log
uses DNSid's public test C2SP log:

```sh
python examples/validate-domain/main.py your-agent.example.com
```

The example explicitly trusts the public test log policy at
`https://log.dnsid.dev/dnsid-policy`. Production applications should select an
independently trusted policy URL or pass trusted policy bytes through
`C2spTlogVerificationOptions.policy_document`. Never derive the policy location
from an unverified identity record, its `lr`, or its log prefix.

Against the local registry, evaluate `dnsid local env` first; it exports
`DNSID_LOG_POLICY_URL`, `DNSID_DNS_SERVER`, and `DNSID_CA_BUNDLE`, which the
example picks up:

```sh
eval "$(dnsid local env)"
python examples/validate-domain/main.py bob.dev.dnsid.test
```
