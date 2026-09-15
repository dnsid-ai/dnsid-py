# DNSid validate-domain example

Minimal Python example that verifies a DNSid-enabled domain whose lifecycle log
uses the DNSid sandbox's public C2SP log:

```sh
python examples/validate-domain/main.py your-agent.example.com
```

The example explicitly trusts the sandbox policy at
`https://log.dnsid.dev/dnsid-policy`. Production applications should select an
independently trusted policy URL or pass trusted policy bytes through
`C2spTlogVerificationOptions.policy_document`. Never derive the policy location
from an unverified identity record, its `lr`, or its log prefix.
