# Trust policy

A verification-only manager with a 30-second status cache interval, one
governance ID and entity-key pin, and an independently supplied C2SP trust
profile. The profile contains the accepted log scope/prefix, checkpoint policy
and stream-bundle signer keys. Checkpoint maximum age is 10 minutes; maximum
bundle lifetime is 5 minutes.

From the SDK repository root:

```sh
uv run python examples/trust-policy/main.py agent.example /trusted/path/profile.json acme.example "$EK_THUMBPRINT"
```

Use a real DNSid domain, its independently accepted `gi=`, and the RFC 7638
SHA-256 thumbprint of its current entity record-signing key (unpadded
base64url). Obtain the profile and pin through a trusted channel, not from
the peer being verified. There are no built-in fallback trust roots.

See [Configure trust policy](https://docs.dnsid.ai/sdk-trust-policy/) for the
profile format, defaults, rotation, bundle fallback and operation-time checks.

The time values are examples, not universal security requirements. A positive
status interval can delay detection of a status change. This example makes one
verification call; reuse the manager and registry to exercise caching. It uses
public-network transport, does not load environment settings, and keeps
checkpoints only in memory. For DNSid Local, use the environment-based
validate-domain example. Before high-value operations, perform the fresh log
check described in the guide.
