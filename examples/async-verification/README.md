# Async verification example

Verify a published DNSid domain with a five-second request deadline, typed error
handling, and async shutdown. No local identity or signing key is required.

From the project root, after installing the SDK:

```sh
python examples/async-verification/main.py your-agent.example
```

Replace the placeholder with a published identity. Without configured log trust,
the example explicitly trusts the SDK's pinned DNSid-managed public logs. For
other logs, configure independent log-policy trust; never discover trust from
an unverified identity record.

The example loads `DNSID_*` configuration before starting the event loop. For a
provisioned local identity, evaluate `dnsid local env bob` and verify `bob.test`.
That environment supplies DNS routing, private-host policy, TLS trust and log
policy. Local identity/key settings are ignored by this verification-only example.
Configure `verification.trusted_entities` when your application also needs a
counterparty allowlist; protocol validity alone does not grant application access.

`VerificationError.code` identifies the failure. `DEADLINE_EXCEEDED` and other
transient errors mean verification is indeterminate; they do not prove that the
identity is invalid. The command prints the code and exits with status 1 on failure.

`async with manager` awaits `aclose()` on every exit. Shared evidence has an
independent 30-second budget and survives caller cancellation or deadline expiry.
Shutdown waits for that work, so it can outlast the five-second request deadline.
Injected blocking dependencies must honor SDK budgets. In a server, keep one
manager for the application lifetime and call `aclose()` during shutdown.
HTTP reads reuse separate pools per event loop. Keep participating event loops
running until shutdown completes. This example lets the configuration constructor
own the log registry, so manager shutdown closes its default log connections too.
Manually injected registries remain caller-owned; close them after their managers
drain. Use `aclose()`, not synchronous `close()`, after async HTTP reads.

Async-led cold verification uses native TXT, JWKS, status and C2SP reads.
Sync-only adapters and atomic checkpoint stores use workers. Mixed sync/async
calls share whichever evidence leader starts first; sync-led work remains
worker-backed. Injected adapters must retain their synchronous methods and
remain caller-owned.

## Testing outbound signatures without network access

For an existing signing profile backed by a local identity, inject a transport:

```python
import httpx

transport = httpx.MockTransport(lambda request: httpx.Response(200))
async with http_signer.create_signed_async_http_client(transport=transport) as client:
    response = await client.post("https://peer.example/api", json={"hello": "world"})
    assert response.status_code == 200
```

The returned client owns and closes the injected transport. It handles its own
DNS/TLS settings; do not also pass `transport_config`. Without injection, the
profile retains its configured SDK transport.
