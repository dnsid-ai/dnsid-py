# Negotiated DNSid response signatures

This opt-in HTTP Message Signature profile implements RFC 9421 §5 negotiation.
It does not change the DNSid core, request-only defaults, or Web Bot Auth.
The design baseline is shared SDK design commit `ed43f42`.

## Public API

```python
ResponseSignatureOptions(
    expected_domain: str,
    additional_components: list[str] = [],
)
HttpSigningOptions(..., response_signature: ResponseSignatureOptions | None = None)

HttpSignatureProfile.sign_requested_http_response(
    request: HttpRequest, response: HttpRequest,
) -> HttpRequest
HttpSignatureProfile.verify_signed_http_response(
    request: HttpRequest, response: HttpRequest, opts: ResponseSignatureOptions,
    *, peer_cert: TLSCertificate | None = None,
) -> VerifiedDomain
async HttpSignatureProfile.async_verify_signed_http_response(
    request: HttpRequest, response: HttpRequest, opts: ResponseSignatureOptions,
    *, peer_cert: TLSCertificate | None = None,
) -> VerifiedDomain
```

The default component list is status, request method, authority, target URI,
Accept-Signature, Signature-Input, Signature, response Content-Digest, and
Cache-Control, in that order. Request components use `;req`. Additional components
use the existing component string model, for example `content-type` or
`example;key="member"`. Required components and equivalent additions are not
repeated. Servers accept another valid label or component order, but fulfill the
complete request exactly. Unsupported syntax or constraints reject the entire
negotiation. Server failures never return an unsigned success.

Only covered fields are authenticated. Content-Type, Content-Encoding, Location,
and other uncovered metadata are not authenticated by default. Request coverage
for metadata your application relies on. HTTPS is required, but the responder's
DNSid identity is verified only after request data has been sent. Configure
`trusted_entities` on the resolver separately when accountable-entity acceptance
is required. The expected domain is local policy, not the HTTP host or a value
learned from the peer.

## Standalone helpers

```python
from copy import deepcopy
from dnsid import HttpRequest, HttpSigningOptions, ResponseSignatureOptions

policy = ResponseSignatureOptions("service.example", ["content-type"])
policy_snapshot = deepcopy(policy)
request = caller_profile.create_signed_http_request(
    HttpRequest("POST", "https://gateway.example/api", body=b"operation"),
    HttpSigningOptions(response_signature=policy_snapshot),
)
# Keep request and policy_snapshot unmodified for this invocation. Your transport
# must not follow redirects, retry/replay, cache, or decode content before verification.
response, current_peer = send_exact_buffered_request(request)
identity = caller_profile.verify_signed_http_response(
    request, response, policy_snapshot, peer_cert=current_peer,
)
```

`send_exact_buffered_request` represents the application's transport, not an SDK
function. Use the signed HTTPX client instead when possible. Standalone callers
own the per-invocation snapshots, bounded reads, time budget, current TLS peer
certificate, and transport cleanup. Do not verify against echoed request fields
or reuse another connection's certificate. Each new attempt starts from the
original unsigned request and obtains a new challenge and signature.

A response uses the existing buffered HTTP message type:
`HttpRequest("", "", headers=..., body=..., status=200)`. Its method/URL do not
supply originating-request components. Those come only from the retained request.
Pass exact content bytes after transfer framing, before content decoding. `None`
is unavailable content except for HEAD, 204, 205, and 304, whose digest is over
empty bytes. A verifier rejects content delivered with those; the server helper
ignores content supplied with them. A supplied empty ordinary body is `b""`, not
`None`.

The negotiation binds the response to the client's own request signature member
with `signature-input;req;key="<label>"` and `signature;req;key="<label>"`, so an
intermediary that adds its own request signature does not break verification.
Responses use a fixed 60-second lifetime, independent of either peer's `max_age`.
If preparation fails, for example in the key provider, the caller's request is
left unchanged.

## Server integration

For ASGI applications, wrap the app with
`ResponseSigningMiddleware(app, server_profile)`. Requests without
`Accept-Signature` pass through unbuffered. Negotiated responses are buffered up
to 8 MiB and signed before any header is sent; on failure it sends a 500 without
the application's headers or content. The request URL uses the ASGI scope scheme
and Host header, so apply trusted proxy-header handling first behind a
TLS-terminating proxy.

Verify and authorize the caller before dispatch. Finalize the response status,
content coding, and covered headers before calling
`sign_requested_http_response(request, response)`. The helper adds SHA-256
Content-Digest and Cache-Control no-store without discarding existing cache
directives, uses the operational key, and preserves other signature labels.
A requested-label collision rejects instead of overwriting it. Only successful
signing publishes header changes. Missing negotiation is a no-op, even for a
verification-only profile. Apply signing to application errors as well.

No middleware may alter covered bytes afterward. Unsupported/incomplete peer
negotiation is a non-transient `VerificationError`; missing local signing
configuration is `ArgumentError`. A provider failure or a key change is an error,
not permission to send an unsigned response. Coverage of the response's own
Signature or Signature-Input fields is rejected during negotiation. Informational responses, upgrades, and successful CONNECT
tunnels are not supported authenticated responses.

## Signed HTTPX clients and resource limits

Both signed clients accept `HttpSigningOptions.response_signature`. In this mode:

- Policy is copied at client construction and again per invocation. The actual
  outgoing context is retained separately from mutable native request objects.
- Every response is verified before it reaches the application, including errors
  and redirects. Redirect following and HTTPX authentication resends are disabled,
  even when requested through per-call settings. Existing Authorization headers
  are preserved; set them explicitly when needed.
- Only exact HTTPX HTTPTransport/AsyncHTTPTransport instances with `retries=0`,
  SDK transports with zero retries, and MockTransport are accepted. Unknown custom
  transports and retry-enabled transports reject before sending. Mock handlers
  must return the actual message without internal caching, resending, or decoding.
  Do not mutate transport dependencies while a client uses them.
- The synchronous wrapper calls the base transport directly. Base-client mounts,
  hooks, authentication flows, and caches are not inherited. The base transport
  remains caller-owned. The async client owns and closes its accepted transport.
- No response cache is provided. A reused response from another challenge rejects.
  The current connection's server certificate is extracted for each response;
  DNSid verification, including cache-hit status/acceptance/mTLS, still runs.
- Raw response content is bounded and verified before decoding. Clients send
  `Accept-Encoding: identity` and reject a non-identity `Content-Encoding` unless
  `content-encoding` is in `additional_components`, because decoding must not
  rely on uncovered metadata. With that coverage, identity, gzip, and deflate are
  supported with bounded decoding; other codecs reject. Already decoded ordinary
  coded content rejects. Empty HEAD/204/205/304 content remains empty even when
  representation-coding headers are present.
- The default invocation budget is 30 seconds, shared across send, reads, DNSid
  verification, hashing, and decoding. Use `dnsid.verification_budget(timeout=...)`
  or its cancellation event to lower it. Async task cancellation is supported.
  Injected synchronous callbacks/key providers must cooperate with the budget;
  Python cannot forcibly stop arbitrary blocking code.
- Owned request streams are closed after buffering/sending. Response streams are
  closed after reads or on rejection/cancellation. Verified bytes remain available
  on the native response; rejection returns no authenticated response.

| Input | Bound and enforcing layer |
|---|---|
| Accept-Signature | 16 KiB before Structured Field parsing; also enforced on preparation |
| Negotiated nonce | Canonical unpadded base64url, 32+ decoded bytes, at most 1024 encoded characters; generated from 32 random bytes |
| Signature plus Signature-Input | 64 KiB combined before parsing |
| Content-Digest | 16 KiB before parsing |
| Signature labels | 16 per dictionary; entire dictionaries are parsed and checked |
| Covered components | 64 per member; equivalent duplicates reject incoming negotiation |
| Request / raw response content | 8 MiB each; client streaming reads enforce the cap before appending |
| Decoded response content | 8 MiB; bounded decompression before publication to HTTPX/application |

Standalone helpers enforce buffered-message bounds, but cannot undo an allocation
the host already made. Hosts must bound incoming headers and content while reading,
and retain replay/cleanup responsibilities. Bounds never permit partial
verification or unsigned fallback. Existing resolver/evidence acquisition error
classifications are preserved; malformed response identity/signature material is
a non-transient verification error.

## Native conformance coverage

All tests below are in `tests/test_negotiated_responses.py`; names have the prefix
`test_`. None of the shared table rows is inapplicable. Boundary signatures are
real Ed25519 or ES256 signatures. Resolver tests use real IdentityManager checks
with injected DNS, HTTPS evidence, lifecycle adapter, clock, transport, and keys.
Malformed/tampered messages are intentionally rejected, not test-supplied verdicts.

| Shared conformance row | Native tests (without `test_` prefix) |
|---|---|
| Response option absent | `option_absent_and_server_no_negotiation` |
| Response option enabled | `preparation_and_fresh_attempts` |
| Invalid domain / non-HTTPS / existing negotiation | `invalid_local_options_before_key_or_network`, `client_preflight_rejection_and_request_cleanup` |
| Repeated sends / explicit retries | `preparation_and_fresh_attempts`, `signed_client_verifies_all_statuses_and_fresh_sends` |
| Caller mutation after preparation | `sync_client_snapshot`, `async_client_snapshot_and_verification` |
| Server without negotiation | `option_absent_and_server_no_negotiation` |
| Alternate label / reordered components / true flags | `nondefault_reordered_and_equivalent_flags`, `equivalent_parameter_order_and_dictionary_selection` |
| Additional metadata | `additional_metadata_and_standalone_policy` |
| Malformed / duplicate / wrong types / nonce / unsupported / multi-member | `strict_negotiation_rejects_atomically`, `self_referential_additions_are_rejected` |
| Ordinary / empty / HEAD / 204 / 205 / 304 content | `content_semantics`, `client_no_content_with_representation_coding`, `raw_coded_content_verified_before_decoding`, `signer_ignores_no_content_body` |
| Different signer/verifier `max_age` / lifetime above 60 seconds | `fixed_lifetime_independent_of_max_age` |
| Intermediary adds a request signature label | `intermediary_request_signature_does_not_break_response` |
| Uncovered non-identity Content-Encoding | `uncovered_content_encoding_is_not_decoded` |
| Key provider fails during preparation | `failed_preparation_leaves_request_unchanged` |
| Server middleware | `asgi_response_signing_middleware` |
| Unavailable content / incompatible decoder | `unavailable_content`, `sync_rejection_closes_resources[decoded]` |
| Label collision / other labels preserved | `colliding_labels_and_preservation` |
| Key change / provider failure / body bound | `signing_failure_is_atomic` |
| Valid expected-domain response | `content_semantics`, `es256_response_and_server_max_age`, `signed_client_verifies_all_statuses_and_fresh_sends`, `standalone_async_resolver_and_peer` |
| Missing / wrong label / coverage / order / nonce | `missing_and_unrelated_signatures`, `valid_crypto_cannot_bypass_negotiation_or_key_policy` |
| Modified response or originating context | `request_and_response_tampering`, `signed_incorrect_digest_rejected` |
| Gateway substitution | `gateway_cannot_substitute_a_differently_signed_request` |
| Timestamps / algorithm / metadata / current key | `freshness`, `valid_crypto_cannot_bypass_negotiation_or_key_policy`, `current_key_and_metadata` |
| Another DNSid domain before lookup | `expected_identity_before_discovery` |
| Status / lifecycle / acceptance / cache denial | `status_denial_on_cache_hit`, `acceptance_denial_including_cache_hit`, `lifecycle_and_acquisition_errors` |
| mTLS missing / wrong / previous connection | `mtls_current_peer_on_cache_hit`, `clients_never_reuse_previous_connection_peer`, `standalone_async_resolver_and_peer` |
| Signed HTTP error / redirect | `signed_client_verifies_all_statuses_and_fresh_sends`, `unsigned_error_is_not_returned`, `async_client_snapshot_and_verification` |
| Automatic redirect / transport replay | `signed_client_verifies_all_statuses_and_fresh_sends`, `retrying_and_unknown_transports_are_rejected`, `async_retry_transport_rejected`, `auth_resend_disabled_and_timeout_shared` |
| Informational / upgrade / tunnel | `nonordinary_responses` |
| Oversize / deadline / cancellation / cleanup | `resource_limits`, `sync_rejection_closes_resources`, `async_stream_resources_and_bounds`, `raw_decompression_is_bounded` |
| Cached response / missing signed no-store | `response_cache_reuse_rejected`, `signed_cache_policy_is_required` |
