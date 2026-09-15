"""Agent card definition, executor interface, and echo implementation."""

from __future__ import annotations

from a2a.helpers.proto_helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types.a2a_pb2 import AgentCard, StringList

# ---------------------------------------------------------------------------
# Shared constants — referenced by server.py for middleware and client headers.
# Mirror the TypeScript constants exported from examples/a2a/src/agent.ts.
# ---------------------------------------------------------------------------

DNSID_A2A_EXTENSION_URI = (
    "https://example-provider.example/a2a/extensions/dnsid-http-message-signatures/v1"
)
DNSID_A2A_SIGNATURE_TAG = "a2a-dnsid-http-sig-v1"
A2A_VERSION = "1.0"


def build_agent_card(domain: str, url: str, provider_url: str = "") -> AgentCard:
    """Build an A2A AgentCard for a DNSid echo agent.

    The card declares the DNSid HTTP Message Signature extension as a required
    capability, mirroring the TypeScript agent card structure.
    """
    if not provider_url:
        provider_url = f"https://{domain}"

    card = AgentCard()
    card.name = "Example DNSid Echo Agent"
    card.description = (
        "A minimal A2A agent that echoes text input and requires "
        "DNSid-bound HTTP Message Signatures."
    )
    card.version = "0.2.0"

    iface = card.supported_interfaces.add()
    iface.url = url
    iface.protocol_binding = "JSONRPC"
    iface.protocol_version = A2A_VERSION
    iface.tenant = ""

    # Provider metadata
    try:
        card.provider.organization = "Example Provider"
        card.provider.url = provider_url
        card.documentation_url = f"{provider_url.rstrip('/')}/docs/echo-agent"
    except AttributeError:
        pass  # older a2a-sdk protobuf without provider/documentation_url fields

    card.capabilities.streaming = False
    card.capabilities.push_notifications = False

    # DNSid extension capability
    try:
        ext = card.capabilities.extensions.add()
        ext.uri = DNSID_A2A_EXTENSION_URI
        ext.description = (
            "Requires DNSid validation, RFC 9421 HTTP Message Signatures, "
            "and mTLS for inbound requests."
        )
        ext.required = True
        try:
            from google.protobuf.struct_pb2 import Struct

            params = Struct()
            params.update(
                {
                    "dnsidSubject": "selected-interface-host",
                    "runtimeProof": "http-message-signature",
                    "signatureInputHeader": "Signature-Input",
                    "signatureHeader": "Signature",
                    "requiredSignatureTag": DNSID_A2A_SIGNATURE_TAG,
                    "keyidSyntax": "<caller-dnsid-subject>#<jwks-kid>",
                    "keyResolution": "dnsid-ku-jwks",
                    "requiredCoveredComponents": ",".join(
                        [
                            "@method",
                            "@target-uri",
                            "content-type",
                            "content-digest",
                            "a2a-version",
                            "a2a-extensions",
                        ]
                    ),
                    "requiredSignatureParameters": "keyid,alg,created,expires,nonce,tag",
                    "contentDigest": "sha-256-required",
                    "statusCheck": "dnsid-su-active-required",
                    "providerPolicy": "provider-url-host-must-equal-or-be-subdomain-of-gi",
                    "mtls": "required-because-target-dnsid-fl-contains-mtls",
                }
            )
            ext.params.CopyFrom(params)
        except (AttributeError, ImportError):
            pass  # params field or Struct not available in this sdk version
    except AttributeError:
        pass  # older a2a-sdk protobuf without extensions field

    card.default_input_modes.append("text/plain")
    card.default_output_modes.append("text/plain")

    sk = card.skills.add()
    sk.id = "echo"
    sk.name = "Echo"
    sk.description = "Returns the input text unchanged."
    sk.tags.extend(["echo", "test", "diagnostic"])
    try:
        sk.examples.extend(["Echo: hello world", "Return this exact text: ping"])
        sk.input_modes.append("text/plain")
        sk.output_modes.append("text/plain")
    except AttributeError:
        pass  # older a2a-sdk

    # Security scheme: dnsidMtls (mTLS required when fl=mtls is set in DNSid record)
    try:
        sc = card.security_schemes["dnsidMtls"]
        sc.mtls_security_scheme.description = (
            "Mutual TLS is required when this agent's DNSid record contains fl=mtls."
        )
        req = card.security_requirements.add()
        req.schemes["dnsidMtls"].CopyFrom(StringList())
        try:
            sk_req = sk.security_requirements.add()
            sk_req.schemes["dnsidMtls"].CopyFrom(StringList())
        except AttributeError:
            pass
    except (AttributeError, KeyError):
        # Fall back to the httpSig scheme for older a2a-sdk versions.
        sc = card.security_schemes["httpSig"]
        sc.http_auth_security_scheme.scheme = "signature"
        sc.http_auth_security_scheme.description = (
            "RFC 9421 HTTP Message Signatures; keyid must be the sender's FQDN"
        )
        req = card.security_requirements.add()
        req.schemes["httpSig"].CopyFrom(StringList())

    return card


def echo_executor(agent_id: str) -> AgentExecutor:
    """Return an AgentExecutor that echoes messages back with the verified sender identity."""

    class _EchoExecutor(AgentExecutor):
        async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
            text = context.get_user_input()
            sender_id = context.call_context.user.user_name
            print(f'[{agent_id}] handling message from verified sender {sender_id}: "{text}"')
            reply_text = f"[from: {agent_id}; verified sender: {sender_id}] {text}"
            print(f'[{agent_id}] sending response to {sender_id}: "{reply_text}"')
            response = new_text_message(
                reply_text,
                context_id=context.context_id,
                task_id=context.task_id,
            )
            await event_queue.enqueue_event(response)

        async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
            pass

    return _EchoExecutor()
