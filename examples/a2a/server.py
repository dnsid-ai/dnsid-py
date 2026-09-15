"""FastAPI agent server backed by the a2a-sdk."""

from __future__ import annotations

import asyncio
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

# Allow sibling imports when run as a script.
_here = Path(__file__).parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

import uvicorn
from a2a.auth.user import UnauthenticatedUser, User
from a2a.server.agent_execution import AgentExecutor
from a2a.server.context import ServerCallContext
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    ServerCallContextBuilder,
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.tasks import InMemoryTaskStore
from a2a.types.a2a_pb2 import AgentCard
from agent import (
    A2A_VERSION,
    DNSID_A2A_EXTENSION_URI,
    DNSID_A2A_SIGNATURE_TAG,
    build_agent_card,
)
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

from dnsid import IdentityManager, active_status_document
from dnsid.http_signatures import HttpSignatureProfile
from dnsid.jose import JoseProfile
from dnsid.models import HttpRequest as DnsidRequest
from dnsid.models import HttpVerificationOptions


@dataclass
class EchoAgentOptions:
    """Options for :class:`EchoAgent`."""

    public_url: str | None = None


# ---------------------------------------------------------------------------
# Required signature components — mirrors TypeScript server.ts
# ---------------------------------------------------------------------------

_REQUIRED_SIG_COMPONENTS = [
    "@method",
    "@target-uri",
    "content-type",
    "content-digest",
    "a2a-version",
    "a2a-extensions",
]

_VERIFY_OPTS = HttpVerificationOptions(
    required_components=_REQUIRED_SIG_COMPONENTS,
    required_tag=DNSID_A2A_SIGNATURE_TAG,
)


class VerifiedSenderUser(User):
    """Wraps a dnsid-verified sender domain as an a2a-sdk User."""

    def __init__(self, domain: str) -> None:
        self._domain = domain

    @property
    def is_authenticated(self) -> bool:
        return bool(self._domain)

    @property
    def user_name(self) -> str:
        return self._domain


class DnsidServerCallContextBuilder(ServerCallContextBuilder):
    """Reads the dnsid-verified sender set by the signature middleware."""

    def build(self, request: Request) -> ServerCallContext:
        sender = request.scope.get("_dnsid_sender")
        return ServerCallContext(
            user=sender or UnauthenticatedUser(),
            state={"headers": dict(request.headers)},
        )


class _DnsidSignatureMiddleware:
    """ASGI middleware that verifies inbound HTTP message signatures via dnsid."""

    def __init__(self, app, idm: IdentityManager, http_sig: HttpSignatureProfile) -> None:
        self._app = app
        self._idm = idm
        self._http_sig = http_sig

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self._app(scope, receive, send)
            return

        chunks: list[bytes] = []
        more = True
        while more:
            msg = await receive()
            chunks.append(msg.get("body", b""))
            more = msg.get("more_body", False)
        body = b"".join(chunks)

        headers_raw = {
            k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        scheme = scope.get("scheme", "https")
        forwarded_proto = headers_raw.get("x-forwarded-proto", scheme)
        host = headers_raw.get("x-forwarded-host") or headers_raw.get("host") or "localhost"
        path = scope.get("path", "/")
        query = scope.get("query_string", b"").decode("latin-1")
        url = f"{forwarded_proto}://{host}{path}" + (f"?{query}" if query else "")
        headers_raw["host"] = host

        # Validate A2A-Version header.
        a2a_version = headers_raw.get("a2a-version", "")
        if a2a_version != A2A_VERSION:
            response = JSONResponse(
                {"error": f"A2A-Version must be {A2A_VERSION}, got {a2a_version!r}"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        # Validate A2A-Extensions header — must include the DNSid extension URI.
        requested_extensions = [
            e.strip() for e in headers_raw.get("a2a-extensions", "").split(",") if e.strip()
        ]
        if DNSID_A2A_EXTENSION_URI not in requested_extensions:
            response = JSONResponse(
                {"error": f"A2A-Extensions must include {DNSID_A2A_EXTENSION_URI}"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        dnsid_req = DnsidRequest(method=scope["method"], url=url, headers=headers_raw, body=body)
        try:
            verified = await asyncio.to_thread(
                self._http_sig.verify_signed_http_request, dnsid_req, _VERIFY_OPTS
            )
            scope = {**scope, "_dnsid_sender": VerifiedSenderUser(verified.domain)}
            print(
                f"[{self._idm.local_domain}] verified signed POST {path} from {verified.domain}"
            )
        except Exception as exc:
            response = JSONResponse({"error": str(exc)}, status_code=401)
            await response(scope, receive, send)
            return

        body_sent = False

        async def replay_receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self._app(scope, replay_receive, send)


class A2AClient:
    """Sends signed A2A messages to a peer agent via the a2a-sdk ClientFactory."""

    def __init__(
        self,
        http_sig: HttpSignatureProfile,
        target_url: str,
    ) -> None:
        from a2a.client.client import ClientConfig
        from a2a.client.client_factory import ClientFactory

        from dnsid.models import HttpSigningOptions

        signing_opts = HttpSigningOptions(
            additional_components=["content-type", "a2a-version", "a2a-extensions"],
            tag=DNSID_A2A_SIGNATURE_TAG,
        )
        self._http_client = http_sig.create_signed_async_http_client(
            base_headers={
                "content-type": "application/json",
                "a2a-version": A2A_VERSION,
                "a2a-extensions": DNSID_A2A_EXTENSION_URI,
            },
            opts=signing_opts,
        )
        self._factory = ClientFactory(ClientConfig(httpx_client=self._http_client, streaming=False))
        self._target_url = target_url.rstrip("/")
        self._client = None

    async def _get_client(self):
        if self._client is None:
            self._client = await self._factory.create_from_url(self._target_url)
        return self._client

    async def aclose(self) -> None:
        await self._http_client.aclose()

    async def send_message(self, message_dict: dict) -> dict:
        """Send a message and return the reply as a dict with a 'parts' list."""
        from a2a.types.a2a_pb2 import Message, Role, SendMessageRequest

        client = await self._get_client()
        msg = Message(message_id=str(uuid.uuid4()), role=Role.ROLE_USER)
        for p in message_dict.get("parts", []):
            part = msg.parts.add()
            if "text" in p:
                part.text = p["text"]
                part.media_type = "text/plain"
        async for event in client.send_message(SendMessageRequest(message=msg)):
            if event.HasField("message"):
                return {
                    "parts": [{"text": p.text} for p in event.message.parts if p.HasField("text")]
                }
        return {}


class EchoAgent:
    """HTTP agent server: verifies inbound signatures via dnsid, delegates to a2a-sdk."""

    def __init__(
        self,
        idm: IdentityManager,
        jose: JoseProfile,
        http_sig: HttpSignatureProfile,
        port: int,
        executor: AgentExecutor,
        card: AgentCard,
    ) -> None:
        self._idm = idm
        self._jose = jose
        self._http_sig = http_sig
        self._port = port
        self._executor = executor
        self._card = card
        self._server: uvicorn.Server | None = None
        self._serve_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._clients: dict[str, A2AClient] = {}

    @classmethod
    async def create(
        cls,
        executor: AgentExecutor,
        idm: IdentityManager,
        port: int,
        options: EchoAgentOptions = EchoAgentOptions(),
    ) -> EchoAgent:
        public_url = options.public_url or f"https://{idm.local_domain}"
        provider_url = (
            public_url
            if ":" in idm.config.identity.governance_id
            else f"https://{idm.config.identity.governance_id}"
        )
        card = build_agent_card(idm.local_domain, public_url, provider_url)

        jose = JoseProfile.from_identity_manager(idm)
        http_sig = HttpSignatureProfile.from_identity_manager(idm)

        # Sign the agent card with a JWS so recipients can verify its authenticity.
        try:
            import json as _json

            def _stable_json(obj: object) -> str:
                if obj is None or not isinstance(obj, (dict, list)):
                    return _json.dumps(obj, separators=(",", ":"))
                if isinstance(obj, list):
                    return "[" + ",".join(_stable_json(v) for v in obj) + "]"
                entries = sorted(
                    (k, v)
                    for k, v in obj.items()
                    if v is not None  # type: ignore[union-attr]
                )
                return (
                    "{"
                    + ",".join(
                        _json.dumps(k, separators=(",", ":")) + ":" + _stable_json(v)
                        for k, v in entries
                    )
                    + "}"
                )

            from google.protobuf.json_format import MessageToDict

            card_dict = MessageToDict(card, preserving_proto_field_name=True)
            card_dict.pop("signatures", None)
            payload = _stable_json(card_dict).encode()
            jws = await asyncio.to_thread(jose.create_jws, payload)
            protected, _, signature = jws.split(".")
            sig = card.signatures.add()
            sig.protected = protected
            sig.signature = signature
        except Exception as exc:
            print(f"[{idm.local_domain}] warning: agent card signing failed: {exc}")

        return cls(idm, jose, http_sig, port, executor, card)

    @property
    def url(self) -> str:
        if self._card.supported_interfaces:
            return self._card.supported_interfaces[0].url
        return f"https://{self._idm.local_domain}"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        app = self._build_app()
        config = uvicorn.Config(app, host="0.0.0.0", port=self._port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._serve_task = asyncio.create_task(self._server.serve())
        while not self._server.started:
            await asyncio.sleep(0.05)

    async def stop(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()
        if self._server:
            self._server.should_exit = True
        if self._serve_task:
            await self._serve_task

    # ------------------------------------------------------------------
    # A2A client: send signed messages to a peer agent
    # ------------------------------------------------------------------

    def create_client(self, target_base_url: str) -> A2AClient:
        """Return a cached A2AClient for *target_base_url*, creating one on first use."""
        key = target_base_url.rstrip("/")
        if key not in self._clients:
            self._clients[key] = A2AClient(self._http_sig, target_base_url)
        return self._clients[key]

    async def send_message(self, peer_fqdn: str, text: str) -> str:
        """Convenience wrapper: send a plain-text message to *peer_fqdn* and return reply text."""
        client = self.create_client(f"https://{peer_fqdn}")
        message = {
            "messageId": str(uuid.uuid4()),
            "role": "ROLE_USER",
            "parts": [{"text": text}],
        }
        result = await client.send_message(message)
        return " ".join(p.get("text", "") for p in result.get("parts", []) if "text" in p)

    def _build_app(self) -> _DnsidSignatureMiddleware:
        idm = self._idm
        card = self._card
        executor = self._executor

        task_store = InMemoryTaskStore()
        request_handler = DefaultRequestHandler(
            agent_executor=executor,
            task_store=task_store,
            agent_card=card,
        )
        context_builder = DnsidServerCallContextBuilder()

        sdk_routes = create_agent_card_routes(
            card, card_url="/.well-known/agent-card.json"
        ) + create_jsonrpc_routes(
            request_handler,
            rpc_url="/",
            context_builder=context_builder,
            enable_v0_3_compat=False,
        )

        app = FastAPI(title="A2A Agent Server", version="1.0.0", routes=sdk_routes)

        @app.get("/.well-known/jwks.json", include_in_schema=False)
        async def get_jwks():
            jwks = idm.get_key_set()
            return jwks.to_dict()

        @app.get("/.well-known/status.json", include_in_schema=False)
        async def get_status():
            return active_status_document()

        return _DnsidSignatureMiddleware(app, idm, self._http_sig)
