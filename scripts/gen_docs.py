#!/usr/bin/env python3
"""Generate the committed markdown API reference under docs/reference/.

Walks the public API of the ``dnsid`` package with griffe — the top-level
``__all__``, the profile submodules, and ``dnsid.c2sp_tlog.__all__`` — and
emits one markdown page per area, plus ``nav.json`` for the docs site.

The output is committed and exported verbatim to the docs site repository
(docs.dnsid.ai) under ``src/content/docs/reference/py/``, so:

- pages carry Starlight YAML frontmatter (``title`` + ``description``);
- links to other docs pages are absolute ``https://docs.dnsid.ai/...`` URLs
  (the files render both on GitHub and on the docs site);
- never hand-edit files in docs/reference/ — regenerate with this script:

    .venv/bin/python scripts/gen_docs.py

Every name in ``dnsid.__all__`` and ``dnsid.c2sp_tlog.__all__`` must be
assigned to exactly one page below; the script fails otherwise, so CI
catches API-surface changes that lack a docs mapping.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import griffe

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "docs" / "reference"
DOCS_SITE = "https://docs.dnsid.ai"
SLUG_PREFIX = "reference/py"

# Names documented from a specific submodule rather than the package root.
# Currently empty: all profile classes are top-level exports (TS-SDK parity)
# and are documented with their root import, though their home submodules
# (dnsid.jose, dnsid.http_signatures) remain valid
# import paths.
SUBMODULE_IMPORTS: dict[str, str] = {}

# Importable from the package root (and listed in the package docstring)
# but absent from dnsid.__all__. Documented anyway; kept explicit here so
# the completeness check still fails on genuinely unknown names.
TOPLEVEL_NOT_IN_ALL = {
    "AwsKmsConfig",
    "AwsKmsFacade",
    "AwsKmsKeyProvider",
    "AwsKmsKeyState",
    "BotoKmsFacade",
}

PROFILE_NOTE = (
    "> Application profiles are **not part of the core DNSid protocol** — "
    "they are optional application-layer integrations built on top of it."
)

# Ordered page spec: (slug, nav label, title, description, intro, [names]).
# Names resolve from dnsid.__all__ unless listed in SUBMODULE_IMPORTS or
# prefixed with "c2sp_tlog." (resolved from dnsid.c2sp_tlog).
OVERVIEW_INTRO = f"""\
The `dnsid` package is the Python SDK for the DNSid Protocol — agent
identity management and verification. Install with `pip install dnsid`
(Python 3.11+). The package ships a `py.typed` marker, so type checkers
see the SDK's full mypy-strict annotations.

See the [quickstart]({DOCS_SITE}/quickstart/) and the
[SDK overview]({DOCS_SITE}/sdk-overview/) for guided introductions;
these pages are the generated API reference.

## Import surface

Everything documented here is importable from the package root
(`from dnsid import IdentityManager, JoseProfile`), mirroring the
TypeScript SDK's umbrella package. The application-profile classes are
also importable from their home submodules — both paths are supported
and refer to the same classes:

```python
from dnsid.jose import JoseProfile
from dnsid.http_signatures import HttpSignatureProfile
```

The transparency-log integration is the exception: import it from
`dnsid.c2sp_tlog`.

## Synchronous by design

The public API is synchronous: every `IdentityManager`, profile, and
registry method blocks. Async support is limited to the httpx transport
plumbing (custom transports may implement `handle_async_request`) and
the `async_retry_transient` helper. Call the SDK from async code via
`asyncio.to_thread` or an executor.

## Application profiles

The JOSE, HTTP Message Signatures, Web Bot Auth, and OIDC profiles are
**not part of the core DNSid protocol** — they
are optional application-layer integrations built on top of it.\
"""

PAGES: list[dict] = [
    {
        "slug": "overview",
        "label": "Overview",
        "title": "Python: SDK overview",
        "description": "Import surface, sync-only design, and layout of the "
        "dnsid Python SDK reference.",
        "intro": OVERVIEW_INTRO,
        "names": [
            "SDKConformance",
            "SDK_CONFORMANCE",
        ],
    },
    {
        "slug": "core",
        "label": "Core: IdentityManager",
        "title": "Python: IdentityManager",
        "description": "Primary entry point of the dnsid Python SDK: "
        "IdentityManager and its dependency bundle.",
        "intro": (
            "`IdentityManager` is the primary entry point of the SDK; all "
            "protocol operations flow through it. The public API is "
            "**synchronous** — see the [package overview]"
            f"({DOCS_SITE}/{SLUG_PREFIX}/overview/) for the async story."
        ),
        "names": [
            "IdentityManager",
            "IdentityManagerDependencies",
            "verification_budget",
            "remaining_seconds",
            "KeyRotationPersistenceHook",
            "ApplicationSigningPauseHook",
            "ManagedKeyRotationSubmissionError",
            "ManagedKeyRotationActivationError",
            "sign_event_with_provider",
        ],
    },
    {
        "slug": "configuration",
        "label": "Configuration",
        "title": "Python: Configuration",
        "description": "Protocol, transport, and registry configuration, plus "
        "CLI-directory and environment-variable config helpers.",
        "intro": None,
        "names": [
            "DnsidConfig",
            "IdentityConfig",
            "VerificationConfig",
            "TrustedEntity",
            "TransportConfig",
            "RegistryConfig",
            "PublicationConfig",
            "config_from_cli_directory",
            "identity_manager_from_cli_directory",
            "CliConfigResult",
            "config_from_environment",
            "identity_manager_from_environment",
            "registry_client_from_environment",
            "EnvironmentConfigResult",
            "EnvironmentFieldName",
            "dnsid_environment_variables",
            "key_store_path_from_environment",
        ],
    },
    {
        "slug": "records",
        "label": "Records & keys",
        "title": "Python: Records and keys",
        "description": "The _dnsid TXT record model, JWK/JWKS key sets, agent "
        "status documents, and protocol constants.",
        "intro": None,
        "names": [
            "DnsIdTxtRecord",
            "TXTRecord",
            "JWK",
            "JWKS",
            "check_ek_ku_distinctness",
            "AgentStatus",
            "TLSCertificate",
            "active_status_document",
            "PROTOCOL_VERSION",
            "IDENTITY_RECORD_VERSION",
            "DEFAULT_REGISTRY_URL",
            "publish_allowed_version",
        ],
    },
    {
        "slug": "verification",
        "label": "Verification results",
        "title": "Python: Verification results",
        "description": "Results of domain verification: VerifiedDomain, the "
        "domain log and snapshot models, and lifecycle log events.",
        "intro": None,
        "names": [
            "VerifiedDomain",
            "LoggedStateEvidence",
            "VerifiedCutoffHistory",
            "DomainLog",
            "DomainSnapshot",
            "LogRef",
            "LogEvent",
            "AnyLogEvent",
            "IssuanceEvent",
            "KeyRotationEvent",
            "RevocationEvent",
            "RetirementEvent",
            "MigrationEvent",
            "DelegationEvent",
            "LogSignerRole",
        ],
    },
    {
        "slug": "profile-jose",
        "label": "Profile: JOSE",
        "title": "Python: JOSE profile",
        "description": "JWT and JWS helpers bound to DNSid identities "
        "(dnsid.jose).",
        "intro": PROFILE_NOTE,
        "names": ["JoseProfile", "JoseConfig", "JWTOptions"],
    },
    {
        "slug": "profile-http-signatures",
        "label": "Profile: HTTP signatures",
        "title": "Python: HTTP Message Signatures profile",
        "description": "RFC 9421 HTTP Message Signatures signing and "
        "verification (dnsid.http_signatures).",
        "intro": PROFILE_NOTE,
        "names": [
            "HttpSignatureProfile",
            "HttpMessageSignatureConfig",
            "HttpRequest",
            "HttpSigningOptions",
            "HttpVerificationOptions",
            "SignatureParams",
        ],
    },
    {
        "slug": "profile-web-bot-auth",
        "label": "Profile: Web Bot Auth",
        "title": "Python: Web Bot Auth profile",
        "description": "Web Bot Auth request signing, verification, and "
        "key-directory serving (dnsid.web_bot_auth, dnsid.wba_signer).",
        "intro": PROFILE_NOTE,
        "names": [
            "WebBotAuthProfile",
            "BotAuthConfig",
            "BotIdentity",
            "VerifiedBotRequest",
            "WBAHttpSigner",
            "WBAVariant",
            "WBADirectoryResponse",
            "WebBotAuthConfig",
            "WebBotAuthSigningOptions",
            "serve_http_message_signatures_directory",
        ],
    },
    {
        "slug": "profile-oidc",
        "label": "Profile: OIDC",
        "title": "Python: OIDC profile",
        "description": "OIDC token minting, exchange, and verification bound "
        "to DNSid identities (dnsid.oidc).",
        "intro": PROFILE_NOTE,
        "names": [
            "OIDCProfile",
            "OIDCConfig",
            "OIDCAssertionOptions",
            "OIDCTokenExchangeOptions",
            "OIDCTokenResponse",
            "OIDCDiscoveryDocument",
            "VerifyOIDCTokenOptions",
            "VerifiedOIDCSubject",
        ],
    },
    {
        "slug": "key-providers",
        "label": "Key providers",
        "title": "Python: Key providers",
        "description": "Key management backends: file-backed local keys and "
        "AWS KMS.",
        "intro": None,
        "names": [
            "LocalKeyProvider",
            "LocalKeyProviderEnvironmentOptions",
            "AwsKmsKeyProvider",
            "AwsKmsConfig",
            "AwsKmsKeyState",
            "BotoKmsFacade",
            "AwsKmsFacade",
        ],
    },
    {
        "slug": "registry",
        "label": "Registry",
        "title": "Python: Registry",
        "description": "Registry control-plane workflows: RegistryClient, "
        "log-method registry, and registry data models.",
        "intro": None,
        "names": [
            "LogRegistry",
            "RegistryClient",
            "required",
            "required_int",
            "AgentRegistrationInput",
            "AgentRegistration",
            "LiveAgentRegistrationInput",
            "LiveChallengeTranscript",
            "LiveProvisioningResponse",
            "LiveProofRequest",
            "LiveProofResponse",
            "LiveProofReissueRequest",
            "LiveProofReissueResponse",
            "LifecycleResult",
            "RegistryAgentStatus",
            "CanonicalRecordContentResponse",
            "PublishedRecord",
            "PreparedRegistryEvent",
            "KeyRotationPreparationRequest",
            "KeyRotationResult",
            "SubmissionResult",
        ],
    },
    {
        "slug": "transparency-log",
        "label": "Transparency log",
        "title": "Python: Transparency log (c2sp-tlog)",
        "description": "LogReader for C2SP tile-log transparency logs "
        "(dnsid.c2sp_tlog).",
        "intro": (
            "Everything on this page is imported from `dnsid.c2sp_tlog`. The "
            "subpackage is wire-compatible with the other DNSid SDKs' "
            "c2sp-tlog implementations."
        ),
        "names": "C2SP_TLOG_ALL",  # expanded at runtime from __all__
    },
    {
        "slug": "interfaces",
        "label": "Interfaces",
        "title": "Python: Interfaces",
        "description": "Extension-point protocols: key providers, logs, "
        "caches, DNS resolvers, and identity resolution.",
        "intro": (
            "Implement these interfaces to integrate your own backends. "
            "`IdentityResolver` is the minimal protocol satisfied by "
            "`IdentityManager` and accepted by the application profiles."
        ),
        "names": [
            "IdentityResolver",
            "KeyProvider",
            "Log",
            "LogReader",
            "NoopLogReader",
            "IdentityCache",
            "DNSResolver",
            "HTTPSFetcher",
            "AbstractRegistryClient",
            "retry_transient",
            "async_retry_transient",
        ],
    },
    {
        "slug": "errors",
        "label": "Errors & enums",
        "title": "Python: Errors and enumerations",
        "description": "Exception hierarchy and enumerations of the dnsid "
        "package.",
        "intro": None,
        "names": [
            "DNSidError",
            "ParseError",
            "ValidationError",
            "VerificationError",
            "RegistryRequestError",
            "LifecycleVerificationError",
            "LifecycleErrorCategory",
            "ArgumentError",
            "NetworkError",
            "OAuthError",
            "DNSSECState",
            "DNSSECMode",
            "VerificationCode",
            "AgentState",
            "RevocationReason",
            "RegistryRevocationReason",
            "EventType",
        ],
    },
]


def _fmt_annotation(annotation) -> str:
    return str(annotation) if annotation is not None else ""


def _signature(func: griffe.Function) -> str:
    parts = []
    for param in func.parameters:
        if param.name in ("self", "cls"):
            continue
        if param.kind is griffe.ParameterKind.var_positional:
            name = f"*{param.name}"
        elif param.kind is griffe.ParameterKind.var_keyword:
            name = f"**{param.name}"
        else:
            name = param.name
        text = name
        if param.annotation is not None:
            text += f": {_fmt_annotation(param.annotation)}"
        if param.default is not None and param.kind not in (
            griffe.ParameterKind.var_positional,
            griffe.ParameterKind.var_keyword,
        ):
            text += f" = {param.default}" if param.annotation is not None else f"={param.default}"
        parts.append(text)
    sig = f"{func.name}({', '.join(parts)})"
    if func.returns is not None:
        sig += f" -> {_fmt_annotation(func.returns)}"
    return sig


_SPHINX_ROLE = re.compile(r":(?:meth|func|class|mod|data|attr|exc|obj):`([^`]+)`")


def _strip_sphinx_roles(line: str) -> str:
    """Rewrite leftover Sphinx roles (:meth:`x`, :class:`~a.b.C`, ...) to
    plain code spans; a leading ~ keeps only the last dotted segment, matching
    Sphinx display behavior."""

    def repl(m: re.Match[str]) -> str:
        target = m.group(1)
        if target.startswith("~"):
            target = target[1:].rsplit(".", 1)[-1]
        return f"`{target}`"

    return _SPHINX_ROLE.sub(repl, line)


def _render_docstring(obj) -> list[str]:
    """Render a griffe-parsed Google docstring to markdown lines."""
    if obj.docstring is None:
        return []
    out: list[str] = []
    for section in obj.docstring.parsed:
        kind = section.kind
        if kind is griffe.DocstringSectionKind.text:
            out += [section.value.strip(), ""]
        elif kind is griffe.DocstringSectionKind.parameters:
            out.append("**Arguments:**")
            out.append("")
            for p in section.value:
                ann = f" (`{_fmt_annotation(p.annotation)}`)" if p.annotation else ""
                default = f" — default `{p.default}`" if p.default else ""
                desc = " ".join(p.description.split())
                out.append(f"- `{p.name}`{ann}: {desc}{default}")
            out.append("")
        elif kind is griffe.DocstringSectionKind.returns:
            out.append("**Returns:**")
            out.append("")
            for r in section.value:
                ann = f"`{_fmt_annotation(r.annotation)}` — " if r.annotation else ""
                out.append(f"- {ann}{' '.join(r.description.split())}")
            out.append("")
        elif kind is griffe.DocstringSectionKind.yields:
            out.append("**Yields:**")
            out.append("")
            for y in section.value:
                ann = f"`{_fmt_annotation(y.annotation)}` — " if y.annotation else ""
                out.append(f"- {ann}{' '.join(y.description.split())}")
            out.append("")
        elif kind is griffe.DocstringSectionKind.raises:
            out.append("**Raises:**")
            out.append("")
            for r in section.value:
                ann = _fmt_annotation(r.annotation) or "Exception"
                out.append(f"- `{ann}`: {' '.join(r.description.split())}")
            out.append("")
        elif kind is griffe.DocstringSectionKind.attributes:
            out.append("**Attributes:**")
            out.append("")
            for a in section.value:
                ann = f" (`{_fmt_annotation(a.annotation)}`)" if a.annotation else ""
                out.append(f"- `{a.name}`{ann}: {' '.join(a.description.split())}")
            out.append("")
        elif kind is griffe.DocstringSectionKind.examples:
            out.append("**Example:**")
            out.append("")
            for _, text in section.value:
                if text.strip().startswith(">>>"):
                    out += ["```python", text.rstrip(), "```", ""]
                else:
                    out += [text.rstrip(), ""]
        elif kind is griffe.DocstringSectionKind.admonition:
            title = section.title or "Note"
            out += [f"> **{title}:** {' '.join(section.value.description.split())}", ""]
        else:  # pragma: no cover - fall back to raw text for unknown kinds
            value = getattr(section, "value", "")
            if isinstance(value, str) and value.strip():
                out += [value.strip(), ""]
    return [_strip_sphinx_roles(line) for line in out]


def _public_members(cls: griffe.Class):
    """Own public methods and documented attributes, in source order."""
    methods, attributes = [], []
    for name, member in cls.members.items():
        if name.startswith("_") and name != "__init__":
            continue
        if member.is_alias:
            continue
        if member.is_function:
            if name != "__init__":
                methods.append(member)
        elif member.is_attribute:
            attributes.append(member)
    methods.sort(key=lambda m: m.lineno or 0)
    attributes.sort(key=lambda a: a.lineno or 0)
    return methods, attributes


def _render_class(cls: griffe.Class, import_path: str) -> list[str]:
    out = [f"## `{cls.name}`", ""]
    out += [f"```python\nfrom {import_path} import {cls.name}\n```", ""]
    bases = [str(b) for b in cls.bases]
    if bases:
        out += [f"*Bases:* {', '.join(f'`{b}`' for b in bases)}", ""]
    out += _render_docstring(cls)

    methods, attributes = _public_members(cls)

    class_sections = cls.docstring.parsed if cls.docstring else []
    documented_attrs = [a for a in attributes if a.docstring is not None]
    if documented_attrs and not any(
        s.kind is griffe.DocstringSectionKind.attributes for s in class_sections
    ):
        out.append("**Attributes:**")
        out.append("")
        for attr in documented_attrs:
            ann = f" (`{_fmt_annotation(attr.annotation)}`)" if attr.annotation else ""
            summary = " ".join(attr.docstring.value.split())
            out.append(f"- `{attr.name}`{ann}: {summary}")
        out.append("")

    # Headings carry only the member name; the full signature goes in a code
    # fence below (matching _render_function) so long signatures don't render
    # as multi-line headings.
    init = cls.members.get("__init__")
    if init is not None and not init.is_alias and init.is_function and init.docstring is not None:
        out += [f"### `{cls.name}` constructor", ""]
        out += [f"```python\n{_signature(init).replace('__init__', cls.name)}\n```", ""]
        out += _render_docstring(init)

    for method in methods:
        out += [f"### `{method.name}`", ""]
        out += [f"```python\n{cls.name}.{_signature(method)}\n```", ""]
        out += _render_docstring(method)
    return out


def _render_function(func: griffe.Function, import_path: str) -> list[str]:
    out = [f"## `{func.name}`", ""]
    out += [f"```python\nfrom {import_path} import {func.name}\n```", ""]
    out += [f"```python\n{_signature(func)}\n```", ""]
    out += _render_docstring(func)
    return out


def _render_enum(cls: griffe.Class, import_path: str) -> list[str]:
    out = [f"## `{cls.name}`", ""]
    out += [f"```python\nfrom {import_path} import {cls.name}\n```", ""]
    out += _render_docstring(cls)
    members = [
        m
        for m in cls.members.values()
        if m.is_attribute and not m.name.startswith("_")
    ]
    members.sort(key=lambda m: m.lineno or 0)
    if members:
        out += ["**Members:**", ""]
        for m in members:
            value = f" = `{m.value}`" if m.value is not None else ""
            doc = ""
            if m.docstring is not None:
                doc = f" — {' '.join(m.docstring.value.split())}"
            out.append(f"- `{m.name}`{value}{doc}")
        out.append("")
    return out


def _render_attribute(attr: griffe.Attribute, import_path: str) -> list[str]:
    out = [f"## `{attr.name}`", ""]
    out += [f"```python\nfrom {import_path} import {attr.name}\n```", ""]
    ann = _fmt_annotation(attr.annotation)
    if ann:
        out += [f"*Type:* `{ann}`", ""]
    if attr.value is not None:
        out += [f"*Value:* `{attr.value}`", ""]
    out += _render_docstring(attr)
    return out


def _is_enum(cls: griffe.Class) -> bool:
    return any("Enum" in str(b) for b in cls.bases)


def _resolve(pkg: griffe.Module, tlog: griffe.Module, name: str):
    """Resolve a public name to (griffe object, import path)."""
    if name in SUBMODULE_IMPORTS:
        module_path = SUBMODULE_IMPORTS[name]
        module = pkg
        for part in module_path.split(".")[1:]:
            module = module.members[part]
        return module.members[name], module_path
    if name.startswith("c2sp_tlog."):
        short = name.split(".", 1)[1]
        obj = tlog.members[short]
        while obj.is_alias:
            obj = obj.target
        return obj, "dnsid.c2sp_tlog"
    obj = pkg.members[name]
    while obj.is_alias:
        obj = obj.target
    return obj, "dnsid"


def _render_page(page: dict, pkg: griffe.Module, tlog: griffe.Module) -> str:
    lines = [
        "---",
        f"title: \"{page['title']}\"",
        f"description: \"{page['description']}\"",
        "---",
        "",
        "<!-- GENERATED FILE — do not edit. Regenerate with"
        " `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->",
        "",
    ]
    if page["intro"]:
        lines += [page["intro"], ""]
    for name in page["names"]:
        obj, import_path = _resolve(pkg, tlog, name)
        if obj.is_class:
            if _is_enum(obj):
                lines += _render_enum(obj, import_path)
            else:
                lines += _render_class(obj, import_path)
        elif obj.is_function:
            lines += _render_function(obj, import_path)
        elif obj.is_attribute:
            lines += _render_attribute(obj, import_path)
        else:
            raise SystemExit(f"gen_docs: cannot render {name} ({obj.kind})")
    text = "\n".join(lines)
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text.rstrip() + "\n"


def main() -> None:
    pkg = griffe.load(
        "dnsid",
        search_paths=[str(REPO_ROOT)],
        docstring_parser=griffe.Parser.google,
    )
    tlog = pkg.members["c2sp_tlog"]

    tlog_all = sorted(tlog.exports or [])
    for page in PAGES:
        if page["names"] == "C2SP_TLOG_ALL":
            page["names"] = [f"c2sp_tlog.{n}" for n in tlog_all]

    # Completeness check: every public name maps to exactly one page.
    assigned: dict[str, str] = {}
    for page in PAGES:
        for name in page["names"]:
            if name in assigned:
                raise SystemExit(
                    f"gen_docs: {name} on both '{assigned[name]}' and '{page['slug']}'"
                )
            assigned[name] = page["slug"]
    public = (
        set(pkg.exports or [])
        | {f"c2sp_tlog.{n}" for n in tlog_all}
        | set(SUBMODULE_IMPORTS)
        | TOPLEVEL_NOT_IN_ALL
    )
    missing = sorted(public - set(assigned))
    extra = sorted(set(assigned) - public)
    if missing or extra:
        raise SystemExit(
            "gen_docs: page mapping out of sync with the public API.\n"
            f"  unassigned public names: {missing}\n"
            f"  assigned but not public: {extra}\n"
            "Update PAGES in scripts/gen_docs.py."
        )

    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)

    nav = []
    for page in PAGES:
        (OUT_DIR / f"{page['slug']}.md").write_text(
            _render_page(page, pkg, tlog), encoding="utf-8"
        )
        nav.append({"label": page["label"], "slug": f"{SLUG_PREFIX}/{page['slug']}"})
    (OUT_DIR / "nav.json").write_text(
        json.dumps(nav, indent=2) + "\n", encoding="utf-8"
    )
    print(f"gen_docs: wrote {len(PAGES)} pages + nav.json to {OUT_DIR}", file=sys.stderr)


if __name__ == "__main__":
    main()
