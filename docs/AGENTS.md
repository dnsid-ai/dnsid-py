# Rules for working in docs/

Durable rules for anyone — human or agent — touching this directory.

## Generated vs hand-written

- **`docs/reference/` is generated.** Every file in it (including
  `nav.json`) is emitted by `scripts/gen_docs.py` from the package's
  docstrings. **Never hand-edit these files** — fix the docstring (or the
  generator) and regenerate:

  ```sh
  python scripts/gen_docs.py
  ```

  CI runs the generator and warns if `git diff docs/reference/` is dirty;
  same-repo PR branches get an auto-regeneration commit, while fork PRs
  must regenerate and commit the reference manually.
- **`quickstart.md` and `security.md` are hand-written** and freely
  editable.

## Export to the docs site

Files under `docs/reference/` are exported **verbatim** to the
docs site repository (the Astro/Starlight site behind
docs.dnsid.ai) under `src/content/docs/reference/py/`, and
`nav.json` feeds that site's `nav.mjs`. Consequences:

- Every reference page needs YAML frontmatter with `title` (e.g.
  "Python: IdentityManager") and a one-line `description` — the
  generator emits these; keep the requirement in mind when changing it.
- Links to other docs pages must be **absolute**
  `https://docs.dnsid.ai/...` URLs, never site-relative slugs — the
  files render both on GitHub and on the docs site, and relative slugs
  break on GitHub.

## Docstring and terminology conventions

- Docstrings are **Google style** (`Args:` / `Returns:` / `Raises:`),
  enforced by ruff's pydocstyle rules (`convention = "google"`). They
  describe behavior and contracts (inputs, returns, raises, side
  effects), not implementation history.
- Terminology: "DNSid" (capital DNS, lowercase id), "identity record",
  "operational key" / "entity key", "agent".
- Application profiles (JOSE, HTTP Message Signatures, Web Bot Auth, OIDC)
  are explicitly **not part of the core DNSid
  protocol** — preserve that framing wherever profiles are described.
- The public API is synchronous by design; async support is limited to
  the httpx transport plumbing and `async_retry_transient`. Don't
  document methods as async-capable.
