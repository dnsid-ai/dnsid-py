# Public Release Preparation

## Must fix before making the repository public

### 1. Finish PyPI setup

The release workflow now publishes the checked wheel and sdist to PyPI and attaches the same artifacts to the GitHub release.

- Claim the `dnsid` PyPI project name.
- Configure PyPI Trusted Publishing for this repository and workflow.
- Create and protect the `pypi` GitHub environment used by `.github/workflows/release.yml`.

### 2. Audit the complete Git history and existing release artifacts

Making the repository public exposes every historical commit, tag, and existing GitHub release—not only the current `main` branch.

- Review the complete history for confidential information, proprietary material, credentials, and unintended files.
- Review all attached GitHub release artifacts.
- Current GitHub secret scanning reports no open alerts, but this should not replace an explicit legal and security review.

### 3. Align branch protection with the documentation

`CONTRIBUTING.md` claims code-owner reviews, resolved conversations, and signed commits are required. Current branch protection does not enforce all of those controls, and required status checks appear unset.

Configure protection to require the intended controls, including:

- lint and tests
- compliance checks
- CodeQL
- code-owner review, if intended
- resolved conversations
- signed commits, if intended
- administrator enforcement, if intended

Otherwise, correct the documentation to describe the actual policy.

## Repository settings

- Enable immutable GitHub Releases.
- Add a GitHub repository description; it is currently blank.

## Checks already passing

- Ruff passes.
- Strict mypy passes.
- All 971 tests pass.
- The wheel and sdist build successfully and pass `twine check`.
- The installed-wheel import smoke test passes.
- GitHub reports no open CodeQL, Dependabot, or secret-scanning alerts. CodeQL alerts [#4](https://github.com/dnsid-ai/dnsid-py/security/code-scanning/4) and [#5](https://github.com/dnsid-ai/dnsid-py/security/code-scanning/5) were fixed by restricting key-store files before writing private key material.
- GitHub Actions are pinned to commit SHAs.

## Release blockers

The remaining blockers are:

1. PyPI project, Trusted Publishing, and protected-environment setup.
2. History and release-artifact review.
3. Branch-protection alignment.
