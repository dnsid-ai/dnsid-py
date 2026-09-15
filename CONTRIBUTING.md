# Contributing to dnsid-py

Thanks for contributing! This is the Python client SDK for the DNSid protocol.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Signed commits

As of 2026-07-09, contributors are expected to sign local commits for this
repository. Commits created through GitHub's web UI are signed by GitHub
automatically, but commits created from a local Git CLI need local signing
configured before you push them. GitHub branch enforcement must be enabled
separately before saying `main` rejects unsigned commits.

SSH commit signing is the preferred setup for this SDK. GitHub verifies SSH,
GPG, and S/MIME signatures, but SSH signing works with normal SSH keys and
requires Git 2.34 or later.

These commands set up a dedicated SSH signing key. To reuse an existing SSH key
instead, set `SIGNING_KEY` to that private key path before running the block.

```bash
git --version

git_email="$(git config user.email)"
test -n "$git_email" || {
  echo "Set your Git email first: git config user.email you@example.com"
  exit 1
}

SIGNING_KEY="${SIGNING_KEY:-$HOME/.ssh/id_ed25519_signing}"
if [ ! -f "$SIGNING_KEY" ]; then
  ssh-keygen -t ed25519 -C "$git_email" -f "$SIGNING_KEY"
fi
test -f "${SIGNING_KEY}.pub" || ssh-keygen -y -f "$SIGNING_KEY" > "${SIGNING_KEY}.pub"
```

Upload the public key to GitHub as a signing key:

```bash
gh auth status
SIGNING_KEY="${SIGNING_KEY:-$HOME/.ssh/id_ed25519_signing}"
gh ssh-key add "${SIGNING_KEY}.pub" --type signing --title "$(hostname)-dnsid-py-signing"
```

Configure Git to sign commits and tags with that SSH key:

```bash
SIGNING_KEY="${SIGNING_KEY:-$HOME/.ssh/id_ed25519_signing}"
git config --global gpg.format ssh
git config --global user.signingkey "${SIGNING_KEY}.pub"
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Confirm your Git commit email is verified on GitHub. The command should print
your email with `"verified": true`; if it prints nothing or `false`, add or
verify that email in your GitHub account settings before opening a PR.

```bash
git_email="$(git config user.email)"
gh api user/emails --jq ".[] | select(.email == \"$git_email\") | {email, verified}"
```

Verify the setup with a throwaway signed branch and commit:

```bash
previous_branch="$(git branch --show-current)"
test_branch="verify-signed-commit-$(date +%s)"

git switch -c "$test_branch"
git commit --allow-empty -m "verify signed commit setup"
test_sha="$(git rev-parse HEAD)"

git log --show-signature -1 "$test_sha"
git push -u origin "$test_branch"
gh api "repos/:owner/:repo/commits/$test_sha" --jq '.commit.verification | {verified, reason}'

git switch "$previous_branch"
git branch -D "$test_branch"
git push origin --delete "$test_branch"
```

The GitHub API verification result should report `"verified": true`. For more
detail, see GitHub's docs on
[telling Git about your signing key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key)
and
[signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

## Pull requests

- Branch off `main`; open a PR against `main`.
- All PRs require **1 approving review** from a code owner and all conversations resolved before merge.
- Keep changes focused; add tests for behavior changes.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not file public issues for vulnerabilities.
