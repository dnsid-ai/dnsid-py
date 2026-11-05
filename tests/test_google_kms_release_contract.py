"""Release-wiring guards: the optional distribution must actually reach users.

Inspect declarative workflows/manifests, never provider implementation bodies.
These are repository proof guards, not protocol or manager lifecycle contracts.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "packages/google-kms"


def executable_lines(text):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_given_release_when_building_then_google_wheel_and_sdist_share_uploaded_dist():
    """**Mode**: real-capable (repository files). GWT: optional package is built."""
    workflow = executable_lines((ROOT / ".github/workflows/release.yml").read_text())
    lines = workflow.splitlines()
    google_builds = [line for line in lines if PACKAGE in line and "-m build" in line]
    assert google_builds, "release must build packages/google-kms, not only the root distribution"
    # An unrestricted build creates both wheel and sdist; require one shared output
    # so the existing checked/uploaded/published artifact cannot omit the provider.
    assert any("--wheel" not in line and "--sdist" not in line
               and ("--outdir dist" in line or "-o dist" in line)
               for line in google_builds), "build Google wheel AND sdist into the shared dist directory"
    assert "python -m twine check dist/*" in workflow
    assert "python scripts/check_distribution_attribution.py dist" in workflow


def test_given_shared_distributions_when_released_then_upload_download_publish_cover_all():
    """**Mode**: real-capable (repository files). GWT: no wheel-only artifact filter."""
    workflow = executable_lines((ROOT / ".github/workflows/release.yml").read_text())
    assert "actions/upload-artifact@" in workflow
    assert "actions/download-artifact@" in workflow
    assert workflow.count("name: dist") >= 2
    assert workflow.count("path: dist/") >= 2
    assert "if-no-files-found: error" in workflow
    assert "pypa/gh-action-pypi-publish@" in workflow
    assert "dist/* sbom.cdx.json" in workflow
    assert "subject-path: dist/*" in workflow
    # The publisher's default directory is dist; an explicit override must retain it.
    for line in workflow.splitlines():
        if "packages-dir:" in line:
            assert line.strip().split(":", 1)[1].strip().strip("\"'") in {"dist", "dist/"}


def test_given_release_version_bump_when_preparing_then_google_version_is_managed():
    """**Mode**: real-capable (repository files). GWT: provider cannot stay at 0.1.0 forever."""
    workflow = executable_lines((ROOT / ".github/workflows/release-pr.yml").read_text())
    assert f"{PACKAGE}/pyproject.toml" in workflow, (
        "release preparation must explicitly manage the Google distribution version "
        "alongside its release artifacts"
    )
