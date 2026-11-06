"""Release-wiring guards for Google KMS support in the main distribution.

Inspect declarative workflows/manifests, never provider implementation bodies.
These are repository proof guards, not protocol or manager lifecycle contracts.
"""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def executable_lines(text):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_given_release_when_building_then_main_distribution_includes_google_extra():
    """**Mode**: real-capable (repository files). GWT: provider ships in dnsid."""
    manifest = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert manifest["project"]["optional-dependencies"]["gcp"] == [
        "google-cloud-kms>=3.0", "google-crc32c>=1.5",
    ]
    assert manifest["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["dnsid"]
    assert (ROOT / "dnsid/google_kms_key_provider.py").is_file()
    workflow = executable_lines((ROOT / ".github/workflows/release.yml").read_text())
    assert "python -m build\n" in workflow
    assert "python -m twine check dist/*" in workflow
    assert "python scripts/check_distribution_attribution.py dist" in workflow
    assert 'pip install "${wheel}[gcp]"' in workflow


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


def test_given_release_version_bump_when_preparing_then_main_version_is_managed():
    """**Mode**: real-capable (repository files). GWT: one distribution version."""
    workflow = executable_lines((ROOT / ".github/workflows/release-pr.yml").read_text())
    assert 'sed -i "s/^version = \\".*\\"/version = \\"${VERSION_BARE}\\"/" pyproject.toml' in workflow
    assert "uv lock" in workflow
