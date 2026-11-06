"""Build all release artifacts and exercise wheels outside the source checkout."""

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command, *, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=240)  # noqa: S603
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_release_artifacts_and_installed_gcp_extra_consumer(tmp_path):
    """**Mode**: fake-only KMS/DNS/HTTPS; real build/install (package index needed).

    Build tools and runtime dependencies may be obtained from the configured
    package index. The installed DNSid distribution must come from this checkout.
    Test sources are copied, never SDK sources; isolated Python drops PYTHONPATH.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    dist = tmp_path / "dist"
    run([sys.executable, "-m", "build", "--outdir", str(dist), str(ROOT)], cwd=tmp_path, env=env)
    artifacts = list(dist.iterdir())
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    assert len(artifacts) == 2 and len(wheels) == len(sdists) == 1
    assert wheels[0].name.startswith("dnsid-")
    run([sys.executable, str(ROOT / "scripts/check_distribution_attribution.py"), str(dist)], cwd=tmp_path, env=env)
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    venv.EnvBuilder(with_pip=True).create(tmp_path / "venv")
    python = tmp_path / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run([str(python), "-I", "-m", "pip", "install", *map(str, wheels), "pytest"], cwd=consumer, env=env)
    run([str(python), "-I", "-c", """
import importlib.util
import sys
from dnsid import ArgumentError, GoogleKmsKeyProvider
from dnsid.config_loading import KeySource, _validate_key_source

assert "google.cloud.kms_v1" not in sys.modules
assert "google_crc32c" not in sys.modules
assert importlib.util.find_spec("google_crc32c") is None
try:
    _validate_key_source(KeySource(provider="google-kms", key_ref="existing"))
except ArgumentError as error:
    assert "install dnsid[gcp]" in str(error)
else:
    raise AssertionError("Google KMS must require the gcp extra")
"""], cwd=consumer, env=env)
    run([str(python), "-I", "-m", "pip", "install", f"{wheels[0]}[gcp]"], cwd=consumer, env=env)
    shutil.copytree(ROOT / "tests", consumer / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    imports = run([str(python), "-I", "-c", (
        "import pathlib,dnsid; "
        "from dnsid import google_kms_key_provider; "
        "from importlib.metadata import distribution; "
        "assert dnsid.GoogleKmsKeyProvider is google_kms_key_provider.GoogleKmsKeyProvider; "
        "mods=(dnsid,google_kms_key_provider); "
        "assert all('site-packages' in str(pathlib.Path(m.__file__)) for m in mods); "
        "assert all(not distribution(n).read_text('direct_url.json') or "
        "'editable' not in distribution(n).read_text('direct_url.json') "
        "for n in ('dnsid',)); "
        "print(*(m.__file__ for m in mods),sep='\\n')"
    )], cwd=consumer, env=env)
    assert str(ROOT) not in imports
    run([str(python), "-I", "-m", "pytest", "-q", "tests/test_google_kms_functional.py"], cwd=consumer, env=env)
