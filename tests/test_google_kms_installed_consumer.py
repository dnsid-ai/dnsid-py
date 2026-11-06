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


def test_four_release_artifacts_and_installed_config_profile_consumer(tmp_path):
    """**Mode**: fake-only KMS/DNS/HTTPS; real build/install (package index needed).

    Build tools and runtime dependencies may be obtained from the configured
    package index. Neither installed DNSid distribution may come from that index.
    Test sources are copied, never SDK sources; isolated Python drops PYTHONPATH.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    dist = tmp_path / "dist"
    for source in (ROOT, ROOT / "packages/google-kms"):
        run([sys.executable, "-m", "build", "--outdir", str(dist), str(source)], cwd=tmp_path, env=env)
    artifacts = list(dist.iterdir())
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    assert len(artifacts) == 4 and len(wheels) == len(sdists) == 2
    assert {p.name.split("-0.")[0] for p in wheels} == {"dnsid", "dnsid_google_kms"}
    run([sys.executable, str(ROOT / "scripts/check_distribution_attribution.py"), str(dist)], cwd=tmp_path, env=env)
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    venv.EnvBuilder(with_pip=True).create(tmp_path / "venv")
    python = tmp_path / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run([str(python), "-I", "-m", "pip", "install", *map(str, wheels), "pytest"], cwd=consumer, env=env)
    shutil.copytree(ROOT / "tests", consumer / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    imports = run([str(python), "-I", "-c", (
        "import pathlib,dnsid,dnsid_google_kms; "
        "from importlib.metadata import distribution; "
        "mods=(dnsid,dnsid_google_kms); "
        "assert all('site-packages' in str(pathlib.Path(m.__file__)) for m in mods); "
        "assert all(not distribution(n).read_text('direct_url.json') or "
        "'editable' not in distribution(n).read_text('direct_url.json') "
        "for n in ('dnsid','dnsid-google-kms')); "
        "print(*(m.__file__ for m in mods),sep='\\n')"
    )], cwd=consumer, env=env)
    assert str(ROOT) not in imports
    output = run([str(python), "-I", "-m", "pytest", "-q", "tests/test_google_kms_functional.py"], cwd=consumer, env=env)
    assert "10 passed" in output
