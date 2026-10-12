import subprocess
import sys
from pathlib import Path


def test_rejects_missing_arguments_and_invalid_trust(tmp_path: Path) -> None:
    script = Path(__file__).parents[1] / "examples/trust-policy/main.py"
    missing = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert missing.returncode == 1
    assert "usage:" in missing.stderr
    profile = tmp_path / "profile.json"
    profile.write_text("{}")
    invalid = subprocess.run(
        [sys.executable, str(script), "agent.example", str(profile), "acme.example", "invalid"],
        capture_output=True, text=True,
    )
    assert invalid.returncode == 1
    assert "trust profile" in invalid.stderr
    # A valid profile reaches pin validation without querying DNS.
    profile.write_text(r'''{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.example",
  "tlog_policy": "log log.example+3db4ee08+AcqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\nwitness primary witness.example+da76602f+BG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx\nquorum primary\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+dfa43feb+AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  ]
}''')
    invalid_pin = subprocess.run(
        [sys.executable, str(script), "agent.example", str(profile), "acme.example", "invalid"],
        capture_output=True, text=True,
    )
    assert invalid_pin.returncode == 1
    assert "thumbprint" in invalid_pin.stderr.lower()
