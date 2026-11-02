"""Generate an isolated test key on the CI runner and detect it without verification."""
import json
import subprocess
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    key = Path(tmp) / "fixture.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run(["/usr/local/bin/trufflehog", "filesystem", tmp, "--json",
                             "--no-verification", "--no-update", "--concurrency", "1",
                             "--include-detectors", "PrivateKey,AWS,Github,Slack,HuggingFace,OpenAI",
                             "--results", "verified,unverified,unknown", "--allow-verification-overlap",
                             "--no-verification-cache"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    findings = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert any("private" in str(item.get("DetectorName", "")).lower() for item in findings)
print("TruffleHog installed detector smoke passed; generated key and output discarded")
