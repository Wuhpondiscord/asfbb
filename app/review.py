"""Opt-in single-target verification stages. Output is evidence, not confirmed findings."""
from urllib.parse import urlsplit
from .pipeline import execute, in_host
from . import config

ACTIVE_MODULES = {"ffuf", "sqlmap", "dalfox", "arjun"}

def command(module, url, host):
    if not in_host(url, host):
        raise ValueError("Review URL must stay on the selected exact host")
    if module == "ffuf":
        return ["/usr/local/bin/ffuf", "-u", url.rstrip("/") + "/FUZZ",
                "-w", "/app/app/wordlists/paths.txt", "-t", "1", "-rate", "1",
                "-maxtime", "25", "-timeout", "5", "-noninteractive", "-json"]
    if module == "arjun":
        return ["/opt/asfb-venv/bin/arjun", "-u", url, "-t", "1"]
    if module == "dalfox":
        return ["/usr/local/bin/dalfox", "scan", url, "--workers", "1",
                "--timeout", "5", "--silence"]
    if module == "sqlmap":
        if not urlsplit(url).query:
            raise ValueError("SQLmap review requires a parameterized URL")
        return ["python3", "/opt/sqlmap/sqlmap.py", "-u", url,
                "--batch", "--level=1", "--risk=1", "--threads=1",
                "--timeout=5", "--retries=0", "--technique=B",
                "--smart", "--disable-coloring"]
    raise ValueError("Unsupported review module")

async def review(module, url, host):
    if module == "sqlmap" and not urlsplit(url).query:
        return {"source": module, "status": "skipped", "target": url, "output": "", "reason": "URL has no query parameters"}
    args = command(module, url, host)
    lines, status = await execute(args, config.PROCESS_TIMEOUT_SECONDS)
    return {"source": module, "status": status, "target": url,
            "output": "\n".join(lines)[:2500],
            "reason": (" | ".join(line[:180] for line in lines if line.startswith("[stderr]") or line.startswith("[diagnostic]")) or (f"{module} returned an unsuccessful exit status; inspect captured output" if status == "failed" else ""))[:500],
            "note": "Unverified tool output. Confirm impact manually before reporting."}
