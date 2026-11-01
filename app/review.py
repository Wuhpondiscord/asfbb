"""Opt-in single-target verification stages. Output is evidence, not confirmed findings."""
import json
import tempfile
from pathlib import Path
import re
from collections import Counter
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
        return ["/opt/asfb-venv/bin/arjun", "-u", url, "-t", "1",
                "-T", "8", "--rate-limit", "2"]
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

def ffuf_discoveries(lines, host):
    """Only preserve directly observed same-host success responses as URLs."""
    found = []
    for line in lines:
        try:
            item = json.loads(line)
        except (TypeError, ValueError):
            continue
        if (isinstance(item, dict) and item.get("status") in (200, 201, 202, 204)
                and isinstance(item.get("url"), str) and in_host(item["url"], host)):
            found.append(item["url"])
    return list(dict.fromkeys(found))[:100]


def summarize_review(module, lines):
    if module == "ffuf":
        results = []
        for line in lines:
            try:
                item = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(item, dict) and isinstance(item.get("status"), int) and item.get("url"):
                results.append(item)
        if results:
            redirects = Counter((item.get("status"), item.get("redirectlocation")) for item in results
                                if 300 <= item["status"] < 400 and item.get("redirectlocation"))
            common = {pair for pair, count in redirects.items() if count >= 3}
            kept = [item for item in results if (item.get("status"), item.get("redirectlocation")) not in common]
            return ("\n".join(f'{item["status"]} {item["url"]} -> {item.get("redirectlocation") or "-"}' for item in kept[:100])
                    + (f"\nSuppressed {len(results)-len(kept)} repeated redirects to the same destination; likely wildcard redirect behavior." if common else "")).strip()
    if module == "arjun":
        cleaned = [re.sub(r"\s+", " ", line).strip() for line in lines
                   if not re.search(r"Processing chunks:|^\\s*[_/\\\\|()]+\\s*$", line)]
        return "\n".join(line for line in cleaned if line)[-2500:]
    return "\n".join(lines)[:5000]

def read_arjun_results(path, host):
    """Parse Arjun's JSON export without trusting URLs outside the exact host."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8")[:500000])
    except (OSError, ValueError):
        return []
    if not isinstance(payload, dict):
        return []
    found = []
    for candidate, data in payload.items():
        if not in_host(candidate, host) or not isinstance(data, dict):
            continue
        method = str(data.get("method") or "GET").upper()
        for entry in data.get("params", []):
            name = entry.get("name") if isinstance(entry, dict) else entry
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.$-]{1,100}", name):
                found.append({"url": candidate, "method": method, "name": name,
                              "source": "arjun"})
    return found[:100]


async def review(module, url, host):
    if module == "sqlmap" and not urlsplit(url).query:
        return {"source": module, "status": "skipped", "target": url, "output": "", "reason": "URL has no query parameters"}
    args = command(module, url, host)
    parameters = []
    if module == "arjun":
        with tempfile.TemporaryDirectory(prefix="asfb-arjun-") as tmp:
            export_path = str(Path(tmp) / "parameters.json")
            lines, status = await execute(args + ["-oJ", export_path],
                                          config.ARJUN_TIMEOUT_SECONDS)
            parameters = read_arjun_results(export_path, host)
    else:
        timeout = (config.DALFOX_TIMEOUT_SECONDS if module == "dalfox"
                   else config.PROCESS_TIMEOUT_SECONDS)
        lines, status = await execute(args, timeout)
    has_evidence = module == "dalfox" and any("[POC]" in line for line in lines)
    exit_code = next((int(line.rsplit(":", 1)[1].strip()) for line in lines
                      if line.startswith("[diagnostic] Process exit code:")
                      and line.rsplit(":", 1)[1].strip().isdigit()), None)
    if module == "dalfox" and status == "failed":
        # Documented: 0 = clean, 1 = findings, 2 = runtime/configuration error.
        if exit_code == 1:
            status = "findings"
        elif has_evidence:
            status = "partial"
    # Code 1 is an expected Dalfox finding outcome, not an error diagnostic.
    displayed_lines = [line for line in lines
                       if not (module == "dalfox" and status == "findings"
                               and line.strip() == "[diagnostic] Process exit code: 1")]
    reason = " | ".join(line[:180] for line in displayed_lines
                        if line.startswith(("[stderr]", "[diagnostic]")))
    if not reason and status == "failed":
        reason = f"{module} exited unsuccessfully; inspect its output"
    if not reason and status == "partial" and has_evidence:
        reason = "Unverified findings were returned, but the tool did not finish cleanly"
    return {"source": module, "status": status, "target": url,
            "exit_code": exit_code,
            "parameters": parameters,
            "endpoints": ffuf_discoveries(lines, host) if module == "ffuf" else [],
            "output": summarize_review(module, displayed_lines),
            "reason": reason[:500],
            "note": "Unverified tool output. Confirm impact manually before reporting."}
