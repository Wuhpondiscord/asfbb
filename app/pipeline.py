import asyncio
import json
import re
from urllib.parse import urlsplit

def clean_output(data):
    value = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "\n")

async def execute(args, timeout):
    try:
        p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        return ["Binary missing"], "unavailable"
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        await p.communicate()
        return ["Stage timed out"], "timeout"
    lines = clean_output(out).splitlines()[:500]
    if p.returncode:
        lines += ["[stderr] " + x[:200] for x in clean_output(err).splitlines()[-8:]]
    return lines, "completed" if p.returncode == 0 else "failed"

def in_host(url, host):
    try:
        p = urlsplit(url)
        return p.scheme in ("http", "https") and p.hostname == host and not p.username and not p.password
    except ValueError:
        return False

async def katana(url, host, agent, depth=1):
    rows, status = await execute(["/usr/local/bin/katana", "-u", url, "-d", str(max(1,min(int(depth),2))), "-fs", "fqdn", "-c", "1",
        "-p", "1", "-rl", "1", "-ct", "30s", "-timeout", "8", "-retry", "0",
        "-H", "User-Agent: " + agent, "-silent", "-duc"], 65)
    return {"status": status, "endpoints": list(dict.fromkeys(x.strip() for x in rows if in_host(x.strip(), host)))[:100]}

async def nuclei(url, host, agent):
    rows, status = await execute(["/usr/local/bin/nuclei", "-u", url, "-tags", "tech", "-rl", "1",
        "-c", "1", "-bs", "1", "-timeout", "8", "-retries", "0", "-jsonl",
        "-silent", "-duc", "-H", "User-Agent: " + agent], 90)
    findings = []
    for row in rows:
        try:
            obj = json.loads(row)
        except ValueError:
            continue
        found_url = obj.get("matched-at") or obj.get("host") or url
        if not in_host(found_url, host):
            continue
        info = obj.get("info") or {}
        findings.append({"name": info.get("name") or obj.get("template-id") or "Technology",
                         "risk": str(info.get("severity", "info")).title().replace("Info", "Informational"),
                         "confidence": "Medium", "url": found_url,
                         "description": str(info.get("description") or "")[:1000],
                         "source": "nuclei", "template_id": obj.get("template-id")})
    return {"status": status, "alerts": findings[:100]}

async def gau(url, host):
    rows, status = await execute(["/usr/local/bin/gau", "--threads", "1", "--timeout", "15",
        host], 55)
    return {"status": status, "endpoints": list(dict.fromkeys(
        value.strip() for value in rows if in_host(value.strip(), host)))[:100]}

async def probe(urls, host, agent, limit=1):
    # Header-only non-intrusive metadata probe. URLs are limited to the selected host.
    targets = list(dict.fromkeys(u for u in urls if in_host(u, host)))[:max(1, min(int(limit), 10))]
    if not targets:
        return {"status": "completed", "probes": []}
    all_rows = []
    status = "completed"
    for target in targets:
        args = ["/usr/local/bin/pd-httpx", "-u", target, "-json", "-silent",
            "-rl", "1", "-threads", "1", "-timeout", "8", "-retries", "0",
            "-H", "User-Agent: " + agent, "-no-color"]
        rows, stage_status = await execute(args, 30)
        all_rows.extend(rows)
        if stage_status != "completed": status = stage_status
    probes = []
    for line in all_rows:
        try:
            item = json.loads(line)
            found = item.get("url", "")
            if in_host(found, host):
                probes.append({"url": found, "status_code": item.get("status_code"),
                               "title": str(item.get("title") or "")[:160],
                               "webserver": str(item.get("webserver") or "")[:120],
                               "source": "httpx"})
        except ValueError:
            continue
    return {"status": status, "probes": probes[:10]}
