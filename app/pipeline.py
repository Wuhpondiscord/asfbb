import asyncio
import json
from urllib.parse import urlsplit

async def execute(args, timeout):
    try:
        p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        return [], "unavailable"
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        await p.communicate()
        return [], "timeout"
    return out.decode("utf-8", "replace").splitlines()[:500], "completed" if p.returncode == 0 else "failed"

def in_host(url, host):
    try:
        p = urlsplit(url)
        return p.scheme in ("http", "https") and p.hostname == host and not p.username and not p.password
    except ValueError:
        return False

async def katana(url, host, agent):
    rows, status = await execute(["/usr/local/bin/katana", "-u", url, "-d", "1", "-fs", "fqdn", "-c", "1",
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
