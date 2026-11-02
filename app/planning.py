"""Stable producer/consumer planning; never enable tools or expand target scope."""
from urllib.parse import urlsplit

MODULES = ("gau", "katana", "httpx", "wafw00f", "zap-passive", "nuclei", "nikto", "wpscan",
           "testssl", "wapiti", "retirejs", "amass", "kiterunner", "nettacker",
           "idor-forge", "trufflehog", "semgrep", "depscan", "trivy", "osv-scanner", "garak",
           "ffuf", "arjun", "dalfox", "sqlmap", "graphw00f", "corsy", "takeover", "s3-review", "websocket", "vcs-artifacts")
URL_PRODUCERS = ("gau", "katana", "ffuf", "kiterunner")
URL_CONSUMERS = ("httpx", "zap-passive", "nuclei", "retirejs", "arjun", "dalfox", "sqlmap", "graphw00f", "websocket")
STATIC_EXTENSIONS = (".js", ".mjs", ".css", ".json", ".map", ".svg", ".png", ".jpg",
                     ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2", ".webmanifest")


def same_origin(candidate, target):
    try:
        a, b = urlsplit(candidate), urlsplit(target)
        return (isinstance(candidate, str) and a.scheme in ("http", "https") and
                not a.username and not a.password and a.hostname == b.hostname and
                a.scheme == b.scheme and
                (a.port or (443 if a.scheme == "https" else 80)) ==
                (b.port or (443 if b.scheme == "https" else 80)))
    except (TypeError, ValueError, AttributeError):
        return False


def plan(modules, mode="manual", reuse=False):
    requested = list(modules)
    if not requested or len(requested) != len(set(requested)) or any(m not in MODULES for m in requested):
        raise ValueError("Select unique supported pipeline modules")
    if mode not in ("manual", "guided"):
        raise ValueError("Pipeline mode must be manual or guided")
    edges = {(p, c) for p in URL_PRODUCERS for c in URL_CONSUMERS}
    edges.update({("gau", "katana"), ("arjun", "dalfox"), ("arjun", "sqlmap"),
                  ("httpx", "arjun"), ("httpx", "retirejs"), ("httpx", "zap-passive"),
                  ("httpx", "nuclei")})
    edges.update({("wafw00f", c) for c in ("ffuf", "nuclei", "nikto", "wpscan", "wapiti", "arjun", "dalfox", "sqlmap")})
    if reuse:
        edges.update({("httpx", c) for c in ("nikto", "wpscan", "wapiti", "corsy")})
    edges = {(p, c) for p, c in edges if p in requested and c in requested and p != c}
    ordered, remaining = [], requested.copy()
    if mode == "guided":
        while remaining:
            ready_nodes = [m for m in remaining if not any(c == m and p in remaining for p, c in edges)]
            def phase(m):
                return 0 if m in URL_PRODUCERS or m in ("amass", "takeover") else 1 if m == "httpx" else 2 if m == "arjun" else 3
            ready = min(ready_nodes, key=lambda m: (phase(m), requested.index(m)), default=None)
            if ready is None:
                raise ValueError("Pipeline dependencies contain a cycle")
            ordered.append(ready)
            remaining.remove(ready)
    else:
        ordered = requested.copy()
    positions = {m: i for i, m in enumerate(ordered)}
    warnings = [p + " runs after " + c + "; its new data will not be available to that earlier stage"
                for p, c in sorted(edges) if positions[p] > positions[c]]
    handoffs = [{"from": p, "to": c,
                 "data": "WAF inventory / scan context" if p == "wafw00f" else
                         "GET parameters" if p == "arjun" else
                         "page metadata" if p == "httpx" else
                         "bounded same-origin crawl seeds" if c == "katana" else "URL inventory",
                 "available": positions[p] < positions[c]}
                for p, c in sorted(edges) if p != "amass"]
    return {"mode": mode, "requested": requested, "effective": ordered,
            "changed": requested != ordered, "warnings": warnings, "handoffs": handoffs,
            "extended_reuse": reuse,
            "scope_note": "Only the selected host is scanned. Discovered hostnames remain inventory."}


def crawl_seeds(primary, inventory, maximum=3):
    candidates = [u for u in inventory or [] if isinstance(u, str) and same_origin(u, primary)
                  and not urlsplit(u).path.lower().endswith(STATIC_EXTENSIONS)
                  and not any(c in u for c in "\r\n\x00")]
    candidates.sort(key=lambda u: (bool(urlsplit(u).query), len(urlsplit(u).path)))
    selected, seen = [], set()
    for candidate in [primary] + candidates:
        parts = urlsplit(candidate)
        key = (parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80),
               parts.path or "/", parts.query)
        if key in seen:
            continue
        seen.add(key)
        selected.append(candidate)
        if len(selected) >= maximum:
            break
    return selected


def page_target(primary, probes):
    pages = []
    for probe in probes or []:
        if not isinstance(probe, dict):
            continue
        candidate = probe.get("url")
        code = probe.get("status_code") or probe.get("status-code")
        content = str(probe.get("content_type") or probe.get("content-type") or "").lower()
        if (code == 200 and isinstance(candidate, str) and same_origin(candidate, primary)
                and ("html" in content or not content and not urlsplit(candidate).path.lower().endswith(STATIC_EXTENSIONS))):
            pages.append(candidate)
    if primary in pages or not pages:
        return primary
    return min(pages, key=lambda u: (bool(urlsplit(u).query), len(urlsplit(u).path)))


def assessed_urls(primary, inventory, probes):
    """Prefer observed success responses and omit known error pages, within origin."""
    codes = {p.get("url"): p.get("status_code") for p in probes or [] if isinstance(p, dict)}
    candidates = list(dict.fromkeys([primary] + [u for u in inventory or [] if isinstance(u, str)]))
    scoped = [u for u in candidates if same_origin(u, primary) and
              not (isinstance(codes.get(u), int) and codes[u] >= 400)]
    return sorted(scoped, key=lambda u: (0 if codes.get(u) == 200 else 1, candidates.index(u))) or [primary]
