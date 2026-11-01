import csv
import io
import ipaddress
import re
import socket
from urllib.parse import urlsplit

WEB_TYPES = {"domain", "url", "website", "web application", "api"}
LEVELS = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def yes(value):
    s = str(value or "").strip().lower()
    return s in {"true", "yes", "eligible", "1", "y"}

def field(row, *aliases):
    normalized = {re.sub(r"[^a-z0-9]", "", str(k).lower()): v for k, v in row.items() if k is not None}
    for alias in aliases:
        key = re.sub(r"[^a-z0-9]", "", alias.lower())
        if key in normalized:
            return str(normalized[key] or "").strip()
    return ""

def classify(identifier, asset_type):
    name = identifier.strip()
    kind = asset_type.lower().strip()
    if "*" in name or kind in {"other", "android", "android: play store", "ios", "source code", "executable", "hardware"}:
        return "manual"
    if kind and kind not in WEB_TYPES:
        return "manual"
    try:
        p = urlsplit(name if "://" in name else "https://" + name)
        host = (p.hostname or "").lower().rstrip(".")
        if p.scheme not in {"http", "https"} or not host or p.username or p.password:
            return "manual"
        if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
            return "manual"
        if p.port not in (None, 80, 443, 8080):
            return "manual"
        return "web"
    except ValueError:
        return "manual"

def parse_csv(content):
    if len(content) > 2_000_000:
        raise ValueError("CSV too large (max 2 MB)")
    decoded = content.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(decoded))
    if not reader.fieldnames:
        raise ValueError("CSV is empty")
    assets = []
    for i, row in enumerate(reader):
        if i >= 3000:
            raise ValueError("Scope contains over 3000 entries")
        name = field(row, "asset_identifier", "asset name", "asset", "identifier")
        if not name:
            continue
        kind = field(row, "asset_type", "type")
        bounty = field(row, "eligible_for_bounty", "bounty", "bounty eligible")
        submission = field(row, "eligible_for_submission")
        severity = field(row, "max_severity", "max. severity", "maximum severity").lower()
        reports = field(row, "resolved reports", "resolved_reports", "resolved_reports_count")
        m = re.search(r"\d+", reports)
        assets.append({
            "id": "asset-" + str(i + 1),
            "name": name[:1000],
            "type": kind[:100],
            "compatibility": classify(name, kind),
            "bounty": yes(bounty),
            "submission": yes(submission) if submission else None,
            "max_severity": severity if severity in LEVELS else "unknown",
            "last_update": field(row, "last update", "last_updated", "updated_at")[:80],
            "resolved_reports": int(m.group()) if m else None,
            "description": field(row, "description", "instruction", "instructions", "asset description")[:3000],
            "coverage": field(row, "coverage")[:200]
        })
    if not assets:
        raise ValueError("No recognized asset names. Expected asset_identifier or Asset name column")
    return assets

def target_url(asset):
    if asset["compatibility"] != "web":
        raise ValueError("Only explicit web assets are scannable")
    raw = asset["name"].strip()
    p = urlsplit(raw if "://" in raw else "https://" + raw)
    if p.query or p.fragment:
        raise ValueError("Scope URL with query/fragment requires manual review")
    return p.geturl(), (p.hostname or "").lower().rstrip(".")

def public_host(host, allow_private=False):
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("Invalid hostname")
    try:
        addresses = {x[4][0] for x in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)}
    except socket.gaierror as exc:
        raise ValueError("DNS resolution failed") from exc
    if not addresses:
        raise ValueError("No DNS results")
    if not allow_private:
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ValueError("Private, reserved, or non-global address not allowed")
    return addresses
