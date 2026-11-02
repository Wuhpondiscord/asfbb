"""Bounded local-data parsing for direct URLs and common target-list formats.

Parsing never resolves DNS, fetches URLs, queues jobs, or executes supplied data.
"""
import csv
import io
import json
import re
from pathlib import PurePath

from .scope import TARGET_COLUMNS, asset_from_row, classify, parse_csv, target_url

MAX_BYTES = 2_000_000
MAX_TARGETS = 3000
FORMATS = {"auto", "text", "csv", "tsv", "json", "jsonl"}
WRAPPERS = ("targets", "urls", "assets", "scope", "data")


def decode(content):
    if isinstance(content, str):
        if len(content.encode("utf-8")) > MAX_BYTES:
            raise ValueError("Target input too large (max 2 MB)")
        return content.lstrip("\ufeff")
    if len(content) > MAX_BYTES:
        raise ValueError("Target file too large (max 2 MB)")
    try:
        return content.decode("utf-16") if content.startswith((b"\xff\xfe", b"\xfe\xff")) else content.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("Use UTF-8 text or UTF-16 text with a BOM") from exc


def normalized(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def has_target_column(row):
    return bool({normalized(key) for key in row} &
                {normalized(key) for key in TARGET_COLUMNS})


def text_rows(text):
    rows = []
    for line_number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        value = re.sub(r"^(?:[-+*] |\d+[.)] )", "", value).strip()
        if value.startswith("//"):
            value = "https:" + value
        if classify(value, "URL") != "web" and not re.fullmatch(r"\*\.[A-Za-z0-9.-]+", value):
            raise ValueError("Line " + str(line_number) + ": expected an HTTP(S) URL or hostname")
        rows.append({"url": value, "type": "Domain" if value.startswith("*.") else "URL"})
        if len(rows) > MAX_TARGETS:
            raise ValueError("Target input contains over 3000 entries")
    return rows


def json_rows(payload):
    if isinstance(payload, dict):
        if not has_target_column(payload):
            if isinstance(payload.get("attributes"), dict):
                payload = payload["attributes"]
            else:
                selected = next((payload[key] for key in WRAPPERS if key in payload), None)
                if selected is None:
                    raise ValueError("JSON requires a url/target field or a targets/urls/assets/scope/data array")
                payload = selected
        if isinstance(payload, dict):
            payload = [payload]
    if isinstance(payload, str):
        payload = [payload]
    if not isinstance(payload, list) or len(payload) > MAX_TARGETS:
        raise ValueError("JSON requires an array of at most 3000 URLs or target objects")
    rows = []
    for index, item in enumerate(payload):
        if isinstance(item, str):
            parsed = text_rows(item)
            if len(parsed) != 1:
                raise ValueError("Each JSON string must contain one URL")
            rows.append(parsed[0])
        elif isinstance(item, dict):
            if not has_target_column(item) and isinstance(item.get("attributes"), dict):
                item = item["attributes"]
            if not has_target_column(item):
                raise ValueError("JSON target " + str(index + 1) + " has no url/target/asset field")
            values = [value for key, value in item.items()
                      if normalized(key) in {normalized(column) for column in TARGET_COLUMNS}]
            if not any(isinstance(value, str) and value.strip() for value in values):
                raise ValueError("JSON target " + str(index + 1) + " requires a nonempty string URL/asset")
            rows.append(item)
        else:
            raise ValueError("JSON targets must be URL strings or target objects")
    return rows


def target_key(asset):
    if asset.get("compatibility") == "web":
        url, _ = target_url(asset)
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        return ("web", parts.scheme, parts.hostname,
                parts.port or (443 if parts.scheme == "https" else 80),
                parts.path or "/", parts.query)
    return ("manual", asset.get("type", "").lower(), asset["name"].strip())


def _parse_targets(content, filename="", format="auto"):
    if format not in FORMATS:
        raise ValueError("Unsupported target format")
    text = decode(content).strip()
    if not text:
        raise ValueError("Target input is empty")
    if format in ("auto", "text", "csv", "tsv"):
        lines = text.splitlines()
        start = next((i for i, line in enumerate(lines) if line.strip() and not line.lstrip().startswith("#")), len(lines))
        text = "\n".join(lines[start:]).strip()
        if not text:
            raise ValueError("No targets found")
    suffix = PurePath(filename or "").suffix.lower()
    chosen = format
    if chosen == "auto":
        chosen = {".csv": "csv", ".tsv": "tsv", ".json": "json",
                  ".jsonl": "jsonl", ".ndjson": "jsonl"}.get(suffix, "auto")
    if chosen == "auto":
        if text[0] in '[{"':
            try:
                json.loads(text)
                chosen = "json"
            except json.JSONDecodeError:
                chosen = "jsonl"
        else:
            # Recognized headers distinguish CSV from URLs containing commas.
            first = next((line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")), "")
            delimiter = "\t" if "\t" in first else ","
            fields = next(csv.reader([first], delimiter=delimiter, strict=True), [])
            chosen = ("tsv" if delimiter == "\t" else "csv") if has_target_column(fields) else "text"
    rows, assets = [], None
    if chosen in ("csv", "tsv"):
        delimiter = "\t" if chosen == "tsv" else ","
        reader = csv.reader(io.StringIO(text), delimiter=delimiter, strict=True)
        first = next(reader, [])
        if has_target_column(first):
            assets = parse_csv(text.encode("utf-8"), delimiter)
        else:
            # Headerless delimited lists are accepted only as one target per row.
            values = [row for row in [first] + list(reader) if row and any(cell.strip() for cell in row)]
            if len(values) > MAX_TARGETS:
                raise ValueError("Target input contains over 3000 entries")
            if any(len(row) != 1 for row in values if row):
                raise ValueError("Use a url/target header for multi-column CSV/TSV files")
            rows = text_rows("\n".join(row[0] for row in values if row))
    elif chosen == "json":
        try:
            rows = json_rows(json.loads(text))
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON target file") from exc
    elif chosen == "jsonl":
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid JSONL on line " + str(number)) from exc
            if not isinstance(item, (str, dict)):
                raise ValueError("Each JSONL line must be one URL string or target object")
            rows.extend(json_rows(item))
            if len(rows) > MAX_TARGETS:
                raise ValueError("Target input contains over 3000 entries")
    else:
        rows = text_rows(text)
        chosen = "text"
    if assets is None:
        assets = [asset_from_row(row, index) for index, row in enumerate(rows)]
        assets = [asset for asset in assets if asset is not None]
    if not assets:
        raise ValueError("No targets found")
    unique, seen, duplicates = [], set(), 0
    for asset in assets:
        key = target_key(asset)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(asset)
    return {"format": chosen, "assets": unique, "duplicates": duplicates}


def parse_targets(content, filename="", format="auto"):
    try:
        return _parse_targets(content, filename, format)
    except csv.Error as exc:
        raise ValueError("Malformed CSV/TSV target file") from exc
    except RecursionError as exc:
        raise ValueError("Target JSON nesting is too deep") from exc
