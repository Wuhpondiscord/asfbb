"""Evidence-led, bounded URL checks and private artifact handoffs inside HF."""
import asyncio
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from . import request_policy as policy
from .scope import public_host

VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$")
NPM = {"jquery": "jquery", "bootstrap": "bootstrap", "angular": "angular", "angularjs": "angular",
       "react": "react", "react-dom": "react-dom", "lodash": "lodash", "underscore": "underscore",
       "backbone": "backbone", "moment": "moment", "handlebars": "handlebars", "vue": "vue"}


def kind(url, content):
    content = content.lower()
    if "html" in content:
        return "html"
    if "javascript" in content or urlsplit(url).path.lower().endswith((".js", ".mjs")):
        return "javascript"
    if "json" in content or urlsplit(url).path.lower().endswith(".json"):
        return "json"
    return "other"


class Links(HTMLParser):
    def __init__(self, url):
        super().__init__()
        self.url, self.urls = url, []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        value = attrs.get("src") if tag == "script" else attrs.get("href") if tag in ("a", "link") else None
        if value:
            self.urls.append(urljoin(self.url, value))


class Flow:
    def __init__(self, primary, maximum=10):
        self.primary = primary
        self.maximum = max(1, min(100, int(maximum)))
        self.records, self.samples, self.components, self.suggestions = {}, {}, {}, []
        self.pacer = policy.Pacer()
        self.limit_reached = False
        self.api_schema = False

    def add(self, url, source):
        try:
            if not isinstance(url, str) or len(url) > 2000 or any(ord(c) < 32 for c in url):
                return
            url = urlsplit(url)._replace(fragment="").geturl()
            if not policy.allows(url) or policy.origin(url) != policy.origin(self.primary):
                return
        except (ValueError, TypeError):
            return
        if len(self.records) >= 2000:
            self.limit_reached = True
            return
        record = self.records.setdefault(url, {"url": url, "sources": [], "checked": False, "kind": "unclassified"})
        if source not in record["sources"]:
            record["sources"].append(source)

    def suggestion(self, kind, url, evidence, inputs):
        if any(x["kind"] == kind and x["url"] == url for x in self.suggestions) or len(self.suggestions) >= 20:
            return
        self.suggestions.append({"kind": kind, "url": url, "evidence": evidence,
                                 "review_required": True, "inputs": inputs})

    def schema(self, doc, schema):
        for _ in range(4):
            if not isinstance(schema, dict):
                return {}
            ref = schema.get("$ref")
            if not ref:
                return schema
            if not isinstance(ref, str) or not ref.startswith("#/"):
                return {}
            current = doc
            for key in ref[2:].split("/"):
                current = current.get(key.replace("~1", "/").replace("~0", "~"), {}) if isinstance(current, dict) else {}
            schema = current
        return {}

    def inspect(self, url, content_type, body):
        category = kind(url, content_type)
        if category == "html":
            parser = Links(url); parser.feed(body.decode("utf-8", "replace"))
            for candidate in parser.urls[:100]:
                self.add(candidate, "html-reference")
        elif category == "javascript":
            text = body.decode("utf-8", "replace")
            # Literal GET/import references only; no JavaScript execution or evaluation.
            for match in re.finditer(r"(?:fetch|import|axios\.get)\s*\(\s*['\"]([^'\"\r\n]{1,500})['\"]\s*\)", text):
                self.add(urljoin(url, match.group(1)), "javascript-literal")
            for match in re.finditer(r"(?:from|import)\s+['\"]([^'\"\r\n]{1,500}\.(?:m?js))['\"]", text):
                self.add(urljoin(url, match.group(1)), "javascript-import")
        elif category == "json":
            try:
                doc = json.loads(body)
            except ValueError:
                return
            if not isinstance(doc, dict):
                return
            if isinstance(doc.get("openapi"), str) or doc.get("swagger") == "2.0":
                paths = doc.get("paths")
                if not isinstance(paths, dict):
                    return
                self.api_schema = True
                for path, operations in list(paths.items())[:100]:
                    if not isinstance(path, str) or not path.startswith("/") or len(path) > 250 or any(c in path for c in "{}?#\\\\") or not isinstance(operations, dict):
                        continue
                    target = urljoin(url, path)
                    if not policy.allows(target):
                        continue
                    if "get" in operations:
                        self.add(target, "openapi-get-operation")
                    op = operations.get("post")
                    if not isinstance(op, dict):
                        continue
                    def obj(value):
                        return value if isinstance(value, dict) else {}
                    request = self.schema(doc, obj(obj(obj(op.get("requestBody")).get("content")).get("application/json")).get("schema", {}))
                    response = self.schema(doc, obj(obj(obj(obj(op.get("responses")).get("200")).get("content")).get("application/json")).get("schema", {}))
                    fields, outputs = request.get("properties", {}), response.get("properties", {})
                    if not isinstance(fields, dict) or not isinstance(outputs, dict):
                        continue
                    prompt = next((key for key in ("prompt", "input") if isinstance(fields.get(key), dict) and fields[key].get("type") == "string"), None)
                    result = next((key for key in ("response", "text", "completion") if isinstance(outputs.get(key), dict) and outputs[key].get("type") == "string"), None)
                    label = path + " " + str(op.get("operationId", "")) + " " + str(op.get("tags", []))
                    if prompt and result and re.search(r"llm|complet|generat|chat", label, re.I):
                        self.suggestion("garak", target, "OpenAPI POST operation with explicit string prompt and response schemas; model behavior still needs review",
                                        {"llm_path": path, "prompt_field": prompt, "response_field": result})
                    name = next((key for key, value in fields.items() if isinstance(value, dict) and value.get("type") == "string" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,49}", key)), None)
                    success = next((key for key, value in outputs.items() if isinstance(value, dict) and value.get("type") == "boolean" and key in ("success", "accepted", "found")), None)
                    if name and success:
                        base = {"target_origin": urlsplit(target)._replace(path="", query="", fragment="").geturl(),
                                "request": {"path": path, "method": "POST", "json_body": {name: "REVIEW_KNOWN_BASELINE"}},
                                "field": name, "success": {"pointer": "/" + success, "equals": True}}
                        if re.search(r"search|lookup|filter|query", label, re.I):
                            self.suggestion("nosql", target, "Documented JSON string input and boolean output; working baseline and API semantics are unconfirmed", {"nosql": base})
                        if re.search(r"claim|redeem|coupon|reserve", label, re.I):
                            race = {**base, "control_value": "REVIEW_FRESH_CONTROL", "parallel_value": "REVIEW_FRESH_PARALLEL"}
                            self.suggestion("race-replay", target, "Documented state-changing operation; separate authorized fresh fixtures are required", {"race": race})

    async def check_new(self, agent, count=5):
        remaining = self.maximum - sum(item["checked"] for item in self.records.values())
        if remaining <= 0:
            self.limit_reached = True
            return []
        pending = [item for item in self.records.values() if not item["checked"]]
        pending.sort(key=lambda item: (0 if item["url"] == self.primary else 1,
                                      0 if urlsplit(item["url"]).path.lower().endswith((".js", ".mjs", ".json")) else 1))
        checked = []
        async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
            for record in pending[:min(remaining, count)]:
                url = record["url"]
                if not policy.allows(url):
                    continue
                record["checked"] = True
                await self.pacer.await_turn()
                try:
                    public_host(urlsplit(url).hostname)
                    async with client.stream("GET", url, headers=policy.headers({"User-Agent": agent})) as response:
                        record.update(status_code=response.status_code,
                                      content_type=response.headers.get("content-type", "")[:120])
                        data, truncated = bytearray(), False
                        async for chunk in response.aiter_bytes(16384):
                            if len(data) + len(chunk) > 262144:
                                truncated = True
                                break
                            data.extend(chunk)
                        record["kind"] = kind(url, record["content_type"])
                        record["sample_limited"] = truncated
                        if response.status_code == 200 and not truncated:
                            self.samples[url] = (bytes(data), record["content_type"], url)
                            self.inspect(url, record["content_type"], bytes(data))
                    if record["status_code"] in (429,) or record["status_code"] >= 500:
                        break
                except (httpx.HTTPError, ValueError, OSError):
                    record["check_error"] = "HTTP check incomplete"
                checked.append(dict(record))
        return checked

    def ingest_components(self, components):
        for item in components or []:
            name, version = item.get("component"), str(item.get("version") or "")
            package = NPM.get(str(name).lower())
            if package and VERSION.fullmatch(version):
                self.components[(package, version)] = {"type": "library", "name": package, "version": version,
                    "purl": "pkg:npm/" + package + "@" + version,
                    "properties": [{"name": "asfb:evidence", "value": "Retire.js browser-library/version fingerprint; mapping requires manual verification"}]}

    def inputs_for(self, module, supplied):
        updates, provenance = {}, {}
        if module in ("semgrep", "trufflehog") and not supplied.source_text:
            scripts = [(url, row[0]) for url, row in self.samples.items() if kind(url, row[1]) == "javascript" and len(row[0]) <= 200000]
            if scripts:
                url, data = max(scripts, key=lambda row: len(row[1]))
                updates.update(source_text=data.decode("utf-8", "replace"), sast_language="javascript", trufflehog_verify=False)
                provenance = {"source": "observed-javascript", "url": url, "credential_verification": False}
        if module in ("depscan", "trivy", "osv-scanner") and not supplied.sbom_text and self.components:
            updates["sbom_text"] = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5",
                                              "version": 1, "components": list(self.components.values())[:100]})
            provenance = {"source": "retirejs-fingerprint", "components": len(self.components), "verification": "unverified package mapping"}
        if module == "kiterunner" and not supplied.api_target and (self.api_schema or any(
                row.get("status_code") == 200 and row.get("kind") == "json" and "/api/" in urlsplit(row["url"]).path
                for row in self.records.values())):
            updates["api_target"] = True
            provenance = {"source": "observed-json-api"}
        return (supplied.model_copy(update=updates) if updates else supplied), provenance

    def public(self):
        return {"resources": list(self.records.values())[:2000], "checked": sum(r["checked"] for r in self.records.values()),
                "check_limit": self.maximum, "limit_reached": self.limit_reached,
                "suggestions": self.suggestions, "dependency_candidates": len(self.components)}
