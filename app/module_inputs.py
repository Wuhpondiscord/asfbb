"""In-memory per-job artifact and endpoint inputs; never execute supplied content."""
import json
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator


def clean_sbom(text):
    if not text.strip():
        return ""
    try:
        source = json.loads(text)
    except ValueError as exc:
        raise ValueError("SBOM must be CycloneDX JSON") from exc
    if not isinstance(source, dict) or source.get("bomFormat") != "CycloneDX":
        raise ValueError("Only CycloneDX JSON SBOMs are supported")
    items = source.get("components", [])
    if not isinstance(items, list) or not 1 <= len(items) <= 300:
        raise ValueError("SBOM requires 1-300 application components")
    cleaned = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Invalid SBOM component")
        purl, name, version = item.get("purl"), item.get("name"), item.get("version")
        if not all(isinstance(v, str) and 0 < len(v) <= 500 for v in (purl, name, version)):
            raise ValueError("Each SBOM component requires bounded name, version and purl")
        if not purl.startswith("pkg:") or any(c in purl for c in "\r\n\x00"):
            raise ValueError("Invalid component purl")
        if purl in seen:
            continue
        seen.add(purl)
        cleaned.append({"type": "library", "name": name, "version": version,
                        "purl": purl, "bom-ref": purl})
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                       "components": cleaned}, separators=(",", ":"))


class ModuleInputs(BaseModel):
    source_text: str = Field(default="", max_length=200000)
    sbom_text: str = Field(default="", max_length=1000000)
    api_target: bool = False
    llm_path: str = Field(default="", max_length=250)
    prompt_field: str = Field(default="prompt", max_length=50)
    response_field: str = Field(default="response", max_length=50)

    @field_validator("sbom_text")
    @classmethod
    def validate_sbom(cls, text):
        return clean_sbom(text)

    @field_validator("llm_path")
    @classmethod
    def validate_llm_path(cls, path):
        if not path:
            return path
        parts = urlsplit(path)
        if (not path.startswith("/") or path.startswith("//") or parts.scheme or parts.netloc
                or parts.query or parts.fragment or ".." in path or
                any(c in path for c in "\r\n\x00\\")):
            raise ValueError("LLM endpoint must be a same-origin path without query/fragment")
        return path

    @field_validator("prompt_field", "response_field")
    @classmethod
    def validate_field(cls, value):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,49}", value):
            raise ValueError("LLM JSON fields must be simple top-level property names")
        return value

    def public_summary(self):
        return {"source_bytes": len(self.source_text.encode("utf-8")),
                "sbom_components": len(json.loads(self.sbom_text)["components"]) if self.sbom_text else 0,
                "api_target": self.api_target, "llm_path": self.llm_path,
                "prompt_field": self.prompt_field, "response_field": self.response_field}
