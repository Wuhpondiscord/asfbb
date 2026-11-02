"""Opt-in anonymous GET-only IDOR-Forge comparison adapter for HF."""
import json
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .module_inputs import ModuleInputs
from .pipeline import execute


async def run(url, host, agent, delay, inputs=None):
    inputs = inputs or ModuleInputs()
    base = {"source": "idor-forge", "target": url, "alerts": []}
    if not (inputs.idor_path and inputs.idor_baseline and inputs.idor_values):
        return {**base, "status": "skipped", "reason": "Requires an explicit same-origin path, query parameter, baseline ID and up to three reference IDs",
                "output": "IDOR-Forge skipped: comparison inputs missing"}
    if not any(v != inputs.idor_baseline for v in inputs.idor_values):
        return {**base, "status": "skipped", "reason": "Reference IDs must include a value different from the baseline",
                "output": "IDOR-Forge skipped: no distinct comparison values"}
    with tempfile.TemporaryDirectory(prefix="asfb-idor-forge-") as tmp:
        path = Path(tmp) / "inputs.json"
        path.write_text(json.dumps({"target": url, "host": host, "agent": agent, "delay": delay,
                                    "inputs": {key: value for key, value in inputs.model_dump().items()
                                               if key.startswith("idor_")}}), encoding="utf-8")
        rows, status = await execute(["/opt/idor-forge-venv/bin/python",
                                      "/app/app/idor_runner.py", str(path)], 55)
    report = None
    for row in rows:
        try:
            item = json.loads(row)
            if isinstance(item, dict) and item.get("profile") == "idor-forge-get-comparison":
                report = item
        except (ValueError, TypeError):
            pass
    if report is None:
        return {**base, "status": status if status in ("timeout", "unavailable") else "failed",
                "reason": "No bounded IDOR-Forge report was produced",
                "output": "IDOR-Forge did not produce a comparison report"}
    state = report.get("status")
    if state not in ("completed", "skipped", "partial", "failed"):
        state = "failed"
    if status in ("timeout", "unavailable", "failed"):
        state = status
    comparisons = []
    raw_comparisons = report.get("comparisons", [])
    for item in raw_comparisons[:3] if isinstance(raw_comparisons, list) else []:
        if not isinstance(item, dict):
            continue
        metrics = item.get("similarity", {})
        if not isinstance(metrics, dict):
            metrics = {}
        comparisons.append({"index": len(comparisons) + 1,
                            "http_status": item.get("http_status") if isinstance(item.get("http_status"), int) else 0,
                            "candidate": item.get("candidate") is True,
                            "similarity": {key: max(0.0, min(1.0, metrics[key]))
                                           for key in ("text_similarity", "structure_similarity", "content_similarity")
                                           if isinstance(metrics.get(key), (int, float))}})
    parts = urlsplit(url)
    target = parts._replace(path=inputs.idor_path, query="", fragment="").geturl()
    candidates = sum(1 for item in comparisons if isinstance(item, dict) and item.get("candidate") is True)
    alerts = []
    if candidates:
        alerts.append({"source": "idor-forge", "name": "IDOR-Forge: object-reference response comparison candidate",
                       "url": target, "risk": "Informational", "confidence": "Low",
                       "rule_id": "idor-forge-get-comparison",
                       "description": str(candidates) + " reference comparisons matched upstream similarity heuristics. "
                       "This anonymous GET profile cannot establish object ownership or missing authorization. "
                       "Verify with two authorized test accounts before reporting. Values and response bodies are omitted."})
    reason = str(report.get("reason") or "")[:250]
    return {**base, "status": "findings" if state == "completed" and candidates else state,
            "alerts": alerts, "reason": reason, "requests": int(report.get("requests", 0)),
            "comparisons": comparisons,
            "output": json.dumps({"profile": "anonymous GET-only; manual authorization review required",
                                  "requests": report.get("requests", 0), "comparisons": comparisons})}
