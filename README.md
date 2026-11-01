---
title: ASFB Bug Bounty Scanner
emoji: 🔎
sdk: docker
app_port: 7860
---

# ASFB — Bug bounty scope and ZAP workspace

A self-hosted, API-driven workbench for importing HackerOne scope exports, prioritizing web targets, configuring testing identities, and running **rate-limited passive checks** using the standard OWASP ZAP daemon.

> This is an initial working release, not a comprehensive automated vulnerability detector. It does not prove IDORs or RSA/JWT weaknesses, run Nuclei, or autonomously scan wildcards. Those are future modules.

## Features
- Upload CSV scope exports; recognizes common HackerOne column names (asset name/identifier, type, bounty, severity, resolved reports, last update, instructions).
- API and web UI filtering by reward eligibility, severity, scanner compatibility, text and report volume.
- Preserves non-web assets and wildcard entries for manual review instead of automatically treating them as HTTP scan targets.
- Program-specific scan-policy approval, exact-host scope enforcement, SSRF checks, URL/path exclusions, and small default request budgets.
- Request profiles with custom User-Agent and account-specific cookies/headers. Credentials exist **in process memory only** and are not serialized to files, databases or reports.
- Sequential background jobs, stop/status endpoints, and ZAP passive alerts.
- API-key authentication on the backend; API docs at `/docs`.

## Deployment
Create a **private** Hugging Face Docker Space from this repository (or run Docker locally). Set secrets:
- `ASFB_API_KEY`: a long random API key **required on startup**.
- `ZAP_API_KEY`: a separate random API key **required on startup**.

Configure the frontend by opening the Space, entering `ASFB_API_KEY` into the UI. The browser keeps the key only in memory until the page is reloaded. Do not distribute this key publicly.

```bash
docker build -t asfbb .
docker run --rm -p 7860:7860 -e ASFB_API_KEY=change-me-long-random-value -e ZAP_API_KEY=another-long-random-value asfbb
```

A free Hugging Face Space may sleep and its working disk is ephemeral. This release keeps all data in memory. Do not rely on it for durable findings/history. For public/multiuser deployment, add per-user authentication, a durable encrypted database and stricter queue isolation first.

## Workflow
1. Import a HackerOne CSV via the dashboard or `POST /api/import` multipart upload.
2. Review the parsed assets, their eligibility and descriptions.
3. Add a policy acknowledgement and verify the program permits the proposed automation.
4. Choose an individual, unambiguous domain/URL row. Wildcards, category/group rows, mobile/source-code assets are not auto-scannable.
5. Configure an optional account identity in the UI. Login credentials are not required for unauthenticated scans.
6. Start a passive ZAP scan. The job makes up to the configured number of scoped GET requests; no active scanner payloads are sent.
7. Review the findings and investigate manually.

### API examples
```bash
curl -H "X-ASFB-Key: $ASFB_API_KEY" -F "file=@scope.csv" http://localhost:7860/api/import
curl -H "X-ASFB-Key: $ASFB_API_KEY" http://localhost:7860/api/assets
```

`POST /api/scans` example (replace asset_id with an imported ID):
```json
{
  "asset_id": "ASSET_ID",
  "policy_confirmed": true,
  "user_agent": "ASFB-research/0.1",
  "max_requests": 3,
  "delay_seconds": 1.5,
  "account_id": null
}
```

`POST /api/accounts` accepts `{ "name": "A", "host": "example.org", "cookie": "session=...", "headers": {"X-Testing": "yes"} }`. Accounts are stored only until the process restarts, not included in API responses, and restricted to their exact host.

## Limitations and safety
- Imported scope does not override a program's rules. Scope tables do not consistently include automation prohibitions; check them manually before confirming.
- A listed source-code path or internal-service wildcard is not interpreted as authorization for external web scans.
- DNS is checked before a job; network changes, redirects, proxy behavior and complex authorization still require hardened egress controls. The scan fetcher disallows redirects and rechecks resolved addresses. Deploy on isolated infrastructure for high-assurance SSRF control.
- This MVP uses one backend, one ZAP daemon, one active job at a time; it is not a public SaaS or multi-tenant service.
- Only HTTP(S) ports 80, 443, 8080 are supported by the default target validator (matching common HF egress ports).
- Authentication profiles can become stale; do not use production customer credentials.
- Findings from passive rules are signals, not verified vulnerabilities.
- The ZAP upstream base image is tagged `stable`; pin it to a digest before production.

## Tests
```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

## Next milestones
OpenAPI discovery, per-program policy manifests, scoped crawling, differential two-account IDOR replay, verified JWT rule pack, vulnerability triage, persistence and scan-history diffing.

## v0.2 — additional features
- **Batch queue**: `POST /api/scans/batch` (up to 40 individually scoped web assets per request). Jobs remain sequential and require manual confirmation of program policy.
- **Persistence**: non-secret imported assets and job status/alerts are stored in SQLite (`ASFB_DB_PATH`, default `/app/data/asfb.sqlite3`). Attach persistent storage if desired. Account cookies are never saved.
- **Offline JWT review**: `POST /api/tools/jwt/inspect` accepts a token and returns only header/claim field names plus heuristic warnings; it does not verify signature validity or access tokens to any server.
- **Automatic Hugging Face deployment**: GitHub Action deploys `main` when `HF_TOKEN` is a GitHub **Actions secret** and `HF_SPACE_REPO` is a GitHub **Actions variable** (e.g. `owner/space`). The `GH_Token` secret in Hugging Face is not required and should not be used for raw credential logs.

**Public Space**: The landing page can be viewed without authentication. Operator actions retain `ASFB_API_KEY`: removing access control from an internet-exposed scanner would allow strangers to control scans and read your account profiles. The internal `ZAP_API_KEY` remains necessary.

Still pending: cross-account IDOR testing, live JWT signature bypass testing, authenticated browser crawling, Nuclei integration, program-policy extraction, and full isolation for a public multiuser service.

## No manual API keys
The dashboard no longer requests an ASFB API key. The startup script generates an internal ZAP API key automatically. **Warning:** this build has no public API authentication; do not use it on a publicly accessible Space with real credentials or sensitive targets. Public anonymous scanning must be protected by appropriate abuse prevention and per-user isolation before production use.

## v0.3: opt-in discovery pipeline

The Space Docker image includes pinned ProjectDiscovery Nuclei v3.11.1 and Katana v1.8.0 binaries. Per scan choose **ZAP passive**, **Katana**, **Nuclei**, or a combination. ZAP remains on by default. These modules are not equivalent to passive analysis: Katana and Nuclei send additional traffic.

- **Katana:** standard non-headless crawler, depth 1, exact-host scoping, one request/second, one worker, up to 30 seconds, up to 100 same-host discovered URLs returned per job. No form auto-filling or headless browser.
- **Nuclei:** technology-detection templates only (`-tags tech`), one request/second, one worker, up to 90 seconds, 100 findings per job. Nuclei template updates may require network access on first run. This is not a general vulnerability/active-scan pipeline.
- **Results:** findings from Nuclei are labeled `source: nuclei`; Katana endpoints and per-stage status are included in each job's JSON.
- **Batch scans:** preserve the module selection for each of the up to 40 jobs per batch. These scans run sequentially and are unauthenticated; configured account cookies are passed only to the original single-target ZAP stage, not the new tools.

**Important**: Confirm the target program explicitly permits automated crawling and template-based requests. The project remains an experimental public Space and does not independently prove user authorization or reliably prevent DNS-rebinding/egress abuse. Do not enable unrestricted scanning against targets that have not authorized these activities. Scan detections are preliminary and require manual verification.

## Configurable pipeline (GAU and HTTPX)

ASFB additionally includes GAU v2.2.4 for archive-based URL discovery and ProjectDiscovery HTTPX v1.12.0 for limited HTTP metadata probing. Each module is opt-in. Edit the comma-separated stage order in Scan settings to rearrange selected modules; the server executes them sequentially. GAU and Katana collect exact-host URLs with deduplication. HTTPX currently checks only the first eligible URL (the primary target), not every discovered path, to cap traffic. ZAP and Nuclei likewise operate on the primary target; discovered URL reuse is not implied.

The app is not safe for unrestricted public scanning. Authorization is self-asserted, and per-module rate limits are not a global cross-user rate limiter. Large batches should be restricted to explicitly authorized targets and conservative program-specific limits.
