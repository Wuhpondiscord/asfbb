---
title: ASFB Bug Bounty Scanner
emoji: 🔎
sdk: docker
app_port: 7860
---

## Optional TruffleHog verification

In **Settings → Module inputs**, supply source text and select **Verify found credentials I own or am authorized to test**. Select TruffleHog in the pipeline as usual. Verification is off by default, is not enabled by Full pipeline, and resets after a successful scan submission. No separate provider API key is required: verification authenticates with the detected credential from the HF worker to its provider.

All detector types still run in a detection-only first pass. A second pass checks up to 10 distinct candidates within a shared 30-second budget (one worker, up to 12 seconds per candidate). The pinned native verifiers are restricted to AWS access-key pairs, GitHub, Slack, Hugging Face and OpenAI. Each candidate gets its own temporary input to prevent cross-pairing; arbitrary-host/database/private-key verifiers, custom verifier URLs, account/resource analysis and known AWS canaries are excluded. AWS canary verification uses a different upstream operation and remains detection-only. Other types and candidates outside the budget remain visible.

Findings are grouped by detector and result: **Verified** (provider authentication confirmed; high confidence), **Unverified** (TruffleHog did not confirm validity), **Inconclusive** (provider/transport error, missing output or timeout), or **Detection-only** (not attempted). Unverified does not prove a secret is invalid. Inconclusive or exhausted-budget verification marks the stage partial. Job logs include only verification counts and budget diagnostics; detection findings survive verification failures.

Secret values, source snippets, identity metadata and provider error text are never returned in results or logs. Source and candidate files are temporary on HF and removed after use. API clients opt in with `options.inputs.trufflehog_verify: true` alongside `source_text`. Only a boolean, source byte count and sanitized result counts are persisted.

Implementation follows the [pinned TruffleHog documentation](https://github.com/trufflesecurity/trufflehog/blob/v3.99.7/README.md) and its provider/JSON output implementations. GitHub-hosted tests mock verification responses; the installed-binary smoke remains explicitly `--no-verification` and does not use real credentials.

## Direct URLs and target-list imports

Use **Scope & scanning → Import targets** to paste one URL, paste a list or upload a file. A question-mark button shows format examples on hover/focus and can be pinned with a click/tap. Escape or an outside click closes it.

Supported formats are UTF-8 TXT URL lists (one target per line), standard CSV/TSV, HackerOne CSV exports, JSON strings/arrays/objects and JSONL/NDJSON. UTF-16 files with a BOM are also accepted. Common target headers include url, uri, target, host, hostname, domain, Asset name and asset_identifier. JSON may use a targets/urls/assets/scope/data wrapper. Plain hostnames use HTTPS. TXT lists ignore blank lines and # comment lines.

Examples:

```text
https://example.org/search?q=test
https://api.example.org/v1/
example.net
```

```csv
url,description
https://example.org/,Main app
```

```json
{"targets":["https://example.org/",{"url":"https://api.example.org/"}]}
```

```jsonl
{"url":"https://example.org/"}
{"url":"https://api.example.org/"}
```

Imports merge into the current browser session and reuse duplicate entries. URL query values are retained; fragments are ignored for requests and duplicate matching. Missing bounty/severity metadata stays unknown or ineligible rather than being assumed. Non-web scope entries from structured exports remain available for manual review.

The importer accepts up to 2 MB and 3,000 targets per session, rejects credential-bearing URLs, and never fetches targets or starts scans. The optional **Select imported web targets** checkbox selects entries for review; existing policy and active-test confirmations still apply when queuing. Parsing malformed input is atomic: no partial batch is added. Public-host checks and the existing supported-port limits remain enforced at scan time.

API: `POST /api/import/text` accepts `{"text":"https://example.org/","format":"auto"}`. The existing multipart `POST /api/import` supports filenames/content auto-detection and an optional `?format=text|csv|tsv|json|jsonl` override.

## Guided pipelines and coverage profiles

The dashboard now defaults to **Guided** ordering and the **Balanced** coverage budget. Under Settings → Pipeline order & coverage, switch to **Manual** to preserve the exact comma-separated order. Guided mode reorders only enabled modules: URL discovery runs before URL consumers, HTTPX metadata is available before applicable page reviews, and Arjun runs before Dalfox/SQLmap. Missing modules are never automatically enabled. The preview and each job's stored plan show requested/effective order, handoffs and manual-order warnings.

The extended-reuse checkbox passes a bounded, exact-origin archive URL sample into Katana, prioritizes observed successful responses for ZAP/Nuclei/Arjun, and selects observed HTML pages for applicable web modules. Katana keeps one worker, one request/second, explicit origin scope, and at most 1–3 seeds depending on profile. New hostnames from Amass remain inventory; they do not become authorized scan targets automatically. Manual pipelines can still reuse data produced earlier in their chosen order.

| Coverage | Retire.js sample | Dalfox payloads / scan / process cap | Amass internal / process cap |
| --- | --- | --- | --- |
| Previous limits | 4 files, 512 KiB each | 30 / 30s / 65s | 1 minute / 65s |
| Quick | 4 files, 512 KiB each | 8 / 30s / 60s | 1 minute / 65s |
| Balanced | 8 files, 2 MiB each | 12 / 60s / 90s | 1 minute / 95s |
| Thorough | 16 files, 4 MiB each | 30 / 120s / 150s | 2 minutes / 150s |

Retire.js balances inline and external samples, tries later candidates after failed or oversized bundles, and records eligible/sampled/omitted counts separately from the scanner engine status. Sampling also has overall time and attempt budgets. A completed engine with excluded resources still reports partial coverage. Larger profiles increase time and requests; they do not guarantee that external providers or targets will answer. No timeout or sampling gap is converted into a clean result.

The plan endpoint (`POST /api/pipeline/plan`) previews without queuing or scanning. New options are `order_mode`, `reuse_discovery`, and `coverage_profile`. Existing API clients default to manual order, original handoffs and previous budgets unless they opt in. Dashboard choices are explicitly included in newly queued requests.

## Current remote workflow and dashboard

The queue defaults to one running target per browser session. Select 2 or 3 concurrent targets under Scope & scanning or Settings → Pipeline & modules for new jobs. The Space has a global cap of three jobs; existing jobs keep their queued limit. Jobs from the same session respect the smallest limit among active jobs. Distinct hostnames can overlap, while endpoints on the same hostname are serialized across sessions so per-host module request rates are not multiplied. Each target’s modules remain ordered so discovery results are available to later stages.

The idle dispatcher preserves the first queued target instead of rotating it behind a newly submitted batch. A busy hostname can still be bypassed to start an unrelated host within the configured cap.

WPScan preflight and Retire.js page/script sampling permit up to two redirects on the exact same origin, with public-DNS revalidation on every hop, request pacing, byte caps and one deadline per sample. A different hostname, scheme, port or credential-bearing URL remains blocked, even if a redirect looks like a canonical www alias. Relative script paths resolve against the final sampled page.

When SQLmap is enabled and active testing is confirmed, it can reuse one already observed same-origin GET query or an Arjun-discovered GET parameter. Known query values are retained; a discovered parameter without a known value uses the existing research marker. No parameter names are invented. The profile tests one parameter with level/risk 1, boolean checks, one thread, a delay and process deadline; redirects are disabled and session/output files use a disposable per-job directory.

Dalfox incomplete reports retain their request counters and target status/error codes in log diagnostics; raw request/response bodies and raw target error messages are excluded. A process timeout remains a timeout. GAU uses an explicit keyless config and reports provider problems once in its summary. Amass retains its 65-second budget; provider timeouts remain degraded coverage, not a clean result.

Concurrency uses one async dispatcher and the existing separate scanner subprocesses, not extra API-server workers. ZAP’s daemon is gated across its entire reset/fetch/wait/alert-collection stage, with fresh daemon history per job. Dependency-cache stages are serialized to prevent overlapping database writes. Cancellation interrupts only the selected jobs and their process groups; shutdown waits for running jobs to stop. Queue and resource waits appear in logs and job details. Module deadlines and per-target limits are unchanged. Speedup depends on network delays, available HF resources and shared-stage waits.

Development for this deployment is remote-only. Changes are made with connected GitHub tools; GitHub-hosted Actions runs the checks and pushes a passing main branch to the HF Space. Do not follow older local setup/test examples on the owner's device.

The dashboard groups modules into a searchable library and separates pipeline settings, module inputs, Nuclei templates, and identity tools. Settings is always the final main tab. The scope view keeps target selection beside a compact queue panel with optional 1–3 concurrent targets. Jobs support target/ID, status and module filters, sorting, status dots, reduced-motion-aware animations, individual cancellation, and direct links to job-filtered logs. Findings retain their existing layout.

Logs support full-detail search, level/module/event/job/time filters, elapsed-time sorting, structured diagnostics, copy/export of filtered events, and shared pause/resume controls. They show the newest 2,000 events from the session's retained in-memory history; retention metadata makes this window explicit. Archive provider statuses and deadlines are included in stage diagnostics. Backend restarts clear session history.

### IDOR-Forge comparison profile

The HF image pins [IDOR-Forge's MIT-licensed core](https://github.com/errorfiathck/IDOR-Forge/tree/bc37cfc9143b40d7f91d1fa25753a22e908f4e84) and retains its license in /opt/idor-forge/LICENSE. The upstream response comparison and heuristic methods run in a separate environment. This is a limited anonymous GET comparison profile, not the full upstream CLI or GUI.

Select one asset, enable IDOR-Forge and provide a same-origin endpoint path, one query parameter, a baseline reference ID and up to three distinct reference IDs under Settings → Module inputs. Without applicable inputs it skips, including when all modules are enabled. It needs no API key. The profile permits at most four requests, no redirects, no retries, bounded response bodies, an overall deadline and public-host revalidation before each request. It stops on rate limits. No upstream random payload generation, login, POST/PUT/DELETE, evasion or reports run. Account profiles are not used by active modules.

Identical responses are not flagged. Similarity matches are informational, low-confidence review candidates: anonymous response differences cannot prove object ownership or broken authorization. Verify with two authorized test accounts before reporting. Reference values and response bodies are not returned in jobs or logs. The current profile does not implement authenticated differential two-account IDOR replay.

Regression tests, installed-engine offline smoke checks and a mocked-API Chromium dashboard check run only on GitHub. No live target scans are used for verification. UI review screenshots remain in the GitHub Actions artifact.


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
