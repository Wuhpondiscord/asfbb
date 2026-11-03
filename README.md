---
title: ASFB Bug Bounty Scanner
emoji: 🔎
sdk: docker
app_port: 7860
---

## Race replay and NoSQL HTTP review

Configure **Settings → Replay checks**, enable the desired module and select one asset. Blank profiles skip in Full pipeline. Both modules are keyless; optional test-account headers stay private to the job. Profiles are never saved in cookies/public job options and clear after queuing.

Race replay sends two sequential requests on a control fixture, then two best-effort overlapping requests on a distinct fresh fixture. Use disposable state: POST operations can have effects. Exactly one sequential success is required before the burst. An optional GET counter verifier requires fresh zero counters and exactly one control effect. A parallel counter overrun is a corroborated candidate; without verification, duplicate success responses are informational and may be idempotent acknowledgements. This is not HTTP/2 single-packet synchronization.

```json
{
  "request": {
    "path": "/api/test-claim",
    "method": "POST",
    "json_body": {
      "ticket": "placeholder"
    }
  },
  "field": "ticket",
  "control_value": "CONTROL_TEST_FIXTURE",
  "parallel_value": "RACE_TEST_FIXTURE",
  "success": {
    "pointer": "/accepted",
    "equals": true
  },
  "verification": {
    "request": {
      "path": "/api/test-state",
      "query": {
        "ticket": "placeholder"
      }
    },
    "field": "ticket",
    "pointer": "/accepted_count"
  }
}
```

NoSQL HTTP review uses six paced controls on one top-level query/JSON string field: baseline, negative scalar, inert object, equality-positive, equality-negative and not-equal. GET uses bracket parameters; POST uses JSON objects. Operator-dependent behavior is a candidate, not proof of a database/authentication bypass: documented filter APIs can intentionally support operators. No scripts, sleeps, regex payloads, enumeration, direct database connections or credential extraction.

```json
{
  "request": {
    "path": "/api/test-lookup",
    "method": "POST",
    "json_body": {
      "reference": "KNOWN_TEST_REFERENCE"
    }
  },
  "field": "reference",
  "success": {
    "pointer": "/found",
    "equals": true
  }
}
```

Request paths are same-origin paths without query/fragment. GET uses query; POST uses json_body. Success uses an RFC 6901 JSON pointer and an exact JSON scalar type. Raw headers, bodies, paths, fixture values, predicates and response content are redacted. Protected routing/framing headers and supplied operator-bearing baseline objects are rejected. Validation errors omit raw input/context.

Verified TLS, per-attempt public-DNS checks, fresh clients, no redirects/retries and a 64 KiB uncompressed response limit apply. One shared replay slot bounds HF load; only the two-request race burst overlaps. Race uses four attempts, or eight with verification; NoSQL uses six at most. Deadlines include pacing and cap at 330 seconds. Redirects, 429, 5xx, missing matchers/counters, stale fixtures and failed controls stop the profile. Reports checkpoint partial control results without private data.

API inputs: options.inputs.race and options.inputs.nosql. Configured replay jobs are not deduplicated and cannot target multiple assets. Existing cookies survive the additions; Manual order is exact and Guided mode places WAF context first. Deep network scanning is unchanged.

These project profiles use the existing HTTPX runtime, following [HTTPX async](https://www.python-httpx.org/async/), [OWASP NoSQL testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05.6-Testing_for_NoSQL_Injection/) and MongoDB [equality](https://www.mongodb.com/docs/manual/reference/operator/query/eq/)/[not-equal](https://www.mongodb.com/docs/manual/reference/operator/query/ne/) semantics. They are not the race-the-web/NoSQLMap executables. CI uses mocked transports, never live replay targets.

## Protocol and infrastructure batch

Six additional keyless modules are installed. They are off by default, included by **Enable all modules**, and participate in Guided or exact Manual pipeline ordering. New cookie entries use defaults without clearing old choices. The planner now accepts up to 64 module entries before registry/duplicate validation so the old 30-entry preview ceiling does not block future additions.

| Module | Inputs and behavior | Bounds / interpretation |
| --- | --- | --- |
| **graphw00f** | Explicit GraphQL path, or a same-origin HTTP URL whose path matches graphql/gql from prior discovery. Original archive query strings are discarded. Native engine fingerprints plus `__typename` and limited `__schema { queryType { name } }` metadata. | 64 paced HTTP attempts / 100s process cap. POST with GET fallback, memoized queries. Mutation, subscription and fragment probes are excluded; no schema reconstruction/application-data queries. Fingerprints and introspection are informational. |
| **Corsy** | Native active/passive CORS test order against the selected URL, an observed live page when extended reuse is on, or an explicit CORS path. | 12 header-only GETs / 40s process cap. No supplied account cookies/Authorization. Credential candidates require an exact foreign browser origin, exact ACAC=true and a successful response. Wildcard ACAO, malformed origins and anonymous reflection are not proven credential leaks. |
| **Takeover fingerprints** | Selected hostname's bounded CNAME chain, corroborated by a provider-specific NXDOMAIN condition or a literal provider HTTP fingerprint. Uses the pinned can-i-take-over-xyz data, not a claim/registration workflow. | At most one selected-origin GET / 35s cap, plus bounded DNS queries. Only upstream vulnerable/CI-passing entries with CNAME evidence are considered. No broad host sweep, provider HTTP fetch or service claim. Candidate claimability remains unverified. |
| **S3 bucket review** | Explicit standard AWS S3 REST bucket root, virtual-host or path style. Object URLs, signed/query URLs, website endpoints and non-S3 assets skip. | Two GETs / 30s cap: ListObjectsV2 with max-keys=0 and GetBucketAcl. No object download or write/delete tests. Public ACL grants are advertised permissions, not proof of effective write access; public access may be intentional. |
| **WebSocket review** | Explicit raw WebSocket path, or a matching /ws, /websocket or /socket path in scoped HTTP inventory. Uses the selected HTTP(S) origin for the RFC 6455 upgrade. | Two header-only handshakes / 25s cap. Verifies status, Upgrade/Connection and Sec-WebSocket-Accept, then compares an untrusted Origin. No frames, fuzzing, Socket.IO negotiation or authenticated hijack proof. |
| **Exposed VCS metadata** | Scoped directory URL ending in /, with no query string. Random missing-path control plus .git/HEAD, .git/config, .hg/requires and .svn/entries. | Five GETs / 35s cap. Structured signatures must differ from the missing-path control. No objects, source tree, repository reconstruction or history download. File contents, branch names, owner identifiers and credentials are not saved. |

Set optional GraphQL, CORS and WebSocket paths under **Settings → Module inputs → Protocol endpoints**. These paths are target-specific and remain unsaved. Blank GraphQL/WebSocket paths use only applicable discovered/selected paths; they do not spray common endpoint wordlists. S3 and VCS applicability is checked before launching a process. Guided mode runs URL producers before GraphQL/WebSocket reviews and can reuse HTTPX page metadata for Corsy. Confirmed GraphQL URLs join the same-origin inventory; DNS aliases never become HTTP scan scope.

Dangling DNS names are accepted when Takeover is selected. If a hostname remains unresolved, other stages skip and only the DNS takeover profile runs. Private/reserved destinations are still rejected, and every actual HTTP attempt revalidates the selected public hostname. DNS timeouts/NoAnswer are not interpreted as NXDOMAIN or claimability.

All six profiles use one request worker, the chosen delay (at least one second), verified TLS, public-DNS checks, no redirects and a 64 KiB body sample where needed. A 429 stops the profile without retries. Result files are checkpointed atomically so parsed observations survive process deadlines. Errors/budgets report partial or failed coverage rather than clean results. Native responses, errors, query payloads, ACL owner details and metadata file contents are redacted.

The bundled Semgrep pack now has **ten** rules, adding a JS/TS wildcard `postMessage(..., "*")` review. This flags code for message-sensitivity/target-origin review; it is not browser execution or comprehensive postMessage listener analysis.

Native engine pins: [graphw00f 4901f824140a](https://github.com/dolevf/graphw00f/tree/4901f824140a2da168876412593c213afbdd75fb), [Corsy 2985ae24da52](https://github.com/s0md3v/Corsy/tree/2985ae24da524ba6905d36bfbadca7fe71a9f199). Provider data: [can-i-take-over-xyz 5bd4e1283791](https://github.com/EdOverflow/can-i-take-over-xyz/tree/5bd4e12837911c8475486f1da922c9b9c706e632). Upstream source/data and licenses are retained in the remote image. Protocol checks follow the [GraphQL introspection model](https://graphql.org/learn/introspection/), [S3 REST API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html) and [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html).

CI uses mocked HTTP/DNS with the installed native graphw00f/Corsy engines and provider snapshot inside a network-disabled container. No live-target validation is performed.

The remaining heavier items—NoSQL authentication/injection workflows, race replay, broad network/default-login probing, full cloud posture auditing and repository reconstruction—still need separate request/identity/network/artifact profiles. They are not silently approximated by these checks. Gitleaks remains lower priority because native TruffleHog already provides secret detection/verification.

## New keyless analysis modules: WAFW00F and Semgrep

This batch adds two complementary modules from the scanner review:

- **WAFW00F 2.4.2:** native vendor-signature identification on the selected URL. Guided ordering places it before FFUF, Nuclei and the applicable web reviews. Detected vendors are infrastructure inventory, recorded on the job and in later stage diagnostics. They are informational observations, not vulnerabilities, and signatures can be hidden or spoofed. This profile does not change payload encoding, inject bypass headers or automatically expand scope.
- **Semgrep CE 1.183.0:** static analysis of one supplied Python, JavaScript or TypeScript file. Paste source in Settings → Module inputs and select its language. A URL, SBOM or empty source is not treated as source code. Ten bundled review rules cover Python shell=True, dynamic evaluation, pickle, unsafe YAML loaders and disabled TLS verification, plus JS/TS eval, Function construction, shell execution and dynamic innerHTML assignments. Results require human review of trust and reachability; this is not whole-repository or cross-file analysis.

Both module toggles are off by default. Enable them individually or through Full pipeline. Semgrep skips without source and an explicit supported language, including in Full pipeline. The language preference is stored in a new cookie namespace; pasted source stays unsaved. Existing module choices and pipeline orders are retained; new stages are appended on preference restoration. Manual pipelines preserve the user's exact selected order.

WAF requests use a dedicated transport: same origin, public-DNS revalidation per request, TLS verification, no redirects, no supplied account cookies, one worker, at most eight GETs, at least the chosen request delay, a 256 KiB response sample and a 45-second process cap. A 429 stops this profile without retries. Native vendor identification uses baseline and a bounded central signature probe; the SQL sleep component is replaced with a non-time-based signature. Generic blocking heuristics and OS command/XXE probes are outside this profile. Budget or response-size limits report partial coverage. Raw responses, headers and trigger URLs are omitted from saved reports.

Semgrep uses only the bundled rule file with metrics and version checks disabled, the CE engine, one worker, a 5-second per-rule timeout, a 512 MB engine budget and a 75-second process deadline. It never runs supplied code, project builds, autofixes, remote rule registries or uploads. An exclusive source-analysis slot bounds simultaneous native scans on HF. Findings contain fixed rule messages and line numbers; source snippets, metavariables, native diagnostics and raw file paths are redacted. Errors, skipped files and deadlines do not become clean scans.

Upstream behavior was checked against the [WAFW00F source/docs](https://github.com/EnableSecurity/wafw00f/tree/v2.4.2) and [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference). The container installs pinned native versions during remote builds. CI tests the installed engines with a mocked WAF response and Python/JS/TS source fixtures inside a container with networking disabled.

### Follow-up priorities from the scanner review

GraphQL endpoint-aware checks, dedicated CORS analysis and scoped takeover fingerprinting are the next most useful web additions. They should consume discovered endpoints and require explicit applicable targets rather than run blindly on every asset. Cloud posture tools need explicit cloud scope/identities; broad bucket enumeration should not infer authorization from a web hostname. Raw Nmap/RustScan, default-login probing, race replay and WebSocket fuzzing need separate network/protocol and replay controls before they fit this HF pipeline. Exposed .git reconstruction downloads source/history and needs a separate explicit artifact workflow; another secret detector overlaps the existing TruffleHog more than SAST does.

## Passive ZAP completion and saved browser preferences

ZAP passive rules run asynchronously after proxied responses arrive. The old 30 × 0.75-second polling window could stop after about 22.5 seconds while a large response was still being processed. The default passive wait budget is now **120 seconds**, adjustable from **15–300 seconds** in Settings → Pipeline & modules → Advanced discovery limits. API clients use `options.zap_wait_seconds`. A stable pending-record count with a task for the current host remains active work; zero pending records is still required for completion.

The wait budget also bounds ZAP queue API calls. The shared ZAP slot remains held while waiting and collecting alerts. Periodic `passive_queue_wait` events and the final stage diagnostics record elapsed time, pending count, task counts and deadline state. Exhausted budgets or a stalled backlog retain collected alerts and report partial coverage. This does not guarantee every large response finishes within five minutes.

Non-sensitive settings now save automatically in persistent, host-only preference cookies for one year: enabled modules, pipeline mode/order, coverage, concurrency, scanner limits (including passive wait), request settings, static view filters, bundled Nuclei choices and selected public community template paths. Blank report-count filters remain blank. The Settings page shows save/blocked-cookie status and offers **Restore default settings**, which clears only ASFB preference cookies.

Credentials/account identities, targets/search text, source and SBOM text, custom YAML/drafts, target-specific module inputs, JWTs, policy/active-test confirmations and credential-verification authorization are excluded. Preferences are browser/origin scoped; HTTPS uses Secure, SameSite=None and Partitioned cookies to support compatible embedded HF browsers. If browser policy blocks storage, the page explains that settings apply only to the current page.

### Extending preferences without resets

`app/preferences.js` exposes a registry-based `PreferenceStore`. Use stable namespace/key pairs and register only non-sensitive, validated fields. Each `asfb_pref_<namespace>` cookie has a `{v, values}` envelope containing overrides. Additive fields inherit current defaults without a schema bump; newly added modules/templates receive their own defaults. Restored pipeline orders append newly introduced module names. Existing choices and unknown keys remain intact.

For incompatible changes, supply a namespace schema version and sequential migration functions through the store's `schemas` option. A page with an older schema reads compatible values but will not overwrite a newer cookie. Validation rejects individual bad values without resetting other settings. Writes merge changed fields with the latest cookie, enforce a conservative per-cookie size budget, and report blocked/oversized storage without silently deleting prior data. Introduce separate namespaces for future large features. No cookies need to be cleared when adding a function.

## Optional TruffleHog verification

In **Settings → Module inputs**, supply source text and select **Verify found credentials I own or am authorized to test**. Select TruffleHog in the pipeline as usual. Verification is off by default, is not enabled by Full pipeline, and resets after a successful scan submission. No separate provider API key is required: native detectors use detected credentials to check the relevant service from the HF worker.

The adapter runs one native `trufflehog filesystem` scan against the **original source**, with verification enabled by omitting `--no-verification`. All built-in detector types are available: there is no application provider allowlist, per-credential source reconstruction, extra verification pass or 10-candidate cap. TruffleHog handles credential pairing, endpoint/context selection, verification support, caching, overlap decisions and provider requests. This can contact a database or host identified in source, rather than only one of five public providers. The app does not request separate resource/permission analysis or supply custom verifier URLs.

For HF, the process uses one worker and a 120-second overall deadline (40 seconds when verification is off). Deadlines retain parsed partial output and remain timeout results, never clean scans. No source archive extraction or binary scanning is enabled. Native detection/verification does not imply every credential can be verified successfully: detector support, service reachability and provider restrictions still apply.

Findings preserve native **Verified**, **Unverified** and **Inconclusive** (verification error) outcomes. Disabled or explicitly skipped verification is **Detection-only**. The pinned native JSON does not always distinguish a skipped/unsupported verifier from an unverified credential, so unverified must never be interpreted as invalid or as proof a request was made. Error results mark an otherwise completed stage partial. Logs report native mode, deadline and result counts; they do not invent a count of network verification attempts.

Secret values, source snippets, identity metadata and provider error text are never returned in results or logs. Source files are temporary on HF and removed after use. API clients opt in with `options.inputs.trufflehog_verify: true` alongside `source_text`. Only the setting, source byte count and sanitized result counts are persisted.

This uses the [pinned TruffleHog verification behavior](https://github.com/trufflesecurity/trufflehog/blob/v3.99.7/README.md). GitHub-hosted tests mock native verification output; the installed-binary smoke remains explicitly `--no-verification` and does not authenticate real credentials.

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
| Legacy API profile | 4 files, 512 KiB each; 4 MiB total | 30 / 30s / 120s | 1 minute / 180s |
| Quick | 4 files, 512 KiB each; 4 MiB total | 8 / 30s / 120s | 1 minute / 180s |
| Balanced | 16 files, 4 MiB each; 32 MiB total | 12 / 90s / 210s | 2 minutes / 300s |
| Thorough | 64 files, 8 MiB each; 64 MiB total | 30 / 300s / 420s | 5 minutes / 600s |

Amass consults external passive data sources even for one selected hostname. Initialization occurs before its native enumeration timer, and shutdown/output flushing can take additional time, so the process cap includes extra headroom. A recognized native `context deadline exceeded` exit is **Completed · early stop**, with incomplete inventory coverage explicitly recorded. A forced process timeout, crash or missing binary remains a failure/timeout; elapsed time alone never proves an intentional stop.

Scoped protocol profiles also report **Completed · early stop** (or Findings with the same label) when a valid report confirms a deliberate redirect, scope, request-count or response-sample stop. These outcomes do not degrade the overall job, but retain `early_stop`, `stop_reason` and `coverage_complete: false` in stage details/logs. Transport/DNS/engine failures, HTTP 429 and deadlines retain their incomplete status. Completion describes execution of the configured policy, not exhaustive coverage or absence of vulnerabilities.

Retire.js balances inline and external samples, tries later candidates after failed or oversized bundles, and records eligible/sampled/omitted counts separately from the scanner engine status. Sampling also has overall time and attempt budgets. Configured file/count/byte/time exclusions now report Completed (or Findings) with an early-stop label and explicit incomplete coverage. HTTP failures for current-page script references and actual engine errors retain partial/failed status. Missing inventory-only URLs (HTTP 404/410) are excluded from eligible live scripts and counted separately; no retries are added. Larger profiles increase time and requests; they do not guarantee that external providers or targets will answer. No timeout or sampling gap is converted into a clean result.

The plan endpoint (`POST /api/pipeline/plan`) previews without queuing or scanning. New options are `order_mode`, `reuse_discovery`, and `coverage_profile`. Existing API clients default to manual order, original handoffs and previous budgets unless they opt in. Dashboard choices are explicitly included in newly queued requests.

## Current remote workflow and dashboard

The queue defaults to one running target per browser session. Select 2 or 3 concurrent targets under Scope & scanning or Settings → Pipeline & modules for new jobs. The Space has a global cap of three jobs; existing jobs keep their queued limit. Jobs from the same session respect the smallest limit among active jobs. Distinct hostnames can overlap, while endpoints on the same hostname are serialized across sessions so per-host module request rates are not multiplied. Each target’s modules remain ordered so discovery results are available to later stages.

The idle dispatcher preserves the first queued target instead of rotating it behind a newly submitted batch. A busy hostname can still be bypassed to start an unrelated host within the configured cap.

WPScan preflight and Retire.js page/script sampling permit up to two redirects on the exact same origin, with public-DNS revalidation on every hop, request pacing, byte caps and one deadline per sample. A different hostname, scheme, port or credential-bearing URL remains blocked, even if a redirect looks like a canonical www alias. Relative script paths resolve against the final sampled page.

When SQLmap is enabled and active testing is confirmed, it can reuse one already observed same-origin GET query or an Arjun-discovered GET parameter. Known query values are retained; a discovered parameter without a known value uses the existing research marker. No parameter names are invented. The profile tests one parameter with level/risk 1, boolean checks, one thread, a delay and process deadline; redirects are disabled and session/output files use a disposable per-job directory.

Arjun runs the installed native engine behind an exact-origin GET guard. Unhealthy 400/413/418/429/5xx responses and request errors stop before the upstream 2.2.7 response-handler crash. Logs show the actual HTTP status and request count instead of a traceback. Redirects, count limits and response-size limits are explicit policy early stops; HTTP/network failures remain incomplete. Stability checks preserve the selected query, do not change scheme or follow redirects, validate public DNS per request and verify TLS. At most 64 requests and 256 KiB per response are allowed.

Dalfox URL-only reviews retain initial-page DOM AST analysis while omitting header/cookie/path injection and, without query parameters, parameter discovery/injection. Parameterized URLs retain query testing. A small native wrapper preserves an explicit scan-budget notice without persisting verbose native stdout/stderr. A finished structured report plus that exact notice, zero failed requests and no target error codes permits Completed/Findings with an early-stop label; ambiguous incomplete output and forced outer timeouts remain incomplete.

Dalfox incomplete reports retain their request counters and target status/error codes in log diagnostics; raw request/response bodies and raw target error messages are excluded. A process timeout remains a timeout. GAU uses an explicit keyless config and reports provider problems once in its summary. Amass uses the profile budgets above; forced timeouts remain timeout results.

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
