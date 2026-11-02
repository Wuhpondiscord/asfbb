# Module rollout and HF compatibility

Development remains remote-only. All dependency installation, testing and container builds happen on GitHub-hosted runners or Hugging Face, never on the owner's device. This list records the requested scope; planned entries are not installed or offered as working modules.

## First group

| Module | State | Runtime applicability and coverage |
| --- | --- | --- |
| [Nikto 2.6.1](https://github.com/sullo/nikto/wiki) | Implemented | Explicit HTTP(S) asset; tuning 23b (configuration, information disclosure, software identification), request pause, 45-second internal / 60-second external deadline. No redirect following. This bounded sample is not a complete Nikto scan. |
| [WPScan 4.2.0](https://github.com/wpscanteam/wpscan/blob/v4.2.0/README.md) | Implemented | One current-page GET, capped at 512 KiB and 10 seconds, must show a WordPress generator or same-origin WordPress assets. Otherwise skipped with the reason, including when detection is inconclusive. Passive detection of plugins/themes; no passwords or user enumeration. Target requests restricted to the exact origin with redirects disabled. Nested installations supported when asset paths reveal the installation directory. |
| [testssl.sh 3.2.4](https://github.com/testssl/testssl.sh/blob/v3.2.4/doc/testssl.1.md) | Implemented, limited profile | HTTPS only; HTTP skipped. Server-defaults/certificate profile, one resolved IP, 5-second connection/OpenSSL limits, 90-second overall deadline. Does not run exhaustive cipher or vulnerability sweeps. |

All three require the existing active-testing confirmation, appear in job logs, and retain unverified structured findings. A skipped stage is not a tool error. Unknown WordPress detection is shown explicitly and does not prove a site is not WordPress. TLS egress restrictions and sleeping/rebuilding HF Spaces can still affect availability. Process groups are terminated on cancellation/deadline, including shell children.

Use **Settings → Enable all modules** to select every currently implemented stage. This preserves the separate authorization checkbox. The server checks applicability when each job runs, regardless of how modules were selected.

All implemented modules work without API keys. WPScan runs its inventory profile without a key and clearly reports unavailable vulnerability database coverage. A WPSCAN_API_TOKEN Space secret remains optional for users who already have one; it is never needed to run the pipeline.

## Second group: keyless additions

| Module / check | State | Runtime applicability and limits |
| --- | --- | --- |
| [Retire.js 6.1.0](https://github.com/RetireJS/retire.js/blob/6.1.0/node/README.md) | Implemented | Samples current-page inline scripts and same-origin script URLs, including JS inventory from earlier discovery stages. Maximum 4 files, 512 KiB per file, no redirects. Skips if no usable JavaScript is available. Runs the scanner on HF temporary files as data; never executes target JavaScript. Uses an image-bundled upstream advisory snapshot and no runtime API/key. Findings retain their original source URLs. Snapshot freshness and bounded sampling limit coverage. |
| [Wapiti 3.3.2](https://github.com/wapiti-scanner/wapiti/wiki) | Implemented, limited profile | Browser-free CSP, HTTP-header and cookie-flag checks. Exact selected URL scope, guarded exact origin, GET/HEAD only, 12-request hard limit, configured request delay, no redirects, 25-second scan / 40-second process deadline. No injection modules, form submissions, endpoint callbacks or automatic bug reports. Separate Python 3.12 environment matches upstream requirements. |
| Directory listing Nuclei template | Implemented, opt-in | HTML index title plus directory-navigation markers and HTTP 200. Informational observation; does not prove sensitive file exposure. |
| OpenAPI JSON Nuclei template | Implemented, opt-in | Two common JSON paths, version and paths-object markers, HTTP 200. Runs at the origin once even when discovery found many asset paths. Public API documentation may be intentional. |

Both modules appear in Settings, Enable all modules, source filters and stage logs. Sampling failures and guard limits are reported explicitly. Tests include the actual installed Retire.js scanner on a synthetic JS fixture and the actual installed Wapiti engine behind a mocked HTTP transport; they send no live-target traffic.

## Final group: remaining integrations

All requested integrations now have working bounded entry points. Modules requiring a source artifact, SBOM, API designation or LLM definition skip when that context is absent, even under Enable all modules. These are the HF profiles below; they are not promises of every upstream feature.

| Tool / feature | Implemented profile | Limits / applicability |
| --- | --- | --- |
| TruffleHog 3.99.7 | Supplied source-text scan | No repository cloning, archive extraction, secret verification or live credential requests. Secret values, snippets and tool raw reports are discarded; only redacted detector summaries are returned. |
| OWASP Amass 4.2.0 | Standalone passive enumeration of the selected hostname | v4 is intentionally pinned for a single-container HF deployment; current v5 requires a collection-engine service. External providers can time out or return no data without a key. Discovered hostnames remain separate inventory and never become scan targets automatically. |
| OWASP dep-scan 6.3.0 | Supplied application CycloneDX SBOM | Smaller public app-only 2024+ database, lazily downloaded to HF cache on first applicable scan. No source builds, container daemon, OS database or reachability analysis. Preparation is bounded; unavailable databases produce unavailable coverage, not a clean result. |
| Trivy 0.76.1 | Supplied CycloneDX SBOM | Public keyless advisory DB cached in HF; no container daemon needed. No filesystem/image/kubernetes scanning in this profile. |
| OSV-Scanner 2.7.0 | Supplied CycloneDX SBOM | Queries public OSV with package names/versions; no API key. No automatic repository download or source execution. |
| Kiterunner 1.0.2 | Eight reviewed GET routes at the selected origin | Requires explicit API-target checkbox; one connection, configured pause, no redirects, no large dictionaries or guessed POST payloads. Observed URLs can feed later same-host stages. |
| OWASP Nettacker 0.4.1 | Partial HTTP-status profile using its installed HTTP engine and upstream module conditions | One exact-URL request; no network/port/credential scan, extra services, graph DB or API-key requirement. |
| garak 0.17.1 | Installed REST generator, test-signature prompts and EICAR detector | Requires a same-origin keyless REST LLM endpoint with simple request/response JSON fields. Two benign antivirus-signature checks, applicable when the LLM is expected to filter them. No local model, GPU or provider SDKs; no broad jailbreak benchmark. Model replies are not returned or saved. |
| Nuclei keyless template builder | Deterministic read-only GET observation draft | Always available; validated by the server restrictions and installed Nuclei syntax validator. Generates a draft only; user must review/select it in Custom templates. |
| Optional Gemini drafting | Gemini REST API draft adapter | Disabled until GEMINI_API_KEY and GEMINI_MODEL are supplied as Space configuration. This optional provider necessarily needs credentials; it never becomes a pipeline requirement. Generated drafts pass the same restrictions and installed Nuclei validation. |

### Supplying context

Use Settings → Artifact and specialized module inputs. Source text is limited to 200,000 characters; an application CycloneDX SBOM may contain at most 300 named/versioned components with package URLs. Extra metadata and external references are stripped. Source/SBOM scans attach to one selected asset per job. Submitted content stays in the in-memory job specification and HF temporary directories; job status contains counts instead of content. Use Anonymous for these stages under the existing active-testing confirmation.

Temporary scanner inputs and reports are removed after each stage. Public advisory databases may be cached in /app/data/scanner-cache and can be lost when an HF Space restarts. Initial DB preparation may take up to 180 seconds per scanner; the dep-scan app-only database is about 2 GiB unpacked. The full OS database is not downloaded. No cache preparation occurs for URL-only jobs without SBOM input.

No input source or SBOM is executed, installed as an application, uploaded to a repository, or used to expand target authorization. TruffleHog does not verify detected credentials. OSV uses its documented advisory service; dep-scan/Trivy use downloaded public advisory databases.

## Validation

GitHub Actions runs offline mocked scanner/API tests, syntax checks, and builds the real image. Container checks verify the actual tool help flags and run the Ruby origin/redirect guard tests without target traffic. The existing deployment pushes main to wuhp/bbscanner only after checks pass. No live target scans are part of verification.

The final-group CI checks exercise the installed TruffleHog detector on an isolated generated fixture, installed garak REST/detector code and Nettacker HTTP engine with mocked requests, and validate the dependency/route scanner CLI options. Provider outages and HF runtime DB downloads are not proven by offline CI.
