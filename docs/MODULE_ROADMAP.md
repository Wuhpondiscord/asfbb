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

## Requested next groups

| Requested feature | State | Intended input / applicability gate |
| --- | --- | --- |
| More [Nuclei templates](https://docs.projectdiscovery.io/templates/introduction) | Two added; further expansion WIP | Reviewed HTTP templates, technology gates, exact-origin constraints, existing request budgets and validation. |
| [Gemini Nuclei template generation](https://ai.google.dev/gemini-api/docs/structured-output) | Deferred under keyless preference | Hosted Gemini generation needs API credentials, so it is not part of the keyless pipeline. Any future optional integration would use a separate draft-generation action with a Space secret and configurable model. Generated templates must pass existing template restrictions and Nuclei validation before explicit selection. Do not auto-run generated YAML. |
| [Wapiti](https://github.com/wapiti-scanner/wapiti) | Limited profile implemented | Further profiles need separately reviewed request/method limits. |
| [Retire.js](https://github.com/RetireJS/retire.js) | Implemented for web JavaScript | Source/SBOM upload workflows remain future work. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Planned | Explicit repository/artifact input on remote infrastructure. Redacted secret findings; verification behavior must be explicit. |
| [OWASP Amass](https://github.com/owasp-amass/amass) | Planned | Passive domain discovery first. Newly discovered subdomains are inventory and do not automatically become authorized scan targets. |
| [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) | Planned | Source, SBOM or container artifact; a URL-only job is inapplicable. |
| [Trivy](https://github.com/aquasecurity/trivy) (requested as “trivvy”) | Planned | Explicit image, repository, filesystem artifact or SBOM. No Docker daemon assumed inside the HF runtime. |
| [Kiterunner](https://github.com/assetnote/kiterunner) | Planned | Explicit API target, small reviewed route dictionary, method restrictions and request budget; no unrestricted large route sets by default. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Planned | Supported lockfiles, SBOM or image/source artifact; skip URL-only jobs. |
| [garak](https://github.com/NVIDIA/garak) | Optional, planned | Separately configured LLM endpoint/provider and probe allowlist. A normal website is not automatically an LLM target. |
| [OWASP Nettacker](https://github.com/OWASP/Nettacker) | Optional, partial integration planned | User-confirmed project. Consider HTTP checks on permitted ports first; do not assume raw sockets, arbitrary outbound ports, or broad network scans work in HF. |

No placeholder scanner is represented as installed. Check each group's upstream docs again when implementing it because CLI flags, output formats and provider interfaces change.

## Validation

GitHub Actions runs offline mocked scanner/API tests, syntax checks, and builds the real image. Container checks verify the actual tool help flags and run the Ruby origin/redirect guard tests without target traffic. The existing deployment pushes main to wuhp/bbscanner only after checks pass. No live target scans are part of verification.
