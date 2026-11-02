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

WPScan inventory works without a vulnerability API token. For vulnerability database lookups, optionally set **WPSCAN_API_TOKEN** as a Hugging Face Space **secret**. It is read from the tool's documented environment variable, never inserted into command arguments or returned report metadata. Metadata is fetched during the remote image build; scans use --no-update and isolated temporary cookie/cache paths. See [WPScan's license](https://github.com/wpscanteam/wpscan/blob/v4.2.0/LICENSE) for its usage terms.

## Requested next groups

| Requested feature | State | Intended input / applicability gate |
| --- | --- | --- |
| More [Nuclei templates](https://docs.projectdiscovery.io/templates/introduction) | Planned, WIP | Reviewed HTTP templates, technology gates, exact-origin constraints, existing request budgets and validation. |
| [Gemini Nuclei template generation](https://ai.google.dev/gemini-api/docs/structured-output) | Planned | Separate draft-generation action with a Space secret and configurable model. Generated templates must pass existing template restrictions and Nuclei validation before explicit selection. Do not auto-run generated YAML. |
| [Wapiti](https://github.com/wapiti-scanner/wapiti) | Planned | Explicit web asset, capped crawl/attack modules, selected methods, exact-origin policy. |
| [Retire.js](https://github.com/RetireJS/retire.js) | Planned | Bounded same-origin JavaScript files or uploaded source; not arbitrary domain text passed to a filesystem scanner. |
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
