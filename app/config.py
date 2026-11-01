"""Central ASFB defaults and bounded execution thresholds.

Edit this file before deployment. Server-side limits remain authoritative;
the settings page exposes normal per-job overrides within these maxima.
"""
ACTIVE_BATCH_LIMIT = 100
QUEUE_CAPACITY = 1000
ENDPOINT_LIMIT_DEFAULT = 100
ENDPOINT_LIMIT_MAX = 2000
HTTPX_LIMIT_DEFAULT = 10
HTTPX_LIMIT_MAX = 100
KATANA_DEPTH_DEFAULT = 1
KATANA_DEPTH_MAX = 5
ZAP_ENDPOINT_LIMIT_DEFAULT = 5
ZAP_ENDPOINT_LIMIT_MAX = 100
ZAP_REQUEST_BUDGET_DEFAULT = 100
ZAP_REQUEST_BUDGET_MAX = 2000
REQUEST_DELAY_DEFAULT = 1.5
REQUEST_DELAY_MIN = 1.0
REQUEST_DELAY_MAX = 30.0
MAX_REQUESTS_PER_URL = 10
PROCESS_TIMEOUT_SECONDS = 40
GAU_TIMEOUT_SECONDS = 25
KATANA_TIMEOUT_SECONDS = 65
NUCLEI_TIMEOUT_SECONDS = 90
HTTPX_TIMEOUT_SECONDS = 30

# Process batches are kept small so scans honor conservative per-host rates.
HTTPX_BATCH_SIZE = 25

# Stop retrying a consistently unavailable archive provider across many jobs.
GAU_BREAKER_FAILURES = 4
GAU_BREAKER_COOLDOWN_SECONDS = 900

# Individual review deadlines, separate from the short generic process deadline.
ARJUN_TIMEOUT_SECONDS = 85
DALFOX_TIMEOUT_SECONDS = 65

# Wait briefly for ZAP to drain its asynchronous passive-scan queue before reading alerts.
ZAP_PASSIVE_POLL_LIMIT = 12
ZAP_PASSIVE_POLL_SECONDS = 0.5

# One GAU archive source is selected at a time; change after validating availability.
GAU_PROVIDER = "otx"

PROCESS_OUTPUT_MAX_LINES = 5000

# GAU: fallback providers are queried when Wayback has no successful URL response.
GAU_FALLBACK_PROVIDERS = ("commoncrawl",)
# Wayback is opt-in until its availability recovers.
GAU_ENABLE_WAYBACK = False
GAU_PROVIDER_DEADLINE_SECONDS = 12
GAU_HTTP_TIMEOUT_SECONDS = 8
GAU_AGGREGATE_ALL_PROVIDERS = False

# Curated low-impact templates; the exact reviewed paths are explicit.
NUCLEI_TEMPLATE_PATHS = (
    "/app/app/nuclei-templates/technology-headers.yaml",
    "/app/app/nuclei-templates/hsts-missing.yaml",
    "/app/app/nuclei-templates/csp-missing.yaml",
    "/app/app/nuclei-templates/server-error-disclosure.yaml",
)
NUCLEI_TARGET_LIMIT = 10
NUCLEI_FINDINGS_LIMIT = 100

# Arjun: small/medium/large built-in dictionaries; configurable precision/speed.
ARJUN_WORDLIST = "small"
ARJUN_CHUNK_SIZE = 150
ARJUN_HTTP_TIMEOUT_SECONDS = 8
ARJUN_RATE_LIMIT = 2
ARJUN_PREFER_DYNAMIC_ENDPOINTS = True

# Dalfox machine-readable findings with bounded concurrency and request timeout.
DALFOX_WORKERS = 1
DALFOX_HTTP_TIMEOUT_SECONDS = 5
DALFOX_FINDINGS_LIMIT = 100

# Per-scan template selections; custom and community templates are restricted to
# read-only HTTP paths, checked against the exact target origin.
NUCLEI_COMMUNITY_MAX = 8
NUCLEI_CUSTOM_MAX = 3
NUCLEI_CUSTOM_MAX_BYTES = 20000
NUCLEI_MAX_REQUESTS_PER_TEMPLATE = 2
NUCLEI_CATALOG_PAGE_SIZE = 30

# Optional curated profiles (not enabled unless explicitly selected).
NUCLEI_OPTIONAL_TEMPLATE_PATHS = {
    "bounty-ultimate-lite": "/app/app/nuclei-templates/bounty-ultimate-lite.yaml",
    "bounty-ultimate-medium": "/app/app/nuclei-templates/bounty-ultimate-medium.yaml",
    "bounty-ultimate-large": "/app/app/nuclei-templates/bounty-ultimate-large.yaml",
}
