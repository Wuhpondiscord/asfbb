"""Keep native Dalfox budget evidence without retaining verbose target diagnostics."""
import subprocess
import sys
from urllib.parse import urlsplit


def run(args):
    target = args[args.index("scan") + 1]
    budget = args[args.index("--scan-timeout") + 1]
    suffix = (f" exceeded --scan-timeout ({budget}s); "
              "cancelling target (stops at next checkpoint)")
    def key(value):
        parts = urlsplit(value)
        return (parts.scheme.lower(), parts.hostname, parts.port or (443 if parts.scheme == "https" else 80),
                parts.path or "/", parts.query)
    def budget_notice(line):
        if not line.startswith("[scan] ") or not line.endswith(suffix):
            return False
        try:
            return key(line[7:-len(suffix)]) == key(target)
        except ValueError:
            return False
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if any(budget_notice(line) for line in result.stderr.splitlines()):
        print("[asfb] dalfox_scan_budget")
    if result.returncode not in (0, 1):
        print("[stderr] Dalfox native error; inspect structured coverage counters")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
