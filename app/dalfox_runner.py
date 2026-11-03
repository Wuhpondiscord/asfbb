"""Keep native Dalfox budget evidence without retaining verbose target diagnostics."""
import subprocess
import sys


def run(args):
    target = args[args.index("scan") + 1]
    budget = args[args.index("--scan-timeout") + 1]
    expected = (f"[scan] {target} exceeded --scan-timeout ({budget}s); "
                "cancelling target (stops at next checkpoint)")
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if expected in result.stderr.splitlines():
        print("[asfb] dalfox_scan_budget")
    if result.returncode not in (0, 1):
        print("[stderr] Dalfox native error; inspect structured coverage counters")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
