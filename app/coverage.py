"""Bounded HF execution profiles; current preserves the original API behavior."""
PROFILES = {
    "current": {"retire_total_bytes": 4194304, "retire_files": 4, "retire_bytes": 524288, "retire_sampling_seconds": 60,
                "retire_attempts": 4, "katana_seeds": 2, "katana_timeout": 65, "dalfox_payloads": 30, "dalfox_scan_seconds": 30,
                "dalfox_timeout": 120, "amass_minutes": 1, "amass_timeout": 180},
    "quick": {"retire_total_bytes": 4194304, "retire_files": 4, "retire_bytes": 524288, "retire_sampling_seconds": 30,
              "retire_attempts": 8, "katana_seeds": 1, "katana_timeout": 65, "dalfox_payloads": 8, "dalfox_scan_seconds": 30,
              "dalfox_timeout": 120, "amass_minutes": 1, "amass_timeout": 180},
    "balanced": {"retire_total_bytes": 33554432, "retire_files": 16, "retire_bytes": 4194304, "retire_sampling_seconds": 120,
                 "retire_attempts": 24, "katana_seeds": 2, "katana_timeout": 90, "dalfox_payloads": 12, "dalfox_scan_seconds": 90,
                 "dalfox_timeout": 210, "amass_minutes": 2, "amass_timeout": 300},
    "thorough": {"retire_total_bytes": 67108864, "retire_files": 64, "retire_bytes": 8388608, "retire_sampling_seconds": 240,
                 "retire_attempts": 80, "katana_seeds": 3, "katana_timeout": 120, "dalfox_payloads": 30, "dalfox_scan_seconds": 300,
                 "dalfox_timeout": 420, "amass_minutes": 5, "amass_timeout": 600},
}


def profile(name):
    if name not in PROFILES:
        raise ValueError("Unknown coverage profile")
    return dict(PROFILES[name])
