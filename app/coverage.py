"""Bounded HF execution profiles; current preserves the original API behavior."""
PROFILES = {
    "current": {"retire_files": 4, "retire_bytes": 524288, "retire_sampling_seconds": 60,
                "retire_attempts": 4, "katana_seeds": 2, "katana_timeout": 65, "dalfox_payloads": 30, "dalfox_scan_seconds": 30,
                "dalfox_timeout": 65, "amass_minutes": 1, "amass_timeout": 65},
    "quick": {"retire_files": 4, "retire_bytes": 524288, "retire_sampling_seconds": 30,
              "retire_attempts": 8, "katana_seeds": 1, "katana_timeout": 65, "dalfox_payloads": 8, "dalfox_scan_seconds": 30,
              "dalfox_timeout": 60, "amass_minutes": 1, "amass_timeout": 65},
    "balanced": {"retire_files": 8, "retire_bytes": 2097152, "retire_sampling_seconds": 60,
                 "retire_attempts": 12, "katana_seeds": 2, "katana_timeout": 90, "dalfox_payloads": 12, "dalfox_scan_seconds": 60,
                 "dalfox_timeout": 90, "amass_minutes": 1, "amass_timeout": 95},
    "thorough": {"retire_files": 16, "retire_bytes": 4194304, "retire_sampling_seconds": 120,
                 "retire_attempts": 20, "katana_seeds": 3, "katana_timeout": 120, "dalfox_payloads": 30, "dalfox_scan_seconds": 120,
                 "dalfox_timeout": 150, "amass_minutes": 2, "amass_timeout": 150},
}


def profile(name):
    if name not in PROFILES:
        raise ValueError("Unknown coverage profile")
    return dict(PROFILES[name])
