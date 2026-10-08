"""Framework-wide settings. Case-specific settings live in case_config.json."""
import ipaddress
import json
import os

# Private / internal address ranges (RFC 1918 + loopback)
INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

# Detection thresholds
BRUTE_FORCE_MIN_FAILURES = 5          # failures from one IP against one host
BRUTE_FORCE_WINDOW_MIN = 10           # ... within this many minutes
BRUTE_FORCE_SUCCESS_WINDOW_MIN = 30   # success after failures within this window
BULK_DOWNLOAD_MIN = 10                # S3 GetObject calls ...
BULK_DOWNLOAD_WINDOW_MIN = 10         # ... within this many minutes
BULK_SECRETS_MIN = 5                  # GetSecretValue calls ...
BULK_SECRETS_WINDOW_MIN = 10          # ... within this many minutes
HOST_MEMFD_ALLOW = ("runc",)         # memfd names that are normal (container runtime re-exec)
CLOUD_KEY_STALE_DAYS = 90            # active access key unused (or never used) for longer than this
HOST_RECENT_DAYS = 7                  # 'recent change' window for authorized_keys etc.
SESSION_MAX_HOURS = 8                 # Linux session attribution window

DEFAULT_CASE = {
    "case_id": "CASE-001",
    "investigator": "Jayveer Vasava",
    "linux_timezone_offset": "+05:30",   # auth.log local time (IST)
    "linux_log_year": 2026,              # classic syslog lines have no year
    "credential_inventory": {},          # "host:/path/to/credentials" -> "AKIA..."
    "internal_ranges": [],               # extra internal ranges, e.g. office NAT
    "privileged_source_allowlist": [],   # IPs/CIDRs admin logons are allowed from; empty = rule off
}


def load_case_config(path):
    cfg = dict(DEFAULT_CASE)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def in_ranges(ip, ranges):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(r, strict=False) for r in ranges)


def is_internal(ip, cfg=None):
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # e.g. "AWS Internal", "-", hostnames
    nets = list(INTERNAL_NETS)
    for extra in (cfg or {}).get("internal_ranges", []):
        nets.append(ipaddress.ip_network(extra))
    return any(addr in n for n in nets)
