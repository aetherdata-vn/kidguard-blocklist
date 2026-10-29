"""Shared helpers: data-file readers and the line validators of feed contract section 4."""
import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOMAIN_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def read_names(path):
    """Non-comment, non-blank lines of a data file, stripped."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def valid_domain(s):
    return (
        len(s) <= 253
        and DOMAIN_RE.match(s) is not None
        and all(1 <= len(label) <= 63 for label in s.split("."))
    )


def valid_ip(s):
    addr, _, prefix = s.partition("/")
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if not prefix:
        return True
    low = 24 if ip.version == 4 else 48
    high = 32 if ip.version == 4 else 128
    return prefix.isdigit() and low <= int(prefix) <= high
