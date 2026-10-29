"""Build the list files and an unsigned payload.json (contract: docs/architecture/contracts/blocklist-feed.md
in the KidGuard product repo; schema copy in schema/).

usage: build.py OUT_DIR SEQ [--stevenblack FILE]
Reads data/*.txt and StevenBlack gambling-porn-only (downloaded unless --stevenblack is given).
Never reads vn-gambling-candidates.txt (tier B, not shippable).
"""
import argparse
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

from common import ROOT, read_names, valid_domain, valid_ip

SB_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn-only/hosts"
SB_HOME = "https://github.com/StevenBlack/hosts"
KG_HOME = "https://github.com/aetherdata-vn/kidguard-blocklist"
# TODO(question-039): licence of KidGuard-authored data; MIT is the placeholder.
KG_LICENSE = "MIT"


def stevenblack(text):
    """Split the merged hosts file by its '# Title:' sections into GAMBLING and ADULT name sets."""
    out = {"GAMBLING": set(), "ADULT": set()}
    cat = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("# Title:"):
            title = line.lower()
            if "gambling vn" in title:
                cat = "GAMBLING"
            elif "adult" in title or "snuff" in title:
                cat = "ADULT"
            elif "extensions" in title:
                cat = None  # file header
            else:
                sys.exit(f"unknown upstream section, refusing to guess: {line}")
            continue
        parts = line.split("#")[0].split()
        if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            if cat is None:
                sys.exit(f"host entry outside a known section: {line}")
            name = parts[1].lower().rstrip(".")
            try:
                name = name.encode("idna").decode("ascii")
            except UnicodeError:
                continue
            if valid_domain(name):
                out[cat].add(name)
    return out


def clean(names, suffix_match, never, psl):
    """Drop public suffixes and never-block names (feed section 4); sorted, deduplicated."""
    keep = set()
    for n in names:
        if n in psl or n in never:
            continue
        if suffix_match and any(x.endswith("." + n) for x in never):
            continue
        keep.add(n)
    return sorted(keep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("seq", type=int)
    ap.add_argument("--stevenblack")
    a = ap.parse_args()
    if a.seq < 1:
        sys.exit("seq must be >= 1")
    data = ROOT / "data"
    never = set(read_names(data / "never-block.txt"))
    psl = set(read_names(data / "public-suffixes.txt"))
    if a.stevenblack:
        sb_text = Path(a.stevenblack).read_text(encoding="utf-8")
    else:
        req = urllib.request.Request(SB_URL, headers={"User-Agent": "kidguard-blocklist-build"})
        with urllib.request.urlopen(req, timeout=60) as r:
            sb_text = r.read().decode("utf-8")
    sb = stevenblack(sb_text)
    now = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    version = time.strftime("%Y.%m.%d", time.gmtime(now))
    # (listId, category, kind, match, lines, license, source, sourceUrl)
    specs = [
        ("sb-adult", "ADULT", "DOMAINS", "EXACT", clean(sb["ADULT"], False, never, psl), "MIT",
         "StevenBlack/hosts gambling-porn-only (adult sections)", SB_HOME),
        ("sb-gambling", "GAMBLING", "DOMAINS", "EXACT", clean(sb["GAMBLING"], False, never, psl), "MIT",
         "StevenBlack/hosts gambling-porn-only (gambling section)", SB_HOME),
        ("kg-vn-gambling", "GAMBLING", "DOMAINS", "SUFFIX",
         clean(read_names(data / "vn-gambling.txt"), True, never, psl), KG_LICENSE, "KidGuard", KG_HOME),
        ("kg-vn-card-games", "CARD_GAMES", "DOMAINS", "SUFFIX",
         clean(read_names(data / "vn-card-games.txt"), True, never, psl), KG_LICENSE, "KidGuard", KG_HOME),
        ("kg-bypass", "BYPASS", "DOMAINS", "EXACT",
         clean(read_names(data / "bypass-domains.txt"), False, never, psl), KG_LICENSE, "KidGuard", KG_HOME),
        ("kg-bypass-ips", "BYPASS", "IPS", None,
         sorted(set(read_names(data / "bypass-ips.txt"))), KG_LICENSE, "KidGuard", KG_HOME),
    ]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    lists = []
    for lid, cat, kind, match, lines, lic, src, url in specs:
        valid = valid_domain if kind == "DOMAINS" else valid_ip
        bad = [x for x in lines if not valid(x)]
        if bad:
            sys.exit(f"{lid}: invalid entries, e.g. {bad[:3]}")
        text = ("\n".join(lines) + "\n") if lines else ""
        blob = gzip.compress(text.encode("utf-8"), 9, mtime=0)  # mtime=0: same input, same bytes
        sha = hashlib.sha256(blob).hexdigest()
        path = f"{lid}.{sha[:16]}.txt.gz"
        (out / path).write_bytes(blob)
        e = {"listId": lid, "category": cat, "kind": kind, "version": version, "path": path,
             "sha256": sha, "bytes": len(blob), "entries": len(lines), "license": lic, "source": src,
             "sourceUrl": url}
        if match:
            e["match"] = match
        lists.append(e)
        print(f"{lid}: {len(lines)} entries, {len(blob)} bytes", file=sys.stderr)
    payload = {"format": 1, "seq": a.seq, "createdAtMs": now * 1000, "lists": lists}
    (out / "payload.json").write_bytes(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


if __name__ == "__main__":
    main()
