"""CI gate before signing: schema, required coverage, BYPASS entries, list-file rules (feed sections 3.1, 4).

usage: check.py OUT_DIR   (reads payload.json and the list files beside it)
Exit 1 with every problem printed.
"""
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

from common import ROOT, read_names, valid_domain, valid_ip

REQUIRED_BYPASS = ["use-application-dns.net", "lite.duckduckgo.com", "html.duckduckgo.com"]
# Floors far below real sizes: an upstream that got truncated or mis-split must not be signed.
MIN_ENTRIES = {"sb-adult": 10000, "sb-gambling": 1000, "kg-vn-gambling": 100, "kg-bypass": 10, "kg-bypass-ips": 8}
PATH_RE = re.compile(r"^[a-z0-9-]+\.([0-9a-f]{16})\.txt\.gz$")


def main():
    out = Path(sys.argv[1])
    errs = []
    payload_bytes = (out / "payload.json").read_bytes()
    payload = json.loads(payload_bytes)
    schema = json.loads((ROOT / "schema" / "blocklist-manifest.schema.json").read_text(encoding="utf-8"))
    pschema = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": "#/$defs/Payload"}
    errs += [f"schema: {e.message}" for e in Draft202012Validator(pschema).iter_errors(payload)]
    if len(payload_bytes) > 64 * 1024:
        errs.append("payload over 64 KiB")

    never = set(read_names(ROOT / "data" / "never-block.txt"))
    never_ips = set(read_names(ROOT / "data" / "never-block-ips.txt"))
    psl = set(read_names(ROOT / "data" / "public-suffixes.txt"))
    lists = payload["lists"]
    have = {(e["category"], e["kind"]) for e in lists}
    for need in [("ADULT", "DOMAINS"), ("GAMBLING", "DOMAINS"), ("CARD_GAMES", "DOMAINS"),
                 ("BYPASS", "DOMAINS"), ("BYPASS", "IPS")]:
        if need not in have:
            errs.append(f"missing required list {need}")
    bypass_entries, total = set(), 0
    for e in lists:
        lid = e["listId"]
        blob = (out / e["path"]).read_bytes()
        sha = hashlib.sha256(blob).hexdigest()
        m = PATH_RE.match(e["path"])
        if sha != e["sha256"] or len(blob) != e["bytes"] or not m or m.group(1) != sha[:16]:
            errs.append(f"{lid}: sha256, bytes or path mismatch")
        raw = gzip.decompress(blob)
        if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or (raw and not raw.endswith(b"\n")):
            errs.append(f"{lid}: BOM, CR or missing final LF")
        lines = raw.decode("utf-8").split("\n")[:-1] if raw else []
        if len(lines) != e["entries"]:
            errs.append(f"{lid}: entries {len(lines)} != {e['entries']}")
        if lines != sorted(set(lines)) or "" in lines or any(x.startswith("#") for x in lines):
            errs.append(f"{lid}: not sorted/unique, or has blank/comment lines")
        if len(lines) < MIN_ENTRIES.get(lid, 0):
            errs.append(f"{lid}: only {len(lines)} entries, floor {MIN_ENTRIES[lid]}")
        total += len(lines)
        if e["kind"] == "DOMAINS":
            bad = [x for x in lines if not valid_domain(x)]
            hit = [x for x in lines if x in psl or x in never]
            if bad or hit:
                errs.append(f"{lid}: invalid {bad[:3]}, public-suffix/never-block {hit[:3]}")
            if e.get("match") == "SUFFIX":
                cover = [n for n in never if any(n.endswith("." + x) for x in lines)]
                if cover:
                    errs.append(f"{lid}: SUFFIX entries cover never-block names {cover[:3]}")
            if e["category"] == "BYPASS":
                bypass_entries |= set(lines)
        else:
            bad = [x for x in lines if not valid_ip(x)]
            if bad or never_ips & set(lines):
                errs.append(f"{lid}: invalid {bad[:3]} or upstream resolver IP present")
    if total > 1_000_000:
        errs.append("over 1,000,000 entries in total")
    for r in REQUIRED_BYPASS:
        if r not in bypass_entries:
            errs.append(f"BYPASS list lacks required entry {r}")
    if errs:
        print("CHECK FAILED:\n  " + "\n  ".join(errs), file=sys.stderr)
        sys.exit(1)
    print(f"check ok: {len(lists)} lists, {total} entries, seq {payload['seq']}")


if __name__ == "__main__":
    main()
