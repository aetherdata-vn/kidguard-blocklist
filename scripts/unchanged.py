"""Exit 0 if the previous manifest and the new payload.json carry the same list files (same sha256 set).

usage: unchanged.py PREV_MANIFEST NEW_PAYLOAD   (the previous signature is not checked: it only gates a skip)
"""
import base64
import json
import sys
from pathlib import Path


def shas(payload):
    return {(e["listId"], e["sha256"]) for e in json.loads(payload)["lists"]}


env = json.loads(Path(sys.argv[1]).read_bytes())
prev = base64.urlsafe_b64decode(env["payload"] + "=" * (-len(env["payload"]) % 4))
sys.exit(0 if shas(prev) == shas(Path(sys.argv[2]).read_bytes()) else 1)
