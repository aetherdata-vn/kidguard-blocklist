"""ES256 signing of the manifest envelope (feed contract section 3).

  sign.py sign OUT_DIR KEY_ID            key PEM (PKCS8) from env BLOCKLIST_SIGNING_KEY; writes OUT_DIR/manifest.json
  sign.py pubkey                         prints the SEC1 uncompressed public key (hex) of that key
  sign.py verify MANIFEST KEY_ID:PUBHEX  exit 1 unless one signature verifies
The private key is read from the environment only, never from argv or a file in the repo.
"""
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

DOMAIN_SEP = b"KidGuard-lists-manifest-v1\n"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_key():
    pem = os.environ.get("BLOCKLIST_SIGNING_KEY", "")
    if not pem:
        sys.exit("BLOCKLIST_SIGNING_KEY is not set")
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        sys.exit("key must be an EC P-256 private key")
    return key


def pub_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()


def verify(manifest, key_id, pub):
    env = json.loads(manifest)
    payload = unb64(env["payload"])
    vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub))
    for s in env["signatures"]:
        if s["keyId"] != key_id or s["alg"] != "ES256":
            continue
        raw = unb64(s["sig"])
        if len(raw) != 64:
            continue
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        try:
            vk.verify(der, DOMAIN_SEP + payload, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            pass
    return False


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "pubkey":
        print(pub_hex(load_key()))
    elif cmd == "sign":
        out, key_id = Path(sys.argv[2]), sys.argv[3]
        payload = (out / "payload.json").read_bytes()
        r, s = decode_dss_signature(load_key().sign(DOMAIN_SEP + payload, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        env = {"payload": b64(payload), "signatures": [{"keyId": key_id, "alg": "ES256", "sig": b64(sig)}]}
        (out / "manifest.json").write_text(json.dumps(env, separators=(",", ":")), encoding="utf-8")
    elif cmd == "verify":
        key_id, pub = sys.argv[3].split(":", 1)
        if not verify(Path(sys.argv[2]).read_bytes(), key_id, pub):
            sys.exit("SIGNATURE INVALID")
        print("signature ok")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
