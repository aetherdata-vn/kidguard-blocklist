# kidguard-blocklist

Signed domain and IP lists for the KidGuard parental-control agent (Windows). Public on purpose: the child's PC
downloads them anonymously, without a token. This repository holds only lists and the build scripts.

## What is released

Each release `lists-v<seq>` (integer, never reused) carries `manifest.json` plus the list files as release assets:

| listId | category | match | source |
|---|---|---|---|
| `sb-adult` | ADULT | EXACT | StevenBlack/hosts gambling-porn-only (MIT) |
| `sb-gambling` | GAMBLING | EXACT | same |
| `kg-vn-gambling` | GAMBLING | SUFFIX | KidGuard (`data/vn-gambling.txt`) |
| `kg-vn-card-games` | CARD_GAMES | SUFFIX | KidGuard (`data/vn-card-games.txt`, empty for now) |
| `kg-bypass` | BYPASS | EXACT | KidGuard: DoH/proxy hostnames incl. `use-application-dns.net`, `lite.duckduckgo.com`, `html.duckduckgo.com` |
| `kg-bypass-ips` | BYPASS (IPS) | - | KidGuard: public DoH resolver IPs |

The optional lottery category is not built yet (the contract has no such category; see the product repo handoff q036).
Licences and origins: `NOTICE`.

## URLs

- Manifest, latest: `https://github.com/aetherdata-vn/kidguard-blocklist/releases/latest/download/manifest.json`
- Files: `https://github.com/aetherdata-vn/kidguard-blocklist/releases/download/lists-v{seq}/{path}`
- jsDelivr mirror: `https://cdn.jsdelivr.net/gh/aetherdata-vn/kidguard-blocklist@feed/manifest.json`, files at
  `@lists-v{seq}/dist/{path}`

## Format and signature

`manifest.json` = `{ payload (base64url), signatures[] }`. Signature: ES256 (ECDSA P-256 / SHA-256, 64-byte `r||s`)
over `KidGuard-lists-manifest-v1\n` + payload bytes. Public key (`keyId:SEC1 hex`) is in `PUBLIC_KEY` and is
compiled into the agent (`TRUSTED_KEYS`). Schema copy: `schema/blocklist-manifest.schema.json`; the contract text
lives in the KidGuard product repo (`docs/architecture/contracts/blocklist-feed.md`, private); if the two differ the
product repo wins.

Verify a download: `python scripts/sign.py verify manifest.json "$(cat PUBLIC_KEY)"`.

## Build locally

```
pip install cryptography==43.0.0 jsonschema==4.23.0
python scripts/build.py out 1          # downloads StevenBlack; add --stevenblack FILE to work offline
python scripts/check.py out            # the CI gate
```
Signing needs the private key in env `BLOCKLIST_SIGNING_KEY` (PEM); only the GitHub Actions secret has it.
For a local test use a throwaway key outside the repo.

## Release workflow

`.github/workflows/release.yml`: every Monday 02:17 UTC and on manual run (main only) it builds, runs `check.py`
(required categories, required BYPASS entries, list-file rules, never-block names), skips if no list changed, signs,
verifies against `PUBLIC_KEY`, then publishes tag `lists-v<seq>` (with `dist/`), branch `feed` and the GitHub release.
Pull requests only build and check.

Rollback of a bad list: revert the data change and run the workflow again; that is a new `seq` with the older
content (clients never accept a lower `seq`). Never delete a published release that clients may already have applied.

## Key custody

The private key exists in the `BLOCKLIST_SIGNING_KEY` Actions secret and in the director's password-manager backup.
It is never written to a file in this repository. Rotation: ship the next public key in an agent release first, then
sign with both, then drop the old one (contract section 3).
