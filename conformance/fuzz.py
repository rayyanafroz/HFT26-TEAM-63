"""Differential fuzzing: random texts through the reference and another implementation, compared exactly.

The conformance suite pins known cases. This finds the unknown ones: it builds texts from fake secrets and
personal data, disguises, awkward Unicode (marks, joiners, other scripts' digits, Turkish i, look-alikes,
escapes) and code, sends them to both engines, and reports every difference with the text that caused it.

    python -m conformance.fuzz --cmd "engine/target/release/engine-adapter --settings conformance/build/settings.json"
    python -m conformance.fuzz --cmd "..." --n 20000 --seed 7

It also compares two internal pieces directly when the adapter supports them: base64 decoding against
CPython's binascii (strict and lenient) and the folded detection view against normalize.fold.

Everything is deterministic for a seed. The exit code is 0 only when nothing differs.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import random
import shlex
import subprocess
import sys
import urllib.parse

from conformance.build import answer, disguises, settings
from shadowlens.analysis.normalize import fold
from shadowlens.fakes import KINDS, fake

WORDS = ("the", "key", "token", "password", "pwd", "secret", "api_key", "login", "user", "admin", "is", "was", "here",
         "export", "SSN", "social security", "card", "IBAN", "Aadhaar", "PAN", "email", "phone", "confidential",
         "Copyright", "(c)", "proprietary", "def", "class", "import", "return", "const", "Bearer", "mysql -u root -p",
         "sshpass -p", "credentials: admin /", "https://", "postgres://", "base64,", "model", "example", "test",
         "your_key", "changeme", "settings.DB_PASSWORD", "${SECRET}", "id", "uuid", "sha256", "commit", "corp", "lan")
UNICODE = ("​", "‌", "‍", "⁠", "﻿", "­", "́", "ा", "ः", " ", " ",
           " ", "　", "ı", "İ", "Σ", "σ", "а", "е", "о", "ｓ", "ｋ",
           "١٢٣", "०१", "²", "①", "K", "ſ", "ﬁ", "", "\U0001F600",
           "日本", "אב", "‮", " ", "\x0b", "\x0c", "\x1c", "\x1f", "\x7f", "\x00", "\x85",
           "‐", "−", "－", "ΙΚ")
ESCAPES = ("\\u0073", "\\u006B", "\\uD83D", "%41", "%0A", "%7e", "&#115;", "&#x6B;", "&#X2D;", "&#١٠٠;",
           "&#99999999;", "&#xD800;", "\\u00", "%G1", "&#;")
SEPARATORS = (" ", "  ", "\n", "\r\n", "\t", "", ": ", "=", " = ", ", ", "; ", "/", "-", ".", "\"", "'", "`", "(", ")",
              "[", "]", "{", "}", "@", "+", " + ", "\n\n", "|")
SECRET_KINDS = sorted(k for k in KINDS if k not in ("email", "phone_in", "internal_host"))


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(n))


def fragment(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.22:
        value = fake(rng.choice(sorted(KINDS)), rng.randrange(40))
        if rng.random() < 0.35:
            value = rng.choice(list(disguises(value).values()))
        return value
    if roll < 0.40:
        return rng.choice(WORDS)
    if roll < 0.52:
        return rng.choice(UNICODE)
    if roll < 0.58:
        return rng.choice(ESCAPES)
    if roll < 0.66:
        groups = [_digits(rng, rng.choice((1, 2, 3, 4, 4, 4, 5, 6))) for _ in range(rng.randrange(1, 6))]
        return rng.choice((" ", "-", ".", "", "\n")).join(groups)
    if roll < 0.70:
        return "".join(rng.choice("0123456789abcdef") for _ in range(rng.choice((8, 12, 24, 32, 40, 48, 64))))
    if roll < 0.74:
        raw = (rng.choice(WORDS) + "=" + fake(rng.choice(SECRET_KINDS), rng.randrange(9))).encode()
        return base64.b64encode(raw).decode() if rng.random() < 0.6 else binascii.hexlify(raw).decode()
    if roll < 0.78:
        return "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-=")
                       for _ in range(rng.randrange(16, 70)))
    if roll < 0.81:
        return f"{rng.choice(('GB', 'DE', 'gb', 'IN'))}{rng.choice(('82', '٨٢', '12'))} WEST {_digits(rng, 4)} {_digits(rng, 4)} {_digits(rng, 2)}"
    if roll < 0.84:
        return "```py\n" + "\n".join(rng.choice(("def f(x):", "    return x", "import os", "x = 1;", "class A:", "}"))
                                     for _ in range(rng.randrange(1, 6))) + rng.choice(("\n```", ""))
    if roll < 0.87:
        return rng.choice(("user@corp.example", "a.b@test.com", "x@acme.invalid", "j [at] acme [dot] com",
                           "billing-3.corp", "db.internal", "10.0.0.1", "172.16.300.1", "192.168.1.1", "+91 98765 43210",
                           "(415) 555-0123", "078-05-1120", "ABCPE1234F"))
    if roll < 0.90:
        return urllib.parse.quote(fake(rng.choice(SECRET_KINDS), rng.randrange(9)), safe="")
    if roll < 0.93:
        return "eyJ" + base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "n": rng.randrange(99)}).encode()).decode()[3:].rstrip("=") \
            + "." + "eyJ" + "abcdefghijk" + "." + "sig" + _digits(rng, 9)
    if roll < 0.95:
        return "".join(chr(rng.randrange(0x20, 0x3000)) for _ in range(rng.randrange(1, 12)))
    if roll < 0.962:
        run = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-")
                      for _ in range(rng.choice((23, 24, 25, 40, 4095, 4096, 4097))))
        return rng.choice(("", "=", "x")) + run + "=" * rng.randrange(0, 5) + rng.choice(("", "A", " ", "=", "-"))
    if roll < 0.968:
        n = rng.choice((23, 24, 25, 26, 47, 48, 4096, 4097, 4098))
        return "".join(rng.choice("0123456789abcdefABCDEF") for _ in range(n)) + rng.choice(("", "g", " "))
    if roll < 0.975:
        key = fake(rng.choice(SECRET_KINDS), rng.randrange(9))
        return rng.choice(("GB82", "DE12", "gb82 ", "GB٨٢")) + rng.choice(("", " ", "WEST")) + key[: rng.randrange(8, len(key) + 1)]
    if roll < 0.978:
        return rng.choice((
            f"aws_secret_access_key = {fake('aws_secret_key', rng.randrange(9))}",
            f"SECRET_ACCESS_KEY: '{fake('aws_secret_key', rng.randrange(9))}'",
            f"password = '{rng.choice(('my secret phrase 99', 'hunter2 xyz!', 'short'))}'",
            f"{rng.choice(('dbPassword', 'apiToken', 'clientSecret'))}={fake('password', rng.randrange(9))}",
            f"CONFIDENTIAL{rng.choice((' ', '\n'))}Copyright 2026 Acme",
            "C O N F I D E N T I A L (c) internal use only",
        ))
    begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"  # built, never committed
    return rng.choice((f"{begin}\nMIIEowIBAAKCAQEA1234567890abcdef\n{end}",
                       "[REDACTED:SEC_OPENAI_KEY:0123456789ab]", "[PII:EMAIL]", "\"model\": \"", "sha512-", "://"))


def text_for(rng: random.Random) -> str:
    n = rng.choice((1, 2, 3, 4, 6, 8, 12))
    parts = []
    for _ in range(n):
        parts.append(fragment(rng))
        parts.append(rng.choice(SEPARATORS))
    text = "".join(parts)
    if rng.random() < 0.02:                       # now and then, something long
        text = text * rng.randrange(20, 120)
    return text


def run(command: list[str], requests: list[dict]) -> list[dict]:
    stdin = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in requests)
    done = subprocess.run(command, input=stdin, capture_output=True, text=True, encoding="utf-8", timeout=1800)
    if done.returncode != 0:
        raise RuntimeError(f"adapter exited {done.returncode}: {done.stderr.strip()[:500]}")
    return [json.loads(line) for line in done.stdout.split("\n") if line.strip()]


def b64_cases(rng: random.Random, n: int) -> list[str]:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_ !\n"
    out = []
    for _ in range(n):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 24)))
        if rng.random() < 0.4:
            s = base64.b64encode(s.encode()).decode()[: rng.randrange(0, 40)] + "=" * rng.randrange(0, 4)
        out.append(s)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Differential fuzzing of an engine against the Python reference.")
    parser.add_argument("--cmd", required=True, help="command that speaks the conformance protocol")
    parser.add_argument("--n", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--show", type=int, default=5)
    args = parser.parse_args()
    command = shlex.split(args.cmd)
    rng = random.Random(args.seed)
    cfg = settings()
    problems: list[str] = []

    texts = [text_for(rng) for _ in range(args.n)]
    got = run(command, [{"id": i, "text": t} for i, t in enumerate(texts)])
    for i, text in enumerate(texts):
        expected = answer(text, cfg)
        reply = got[i] if i < len(got) else None
        if reply is not None:
            reply = {k: v for k, v in reply.items() if k != "id"}
        if reply != expected:
            problems.append(f"text {i}: {text[:300]!r}\n  expected {json.dumps(expected, ensure_ascii=False)[:600]}\n"
                            f"  got      {json.dumps(reply, ensure_ascii=False)[:600]}")
    print(f"analyze: {args.n - len(problems)}/{args.n} identical")

    pieces = b64_cases(rng, 3000)
    requests = [{"id": i, "op": "b64", "data": s, "strict": i % 2 == 0} for i, s in enumerate(pieces)]
    replies = run(command, requests)
    b64_bad = 0
    for request, reply in zip(requests, replies):
        try:
            want = {"ok": True, "hex": binascii.a2b_base64(request["data"].encode(), strict_mode=request["strict"]).hex()}
        except binascii.Error:
            want = {"ok": False}
        if {k: v for k, v in reply.items() if k != "id"} != want:
            b64_bad += 1
            problems.append(f"b64 {request}: expected {want}, got {reply}")
    print(f"base64:  {len(pieces) - b64_bad}/{len(pieces)} identical")

    fold_texts = [text_for(rng) for _ in range(1000)]
    replies = run(command, [{"id": i, "op": "fold", "text": t} for i, t in enumerate(fold_texts)])
    fold_bad = 0
    for text, reply in zip(fold_texts, replies):
        view, starts, ends = fold(text)
        if (reply["view"], reply["starts"], reply["ends"]) != (view, starts, ends):
            fold_bad += 1
            problems.append(f"fold {text[:200]!r}: expected {view[:200]!r}, got {reply['view'][:200]!r}")
    print(f"fold:    {len(fold_texts) - fold_bad}/{len(fold_texts)} identical")

    for problem in problems[: args.show]:
        print("\n" + problem)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
