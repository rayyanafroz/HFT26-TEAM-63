"""Speed of an implementation against the reference on hostile and ordinary inputs, with exact output checks.

    python -m conformance.bench --cmd "engine/target/release/engine-adapter --settings conformance/build/settings.json"

Each input is sent alone to one running adapter process, so the times exclude start-up (reported once).
The exit code is 1 if any output differs or any input is slower than its limit.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time

from conformance.build import answer, settings
from shadowlens.fakes import fake

LIMIT_MS = 300


def inputs() -> dict[str, str]:
    key = fake("openai_key")
    return {
        "short prompt": f'Why does this fail? client = OpenAI(api_key="{key}") thanks',
        "dots 64KB": "a." * 32768,
        "dashes 64KB": "a-" * 32768,
        "digit groups 64KB": "1 " * 32768,
        "digits after a letter 64KB": "a" + "1" * 65536,
        "letters then @ 64KB": "a" * 65536 + "@x.com",
        "word run 64KB": "ab" * 32768,
        "at-signs 64KB": "a@" * 32768,
        "brackets": "[at]" * 16000,
        "base64 run 200KB": "QUJD" * 50000,
        "hex run 100KB": "ab" * 50000,
        "prose 200KB": "The quarterly report is attached. Let me know if the numbers look right to you. " * 2500,
        "2500 keys": " ".join(fake("openai_key", i) for i in range(2500)),
        "IBAN prefixes on keys": " ".join("GB82" + fake("openai_key", i)[3:] for i in range(1500)),
        "json 100KB": json.dumps({"messages": [{"role": "user", "content": f"hello {i}"} for i in range(2500)]}),
        "zero-width 50KB": "\u200B".join("abcdefgh" * 800),
        "password words 64KB": "password " * 7000,
        "uppercase run 64KB": "ABCDE" * 13000,
        "code 2000 lines": "\n".join(f"def f{i}(x):\n    return x + {i};" for i in range(1000)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Time an implementation against the reference.")
    parser.add_argument("--cmd", required=True)
    parser.add_argument("--limit-ms", type=float, default=LIMIT_MS)
    args = parser.parse_args()
    proc = subprocess.Popen(shlex.split(args.cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                            encoding="utf-8", bufsize=1)

    def ask(text: str) -> tuple[dict, float]:
        start = time.perf_counter()
        proc.stdin.write(json.dumps({"id": 0, "text": text}) + "\n")
        proc.stdin.flush()
        reply = json.loads(proc.stdout.readline())
        reply.pop("id")
        return reply, (time.perf_counter() - start) * 1000

    _, first = ask("warm up")
    print(f"first call (start-up): {first:.0f} ms")
    cfg, bad = settings(), 0
    for name, text in inputs().items():
        got, ms = ask(text)
        start = time.perf_counter()
        expected = answer(text, cfg)
        python_ms = (time.perf_counter() - start) * 1000
        ok = got == expected and ms <= args.limit_ms
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name:28} {ms:8.1f} ms   (python {python_ms:7.1f} ms)   "
              f"{'same' if got == expected else 'DIFFERENT'}", flush=True)
    proc.stdin.close()
    proc.wait()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
