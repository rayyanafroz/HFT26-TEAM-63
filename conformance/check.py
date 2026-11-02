"""Runs an implementation against the conformance suite and reports where it differs.

    python -m conformance.check                              # the Python reference
    python -m conformance.check --cmd "./target/release/engine-adapter"
    python -m conformance.check --cmd "node adapter.mjs" --show 5

The suite is built first if it is missing. The exit code is 0 only when every case matches exactly.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

from conformance.build import OUT, build


def load(out_dir: Path = OUT) -> list[dict]:
    if not (out_dir / "cases.jsonl").exists():
        build(out_dir)
    return [json.loads(line) for line in (out_dir / "cases.jsonl").read_text(encoding="utf-8").splitlines()]


def run(command: list[str], rows: list[dict]) -> dict[str, dict]:
    """Send every case to ``command`` and return its answers by case id."""
    stdin = "".join(json.dumps({"id": r["id"], "text": r["text"]}, ensure_ascii=False) + "\n" for r in rows)
    done = subprocess.run(command, input=stdin, capture_output=True, text=True, encoding="utf-8", timeout=600)
    if done.returncode != 0:
        raise RuntimeError(f"adapter exited {done.returncode}: {done.stderr.strip()[:500]}")
    answers = {}
    for line in done.stdout.splitlines():
        if line.strip():
            reply = json.loads(line)
            answers[reply.pop("id")] = reply
    return answers


def compare(rows: list[dict], answers: dict[str, dict]) -> tuple[dict[str, list[int]], list[dict]]:
    """``{category: [passed, total]}`` and the list of mismatches."""
    tally: dict[str, list[int]] = {}
    misses = []
    for row in rows:
        got = answers.get(row["id"])
        ok = got == row["expected"]
        counts = tally.setdefault(row["category"], [0, 0])
        counts[0] += ok
        counts[1] += 1
        if not ok:
            misses.append({"id": row["id"], "expected": row["expected"], "got": got})
    return tally, misses


def main() -> int:
    parser = argparse.ArgumentParser(description="Check an engine against the conformance suite.")
    parser.add_argument("--cmd", help="command that speaks the protocol (default: the Python reference)")
    parser.add_argument("--show", type=int, default=3, help="how many mismatches to print")
    args = parser.parse_args()
    command = shlex.split(args.cmd) if args.cmd else [sys.executable, "-m", "conformance.adapter"]
    rows = load()
    tally, misses = compare(rows, run(command, rows))
    for category, (passed, total) in sorted(tally.items()):
        print(f"  {'ok ' if passed == total else 'FAIL'} {category:18} {passed}/{total}")
    print(f"{len(rows) - len(misses)}/{len(rows)} cases match")
    for miss in misses[:args.show]:
        print(f"\n{miss['id']}\n  expected {json.dumps(miss['expected'], ensure_ascii=False)[:400]}\n  got      {json.dumps(miss['got'], ensure_ascii=False)[:400]}")
    return 0 if not misses else 1


if __name__ == "__main__":
    sys.exit(main())
