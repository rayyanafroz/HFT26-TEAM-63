"""A fake program leaking a key to a local model, over real sockets (SOT 8.3).

    python -m scenarios.agent_sim [--port 11434]

It keeps ONE connection open and posts a prompt holding a fake key every few seconds, so the
live scan (2 s interval) sees the connection and the log tail inspects the payload.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time

from shadowlens.config import LOOPBACK_HOST
from shadowlens.fakes import fake

DEFAULT_PORT = 11434
CLIENT_NAME = "agent-sim"


def build_body(key_index: int) -> str:
    prompt = f"My deployment fails with this key, what is wrong? {fake('openai_key', key_index)}"
    return json.dumps({"model": "llama3", "stream": False, "messages": [{"role": "user", "content": prompt}]})


def run(port: int, count: int, interval: float, key_index: int = 0) -> int:
    """Sends ``count`` requests on one connection. Returns how many were answered."""
    connection = http.client.HTTPConnection(LOOPBACK_HOST, port, timeout=10)
    headers = {"Content-Type": "application/json", "x-shadow-client": CLIENT_NAME}
    sent = 0
    try:
        for number in range(count):
            connection.request("POST", "/api/chat", body=build_body(key_index), headers=headers)
            response = connection.getresponse()
            response.read()  # the next request can only reuse the connection once this is drained
            sent += 1
            print(f"request {number + 1}/{count}: HTTP {response.status}", flush=True)
            if number < count - 1:
                time.sleep(interval)
    finally:
        connection.close()
    return sent


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Posts a fake key to a local model server.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--key-index", type=int, default=0, help="a different fake key, to get a new finding without Reset")
    args = parser.parse_args(argv)
    try:
        sent = run(args.port, args.count, args.interval, args.key_index)
    except OSError:
        print(f"Nothing is answering on port {args.port}. Start: python -m scenarios.mock_ollama --port {args.port}")
        return 1
    return 0 if sent == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
