"""The reference implementation of the conformance protocol, over the Python engine.

Reads one JSON object per line on stdin (``{"id": ..., "text": ...}``) and writes one per line on stdout
(``{"id": ..., "findings": [...], "redacted_text": ..., "safe_to_send": ..., "failed": [...]}``).
A port to another language implements the same two lines of protocol; see conformance/README.md.
"""

from __future__ import annotations

import json
import sys

from conformance.build import answer


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        sys.stdout.write(json.dumps({"id": request["id"], **answer(request["text"])}, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
