"""What each source of data lets us see, in plain words (SOT 4.3).

This is the honest answer to "can you see inside HTTPS?" and is shown on the Capture screen.
The wording is the SOT's; keep the two in step.
"""

from __future__ import annotations

from ..models import VisibilityResponse, VisibilityRow

# The exact sentence for the Coverage card (SOT 4.3).
COVERAGE_STATEMENT = "Payload inspection only applies to events with full visibility. HTTPS traffic is reported as metadata only."

_ROWS = (
    ("Live process scan (conn_scan)",
     "process name, pid, destination IP and port; local LLM servers by port (high confidence)",
     "payload, byte counts, connections shorter than ~2 s, cloud provider unless hostname known",
     "metadata_only"),
    ("HTTP log / HAR upload",
     "everything in the export (the exporter already decrypted it)",
     "traffic not in the export",
     "full"),
    ("Live log tail (data/live/)",
     "requests a local server logs",
     "anything it does not log",
     "full"),
    ("PCAP upload (P2)",
     "DNS names, TLS SNI, plaintext HTTP",
     "contents of TLS (HTTPS)",
     "TLS metadata_only; plaintext full"),
    ("AI tool transcripts (opt-in; Claude Code: ~/.claude/projects/**/*.jsonl) (P1)",
     "prompts typed, tool results and agent tool calls, in full, as the tool saved them",
     "tools that keep no transcript; anything the tool does not write to the file",
     "full"),
    ("Ollama tap (P1, opt-in; ShadowLens listens on 127.0.0.1:11436 and forwards to Ollama unchanged)",
     "full request bodies of clients pointed at it",
     "clients not pointed at it; it is a forwarding tap, not passive; never blocks or edits",
     "full"),
)


def visibility_response() -> VisibilityResponse:
    return VisibilityResponse(
        statement=COVERAGE_STATEMENT,
        rows=[VisibilityRow(source=s, can_see=c, cannot_see=n, visibility=v) for s, c, n, v in _ROWS])
