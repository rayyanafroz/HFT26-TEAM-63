"""Per-tool memory for agent analysis (SOT 7.4, "Context").

An ``AgentSessionContext`` is kept for each tool (``process|provider``). It is what lets
the analyzer avoid re-flagging an agent's old tool calls every time the whole conversation
is sent again. The same input with the same context always gives the same output.

``AgentContexts`` is the registry the pipeline owns. Reset clears it (``/api/demo/reset``).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from ..models import CapabilityName


@dataclass
class AgentSessionContext:
    tool_id: str
    seen_calls: set[str] = field(default_factory=set)            # hash12 of "tool name + normalized arguments"
    granted: set[CapabilityName] = field(default_factory=set)    # capabilities the agent declared it has
    last_injection_ts: str | None = None                         # P2: for the injection-chain rule


class AgentContexts:
    """All contexts, by tool id. Safe to use from several threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_tool: dict[str, AgentSessionContext] = {}

    def get(self, tool_id: str) -> AgentSessionContext:
        """The context for a tool, created empty on first use."""
        with self._lock:
            ctx = self._by_tool.get(tool_id)
            if ctx is None:
                ctx = self._by_tool[tool_id] = AgentSessionContext(tool_id=tool_id)
            return ctx

    def tool_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._by_tool)

    def reset(self) -> None:
        with self._lock:
            self._by_tool.clear()
