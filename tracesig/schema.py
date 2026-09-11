"""TraceSig open trace schema.

A *trace* is a JSONL file: one normalized TraceEvent per line, in order.
See docs/trace-schema.md for the full specification.

Normalizers turn provider-native logs (MCP, OpenAI tool calls, Anthropic
tool_use blocks, agent-policy-gateway audit logs) into this shape. v0.1
ships the generic loader; provider normalizers land in v0.2.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class TraceEvent:
    """One tool call made by an agent."""

    session_id: str
    seq: int
    tool: str
    args: str = ""                       # canonical string dump of arguments
    labels: List[str] = field(default_factory=list)  # data-source labels: web, pii, file, untrusted...
    result_preview: str = ""             # first N chars of the tool result (optional)
    ts: Optional[str] = None             # ISO-8601 timestamp (optional)
    agent: Optional[str] = None          # agent / model identifier (optional)
    raw: Dict[str, Any] = field(default_factory=dict)

    def get(self, path: str) -> Any:
        """Dotted-path field access used by the rule engine.

        Supported paths: tool, args, labels, result_preview, ts, agent,
        session_id, seq, and raw.<key> for anything else.
        """
        if path.startswith("raw."):
            cur: Any = self.raw
            for part in path[4:].split("."):
                if not isinstance(cur, dict) or part not in cur:
                    return None
                cur = cur[part]
            return cur
        return getattr(self, path, None)


def load_jsonl(path: str) -> List[TraceEvent]:
    """Load a normalized trace from a JSONL file."""
    events: List[TraceEvent] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            events.append(
                TraceEvent(
                    session_id=str(obj.get("session_id", "default")),
                    seq=int(obj.get("seq", i)),
                    tool=str(obj.get("tool", "")),
                    args=_canon_args(obj.get("args", "")),
                    labels=[str(x) for x in obj.get("labels", [])],
                    result_preview=str(obj.get("result_preview", "")),
                    ts=obj.get("ts"),
                    agent=obj.get("agent"),
                    raw=obj,
                )
            )
    events.sort(key=lambda e: (e.session_id, e.seq))
    return events


def _canon_args(args: Any) -> str:
    """Canonicalize arguments to a single searchable string."""
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(args)


def sessions(events: List[TraceEvent]) -> Iterator[List[TraceEvent]]:
    """Yield events grouped by session, in seq order."""
    current: List[TraceEvent] = []
    for ev in events:
        if current and ev.session_id != current[-1].session_id:
            yield current
            current = []
        current.append(ev)
    if current:
        yield current
