"""TraceSig open trace schema.

A *trace* is a JSONL file: one normalized TraceEvent per line, in order.
See docs/trace-schema.md for the full specification.

Normalizers in :mod:`tracesig.normalize` turn provider-native logs (Claude
Code transcripts and OpenTelemetry exports, agent-policy-gateway audit
exports) into this shape.
"""

from __future__ import annotations

import json
import os
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


def event_from_dict(obj: Dict[str, Any], default_seq: int = 0) -> TraceEvent:
    """Build a :class:`TraceEvent` from one decoded JSON object."""
    labels = obj.get("labels", [])
    if not isinstance(labels, list):
        labels = [labels] if labels else []
    return TraceEvent(
        session_id=str(obj.get("session_id") or "default"),
        seq=int(obj.get("seq", default_seq)),
        tool=str(obj.get("tool", "")),
        args=_canon_args(obj.get("args", "")),
        labels=[str(x) for x in labels],
        result_preview=str(obj.get("result_preview") or ""),
        ts=obj.get("ts"),
        agent=obj.get("agent"),
        raw=obj,
    )


def load_jsonl(path: str) -> List[TraceEvent]:
    """Load a normalized trace from a JSONL file.

    Lines exported by agent-policy-gateway (``"schema": "apg-audit-trace"``)
    are mapped on the fly; use :func:`tracesig.normalize.load_events` for
    other formats and for directories.
    """
    from .normalize import apg  # local import: normalize depends on schema

    events: List[TraceEvent] = []
    stem = os.path.splitext(os.path.basename(path))[0]
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            if apg.is_apg_event(obj):
                obj = apg.to_event(obj, stem, i)
            events.append(event_from_dict(obj, i))
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
