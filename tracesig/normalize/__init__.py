"""Read traces in any supported format and return TraceSig events.

Formats, detected per file (``fmt="auto"``) or forced:

* ``tracesig``     the native schema (docs/trace-schema.md)
* ``apg``          agent-policy-gateway ``apg audit export --format tracesig``
* ``claude-code``  Claude Code session transcripts and OpenTelemetry exports

Directories are searched recursively for ``.jsonl`` and ``.json`` files.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from ..schema import TraceEvent, event_from_dict
from . import apg, claude_code

FORMATS = ("auto", "tracesig", "apg", "claude-code")
PEEK_LINES = 200


def iter_files(paths: Sequence[str]) -> Iterator[Path]:
    for raw in paths:
        p = Path(os.path.expanduser(raw))
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames.sort()
                for name in sorted(filenames):
                    if name.endswith((".jsonl", ".json")):
                        yield Path(dirpath) / name
        elif p.is_file():
            yield p
        else:
            raise FileNotFoundError(raw)


def detect_format(path: Path) -> Optional[str]:
    """Guess a file's format from its first JSON objects; None if unknown."""
    for n, (_i, obj) in enumerate(claude_code.iter_json_lines(path)):
        if n >= PEEK_LINES:
            break
        if not isinstance(obj, dict):
            continue
        if apg.is_apg_event(obj):
            return "apg"
        if "resourceLogs" in obj or "event.name" in obj:
            return "claude-code"
        if obj.get("type") in ("user", "assistant") and "sessionId" in obj:
            return "claude-code"
        if "tool" in obj and ("session_id" in obj or "seq" in obj):
            return "tracesig"
    return None


def load_events(paths: Sequence[str], fmt: str = "auto", session: Optional[str] = None
                ) -> Tuple[List[TraceEvent], Dict[str, Any]]:
    """Load and normalize every input; returns (events, stats)."""
    if fmt not in FORMATS:
        raise ValueError("unknown format %r (choose from %s)" % (fmt, ", ".join(FORMATS)))
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    skipped: List[str] = []
    cc = claude_code.Collector()
    files = 0
    for path in iter_files(paths):
        files += 1
        kind = detect_format(path) if fmt == "auto" else fmt
        if kind is None:
            skipped.append(str(path))
            continue
        seen.add(kind)
        if kind == "claude-code":
            cc.add_file(path)
            continue
        for index, (_i, obj) in enumerate(claude_code.iter_json_lines(path)):
            if not isinstance(obj, dict):
                continue
            if kind == "apg" or apg.is_apg_event(obj):
                if apg.is_apg_event(obj):
                    rows.append(apg.to_event(obj, path.stem, index))
            else:
                row = dict(obj)
                row.setdefault("seq", index)
                rows.append(row)
    for row in cc.tracesig():
        rows.append(row)
    events = [event_from_dict(r, i) for i, r in enumerate(rows)]
    if session is not None:
        events = [e for e in events if e.session_id == session]
    events.sort(key=lambda e: (e.session_id, e.seq))
    stats = {"files": files, "formats": sorted(seen), "skipped_files": skipped, "events": len(events),
             "sessions": len({e.session_id for e in events})}
    return events, stats


def to_jsonl(events: Sequence[TraceEvent]) -> str:
    """Serialize events in the native schema (the original extra fields are kept)."""
    out = []
    for ev in events:
        row = {k: v for k, v in ev.raw.items()}
        row.update({"session_id": ev.session_id, "seq": ev.seq, "tool": ev.tool, "args": ev.args,
                    "labels": ev.labels, "result_preview": ev.result_preview})
        if ev.ts is not None:
            row["ts"] = ev.ts
        if ev.agent is not None:
            row["agent"] = ev.agent
        out.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    return "".join(line + "\n" for line in out)
