"""Finding output: human-readable text report and JSON."""

from __future__ import annotations

import json
from typing import List

from .engine import Finding

_SEV_ICON = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED ]",
    "low": "[LOW ]",
    "informational": "[INFO]",
}


def to_text(findings: List[Finding]) -> str:
    if not findings:
        return "No findings. Trace looks clean against the loaded rules.\n"
    lines = [f"{len(findings)} finding(s)\n" + "=" * 60]
    for f in findings:
        lines.append(f"\n{_SEV_ICON.get(f.severity, '[??? ]')} {f.rule_id} — {f.title}")
        lines.append(f"  session: {f.session_id}   category: {f.category}")
        if f.description:
            lines.append(f"  {f.description}")
        lines.append("  timeline:")
        for ev in f.events:
            args = (ev.args[:80] + "…") if len(ev.args) > 80 else ev.args
            labels = f"  labels={ev.labels}" if ev.labels else ""
            lines.append(f"    #{ev.seq:<4} {ev.tool}  {args}{labels}")
    lines.append("")
    return "\n".join(lines)


def to_json(findings: List[Finding]) -> str:
    out = []
    for f in findings:
        out.append(
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "session_id": f.session_id,
                "tags": f.tags,
                "events": [
                    {"seq": ev.seq, "tool": ev.tool, "args": ev.args, "labels": ev.labels}
                    for ev in f.events
                ],
            }
        )
    return json.dumps({"findings": out, "count": len(out)}, indent=2, ensure_ascii=False)
