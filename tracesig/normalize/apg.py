"""agent-policy-gateway normalizer.

`apg audit export --format tracesig` writes one ``apg-audit-trace`` event per
gateway decision. Recent APG versions already include ``session_id`` and
``labels``; for older exports this module derives them the same way:

* ``session_id``: the event's ``session_id``; otherwise the file name, plus
  the agent id when there is one (one audit log is treated as one session per
  agent).
* ``labels``: the names in the call's *output* label (what the tool returned:
  ``output_sources``, ``output_confidentiality``, ``output_integrity``), plus
  ``untrusted`` when the output carries any integrity taint. Output labels are
  what taint rules need: the event that brought web content in is the source,
  and a later sink is the finding.

Every original field stays reachable as ``raw.<field>``, so rules can use the
gateway's own verdicts (``raw.verdict``, ``raw.flagged``, ``raw.input_untrusted``).
"""
from __future__ import annotations

from typing import Any, Dict, List

SCHEMA = "apg-audit-trace"
SUPPORTED_VERSIONS = (1,)


def is_apg_event(obj: Any) -> bool:
    return isinstance(obj, dict) and obj.get("schema") == SCHEMA


def derive_labels(obj: Dict[str, Any]) -> List[str]:
    names = set()
    for key in ("output_sources", "output_confidentiality", "output_integrity"):
        for item in obj.get(key) or []:
            names.add(str(item))
    # APG counts a legacy source in both dimensions, so any source or
    # integrity entry means the output is untrusted.
    if obj.get("output_sources") or obj.get("output_integrity"):
        names.add("untrusted")
    return sorted(names)


def to_event(obj: Dict[str, Any], default_session: str, index: int) -> Dict[str, Any]:
    """Map one APG export line onto the TraceSig event shape (a dict)."""
    version = obj.get("schema_version")
    if version not in SUPPORTED_VERSIONS:
        raise ValueError("unsupported apg-audit-trace schema_version %r (supported: %s)" % (
            version, ", ".join(str(v) for v in SUPPORTED_VERSIONS)))
    row = dict(obj)
    session = obj.get("session_id")
    if not session:
        session = "%s:%s" % (default_session, obj["agent"]) if obj.get("agent") else default_session
    row["session_id"] = str(session)
    row["seq"] = int(obj.get("seq", index))
    row["tool"] = str(obj.get("tool", ""))
    row["args"] = obj.get("args", "")
    labels = obj.get("labels")
    row["labels"] = [str(x) for x in labels] if isinstance(labels, list) else derive_labels(obj)
    row.setdefault("result_preview", "")
    return row
