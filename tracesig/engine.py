"""TraceSig rule engine.

Evaluates YAML rules (see docs/rule-spec.md) against a normalized trace.
v0.1 supports four detection types:

  selection  — all field conditions match a single event
  sequence   — ordered tool calls within one session (optional window)
  taint      — a source label appears in a session, then a sink tool fires
  frequency  — a matching event repeats >= count times in one session
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from .schema import TraceEvent, sessions


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    session_id: str
    events: List[TraceEvent]
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    detection: Dict[str, Any]
    description: str = ""
    status: str = "experimental"
    tags: List[str] = field(default_factory=list)
    path: str = ""


def load_rules(rules_dir: str) -> List[Rule]:
    rules: List[Rule] = []
    for root, _dirs, files in os.walk(rules_dir):
        for name in sorted(files):
            if not name.endswith((".yml", ".yaml")):
                continue
            p = os.path.join(root, name)
            with open(p, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            rules.append(
                Rule(
                    rule_id=str(doc.get("id", name)),
                    title=str(doc.get("title", name)),
                    severity=str(doc.get("severity", "medium")),
                    category=str(doc.get("category", "uncategorized")),
                    detection=doc["detection"],
                    description=str(doc.get("description", "")),
                    status=str(doc.get("status", "experimental")),
                    tags=[str(t) for t in doc.get("tags", [])],
                    path=p,
                )
            )
    return rules


# ---------------------------------------------------------------- matching

def _match_value(op: str, expected: Any, actual: Any) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(_match_value(op, expected, a) for a in actual)
    text = str(actual)
    if op == "matches":
        return re.search(str(expected), text, re.IGNORECASE) is not None
    if op == "contains":
        if isinstance(expected, list):
            return any(str(e).lower() in text.lower() for e in expected)
        return str(expected).lower() in text.lower()
    # default: case-insensitive equality
    return text.lower() == str(expected).lower()


def _event_matches(conditions: Dict[str, Any], ev: TraceEvent) -> bool:
    """`conditions` maps 'field', 'field|matches' or 'field|contains' -> expected."""
    for key, expected in conditions.items():
        if "|" in key:
            path, op = key.split("|", 1)
        else:
            path, op = key, "equals"
        if not _match_value(op, expected, ev.get(path)):
            return False
    return True


# ---------------------------------------------------------------- detections

def _eval_selection(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    conds = det["selection"]
    return [[ev] for ev in sess if _event_matches(conds, ev)]


def _eval_sequence(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    steps: List[Dict[str, Any]] = det["sequence"]
    window = det.get("within_events")
    hits: List[List[TraceEvent]] = []
    i = 0
    while i < len(sess):
        chain: List[TraceEvent] = []
        j = i
        for step in steps:
            found = None
            while j < len(sess):
                ev = sess[j]
                j += 1
                if _event_matches(step, ev):
                    found = ev
                    break
            if found is None:
                chain = []
                break
            chain.append(found)
        if chain:
            if window is None or (chain[-1].seq - chain[0].seq) <= int(window):
                hits.append(chain)
            i = sess.index(chain[0]) + 1
        else:
            break
    return hits


def _eval_taint(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    spec = det["taint"]
    source_label = str(spec["source_label"])
    sink_conds = {k: v for k, v in spec.items() if k.startswith("sink")}
    # rewrite 'sink' / 'sink|matches' keys to address the tool field
    rewritten = {}
    for k, v in sink_conds.items():
        op = k.split("|", 1)[1] if "|" in k else "equals"
        rewritten[f"tool|{op}"] = v
    source_ev: Optional[TraceEvent] = None
    hits: List[List[TraceEvent]] = []
    for ev in sess:
        if source_ev is None and source_label in ev.labels:
            source_ev = ev
            continue
        if source_ev is not None and _event_matches(rewritten, ev):
            hits.append([source_ev, ev])
            source_ev = None  # one finding per source occurrence
    return hits


def _eval_frequency(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    spec = dict(det["frequency"])
    count = int(spec.pop("count", 10))
    matched = [ev for ev in sess if _event_matches(spec, ev)]
    return [matched] if len(matched) >= count else []


_EVALUATORS = {
    "selection": _eval_selection,
    "sequence": _eval_sequence,
    "taint": _eval_taint,
    "frequency": _eval_frequency,
}


def scan(events: List[TraceEvent], rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for sess in sessions(events):
        for rule in rules:
            det_type = next((k for k in _EVALUATORS if k in rule.detection), None)
            if det_type is None:
                continue
            for hit in _EVALUATORS[det_type](rule.detection, sess):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        session_id=sess[0].session_id,
                        events=hit,
                        description=rule.description,
                        tags=rule.tags,
                    )
                )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    findings.sort(key=lambda f: order.get(f.severity, 9))
    return findings
