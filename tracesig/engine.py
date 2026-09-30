"""TraceSig rule engine.

Evaluates YAML rules (see docs/rule-spec.md) against a normalized trace.
Five detection types:

  selection        all field conditions match a single event
  sequence         ordered steps within one session (optional window)
  taint            a source label appears in a session, then a sink tool fires
  frequency        matching events repeat >= count times in one session
  not_preceded_by  an event fires without a required guard (e.g. a
                   human-in-the-loop approval) earlier in the session
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

import yaml

from .schema import TraceEvent, sessions

SEVERITIES = ("critical", "high", "medium", "low", "informational")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
DETECTION_TYPES = ("selection", "sequence", "taint", "frequency", "not_preceded_by")
OPERATORS = ("equals", "contains", "matches")


class RuleError(ValueError):
    """A rule file is not a valid TraceSig rule."""


_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$")
_UNIT_SECONDS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, None: 1}


def parse_duration(value: Any) -> float:
    """'90s', '10m', '2h', '1d' or a number of seconds -> seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    m = _DURATION.match(str(value))
    if not m:
        raise ValueError("bad duration %r (use e.g. 30s, 10m, 2h)" % (value,))
    return float(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def _ts_seconds(ev: TraceEvent) -> Optional[float]:
    if not ev.ts:
        return None
    text = str(ev.ts).strip().replace("Z", "+00:00")
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(text)
    except ValueError:
        # fromisoformat before 3.11 rejects >6 fractional digits
        m = re.match(r"^(.*\.\d{6})\d+(.*)$", text)
        if not m:
            return None
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(m.group(1) + m.group(2))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _in_time(first: TraceEvent, later: TraceEvent, window: Optional[float]) -> bool:
    """True when no time window applies, or both events are timestamped and within it."""
    if window is None:
        return True
    a, b = _ts_seconds(first), _ts_seconds(later)
    return a is not None and b is not None and 0 <= b - a <= window


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
    pack: str = ""


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
    pack: str = ""


# ---------------------------------------------------------------- bundled packs

def bundled_rules_dir() -> Path:
    """Where the rule packs that ship with TraceSig live.

    Installed wheels carry them inside the package (``tracesig/rules``); a
    source checkout keeps them at the repository root (``rules/``).
    """
    here = Path(__file__).resolve().parent
    for candidate in (here / "rules", here.parent / "rules"):
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("bundled TraceSig rules not found")


def available_packs() -> List[str]:
    """Names of the bundled rule packs (the folders under the rules directory)."""
    return sorted(p.name for p in bundled_rules_dir().iterdir() if p.is_dir() and not p.name.startswith("."))


def pack_dirs(names: Iterable[str]) -> List[str]:
    """Directories for the named bundled packs; ``all`` selects every pack."""
    root = bundled_rules_dir()
    packs = available_packs()
    out: List[str] = []
    for name in names:
        if name == "all":
            out.extend(str(root / p) for p in packs)
        elif name in packs:
            out.append(str(root / name))
        else:
            raise RuleError("unknown rule pack %r (available: %s, all)" % (name, ", ".join(packs)))
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- loading and validation

def _split_key(key: str) -> tuple:
    if "|" in key:
        path, op = key.split("|", 1)
    else:
        path, op = key, "equals"
    return path, op


def _check_conditions(conds: Any, where: str, errors: List[str], allow_empty: bool = False) -> None:
    if not isinstance(conds, dict) or (not conds and not allow_empty):
        errors.append("%s must be a non-empty mapping of field conditions" % where)
        return
    for key, expected in conds.items():
        _path, op = _split_key(str(key))
        if op not in OPERATORS:
            errors.append("%s: unknown operator %r in %r (use contains or matches)" % (where, op, key))
        if op == "matches":
            for pattern in (expected if isinstance(expected, list) else [expected]):
                try:
                    re.compile(str(pattern))
                except re.error as exc:
                    errors.append("%s: invalid regex for %r: %s" % (where, key, exc))


def validate_rule(doc: Any) -> List[str]:
    """Return a list of problems with a parsed rule document (empty if valid)."""
    errors: List[str] = []
    if not isinstance(doc, dict):
        return ["rule must be a YAML mapping"]
    for key in ("id", "title", "severity", "category", "detection"):
        if key not in doc:
            errors.append("missing required field %r" % key)
    sev = str(doc.get("severity", ""))
    if "severity" in doc and sev not in SEVERITIES:
        errors.append("severity %r is not one of %s" % (sev, ", ".join(SEVERITIES)))
    if "detection" not in doc:
        return errors
    det = doc["detection"]
    if not isinstance(det, dict):
        return errors + ["detection must be a mapping"]
    types = [t for t in DETECTION_TYPES if t in det]
    if len(types) != 1:
        return errors + ["detection needs exactly one of %s (found %s)" % (", ".join(DETECTION_TYPES), types or "none")]
    kind = types[0]
    body = det[kind]
    if kind == "selection":
        _check_conditions(body, "selection", errors)
    elif kind == "sequence":
        if not isinstance(body, list) or len(body) < 2:
            errors.append("sequence must be a list of at least two steps")
        else:
            for i, step in enumerate(body):
                _check_conditions(step, "sequence step %d" % (i + 1), errors)
    elif kind == "taint":
        if not isinstance(body, dict) or "source_label" not in body:
            errors.append("taint needs source_label")
        elif not any(str(k).split("|", 1)[0] == "sink" for k in body):
            errors.append("taint needs a sink condition (sink or sink|matches)")
        else:
            sink = {"tool" + str(k)[4:]: v for k, v in body.items() if str(k).split("|", 1)[0] == "sink"}
            _check_conditions(sink, "taint sink", errors)
    elif kind == "frequency":
        if not isinstance(body, dict):
            errors.append("frequency must be a mapping")
        else:
            conds = {k: v for k, v in body.items() if k not in ("count", "group_by")}
            _check_conditions(conds, "frequency", errors, allow_empty=True)
            try:
                if int(body.get("count", 10)) < 1:
                    errors.append("frequency count must be >= 1")
            except (TypeError, ValueError):
                errors.append("frequency count must be an integer")
    elif kind == "not_preceded_by":
        if not isinstance(body, dict) or not body.get("event"):
            errors.append("not_preceded_by needs an event condition")
        else:
            _check_conditions(body.get("event"), "not_preceded_by event", errors)
            _check_conditions(body.get("guard") or {}, "not_preceded_by guard", errors, allow_empty=True)
    for dur in [det.get("within")] + ([body.get("within")] if isinstance(body, dict) else []):
        if dur is None:
            continue
        try:
            parse_duration(dur)
        except ValueError as exc:
            errors.append(str(exc))
    windows = [det.get("within_events")]
    if isinstance(body, dict):
        windows.append(body.get("within_events"))
    for window in windows:
        if window is None:
            continue
        try:
            int(window)
        except (TypeError, ValueError):
            errors.append("within_events must be an integer")
    return errors


def _rule_files(target: str) -> List[str]:
    if os.path.isfile(target):
        return [target]
    if not os.path.isdir(target):
        raise FileNotFoundError(target)
    out: List[str] = []
    for root, dirs, files in os.walk(target):
        dirs.sort()
        for name in sorted(files):
            if name.endswith((".yml", ".yaml")):
                out.append(os.path.join(root, name))
    return out


def _pack_of(path: str, base: str) -> str:
    """The pack a rule belongs to: its first folder below the rules root."""
    if not os.path.isdir(base):
        return os.path.basename(os.path.dirname(os.path.abspath(path)))
    parts = Path(os.path.relpath(path, base)).parts
    if len(parts) > 1:
        return parts[0]
    return os.path.basename(os.path.normpath(os.path.abspath(base)))


def load_rules(rules: Union[str, Sequence[str]], strict: bool = False) -> List[Rule]:
    """Load rules from one or more files or directories (searched recursively).

    Documents without a ``detection`` block are skipped (they may be other
    YAML). With ``strict`` an invalid or duplicate rule raises
    :class:`RuleError`; otherwise it is skipped.
    """
    targets = [rules] if isinstance(rules, str) else list(rules)
    out: List[Rule] = []
    seen: Dict[str, str] = {}
    try:
        bundled: Optional[str] = os.path.abspath(str(bundled_rules_dir()))
    except FileNotFoundError:
        bundled = None
    for target in targets:
        for p in _rule_files(target):
            with open(p, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            problems = validate_rule(doc)
            if problems:
                if strict:
                    raise RuleError("%s: %s" % (p, "; ".join(problems)))
                continue
            rule_id = str(doc["id"])
            if rule_id in seen:
                if os.path.abspath(seen[rule_id]) != os.path.abspath(p) and strict:
                    raise RuleError("%s: duplicate rule id %s (also in %s)" % (p, rule_id, seen[rule_id]))
                continue
            seen[rule_id] = p
            inside_bundled = bundled is not None and os.path.abspath(p).startswith(bundled + os.sep)
            out.append(
                Rule(
                    rule_id=rule_id,
                    title=str(doc.get("title", rule_id)),
                    severity=str(doc.get("severity", "medium")),
                    category=str(doc.get("category", "uncategorized")),
                    detection=doc["detection"],
                    description=" ".join(str(doc.get("description", "")).split()),
                    status=str(doc.get("status", "experimental")),
                    tags=[str(t) for t in doc.get("tags", []) or []],
                    path=p,
                    pack=_pack_of(p, bundled if inside_bundled and bundled else target),
                )
            )
    return out


# ---------------------------------------------------------------- matching

def _match_value(op: str, expected: Any, actual: Any) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(_match_value(op, expected, a) for a in actual)
    if isinstance(expected, list) and op != "contains":
        return any(_match_value(op, e, actual) for e in expected)
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
        path, op = _split_key(key)
        if not _match_value(op, expected, ev.get(path)):
            return False
    return True


# ---------------------------------------------------------------- detections

def _eval_selection(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    conds = det["selection"]
    return [[ev] for ev in sess if _event_matches(conds, ev)]


def _eval_sequence(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    """Ordered steps; with ``within_events`` the whole chain spans at most that many seq."""
    steps: List[Dict[str, Any]] = det["sequence"]
    window = det.get("within_events")
    seconds = parse_duration(det["within"]) if det.get("within") is not None else None
    by_end: Dict[int, List[TraceEvent]] = {}
    for start, first in enumerate(sess):
        if not _event_matches(steps[0], first):
            continue
        chain = [first]
        j = start + 1
        for step in steps[1:]:
            found = None
            while j < len(sess):
                ev = sess[j]
                j += 1
                if window is not None and (ev.seq - first.seq) > int(window):
                    break
                if seconds is not None and not _in_time(first, ev, seconds):
                    if _ts_seconds(ev) is not None and _ts_seconds(first) is not None:
                        break
                    continue
                if _event_matches(step, ev):
                    found = ev
                    break
            if found is None:
                chain = []
                break
            chain.append(found)
        if chain:
            # one finding per completing event, anchored on the latest start
            by_end[id(chain[-1])] = chain
    return list(by_end.values())


def _eval_taint(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    spec = det["taint"]
    source_labels = spec["source_label"]
    if not isinstance(source_labels, list):
        source_labels = [source_labels]
    wanted = {str(x).lower() for x in source_labels}
    # rewrite 'sink' / 'sink|matches' keys to address the tool field
    rewritten = {}
    for k, v in spec.items():
        if str(k).split("|", 1)[0] != "sink":
            continue  # also skips source_label and within
        op = k.split("|", 1)[1] if "|" in k else "equals"
        rewritten["tool" if op == "equals" else "tool|%s" % op] = v
    seconds = parse_duration(spec["within"]) if spec.get("within") is not None else None
    source_ev: Optional[TraceEvent] = None
    hits: List[List[TraceEvent]] = []
    for ev in sess:
        if source_ev is not None and seconds is not None and not _in_time(source_ev, ev, seconds):
            source_ev = None  # the source is too old to taint this call
        if source_ev is None and wanted & {str(x).lower() for x in ev.labels}:
            source_ev = ev
            continue
        if source_ev is not None and _event_matches(rewritten, ev):
            hits.append([source_ev, ev])
            source_ev = None  # one finding per source occurrence
    return hits


def _eval_frequency(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    spec = dict(det["frequency"])
    count = int(spec.pop("count", 10))
    group_by = spec.pop("group_by", None)
    if group_by is None and not spec:
        group_by = "tool"  # no conditions: count repeats of the same tool
    matched = [ev for ev in sess if _event_matches(spec, ev)]
    if not group_by:
        return [matched] if len(matched) >= count else []
    groups: Dict[str, List[TraceEvent]] = {}
    for ev in matched:
        groups.setdefault(str(ev.get(str(group_by))), []).append(ev)
    return [evs for _key, evs in sorted(groups.items()) if len(evs) >= count]


def _eval_not_preceded_by(det: Dict[str, Any], sess: List[TraceEvent]) -> List[List[TraceEvent]]:
    """Flag an `event` that has no matching `guard` before it in the session.

    The human-in-the-loop primitive: a high-impact action is a finding unless a
    required guard event (an approval / confirmation) precedes it. With
    `within_events` the guard must fall within that many events before the
    trigger; without it, any earlier guard in the session suppresses the match.
    """
    spec = det["not_preceded_by"]
    event_conds = spec.get("event") or {}
    guard_conds = spec.get("guard") or {}
    window = spec.get("within_events")
    hits: List[List[TraceEvent]] = []
    for idx, ev in enumerate(sess):
        if not _event_matches(event_conds, ev):
            continue
        guarded = False
        for prev in sess[:idx]:
            if window is not None and (ev.seq - prev.seq) > int(window):
                continue
            if guard_conds and _event_matches(guard_conds, prev):
                guarded = True
                break
        if not guarded:
            hits.append([ev])
    return hits


_EVALUATORS = {
    "selection": _eval_selection,
    "sequence": _eval_sequence,
    "taint": _eval_taint,
    "frequency": _eval_frequency,
    "not_preceded_by": _eval_not_preceded_by,
}


def scan(events: List[TraceEvent], rules: List[Rule]) -> List[Finding]:
    """Run every rule over every session; findings sorted most severe first."""
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
                        pack=rule.pack,
                    )
                )
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.session_id, f.events[0].seq))
    return findings
