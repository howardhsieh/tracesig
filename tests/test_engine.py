import os

from tracesig import load_jsonl, load_rules, scan

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
RULES = os.path.join(ROOT, "rules")
EX = os.path.join(ROOT, "examples")


def _scan(name):
    events = load_jsonl(os.path.join(EX, name))
    return scan(events, load_rules(RULES))


def test_indirect_exfil_flagged():
    findings = _scan("indirect_exfil.jsonl")
    ids = {f.rule_id for f in findings}
    # web->email taint and the instruction-in-result rule must both fire
    assert "TS-EXF-001" in ids
    assert "TS-INJ-001" in ids
    # PII -> external recipient too
    assert "TS-ANO-003" in ids
    assert any(f.severity == "critical" for f in findings)


def test_benign_is_quiet():
    findings = _scan("benign.jsonl")
    # no exfil / injection / privilege findings on a clean research session
    assert all(f.category not in ("exfiltration", "injection", "privilege") for f in findings), \
        [f.rule_id for f in findings]


def test_loop_flagged():
    findings = _scan("agent_loop.jsonl")
    assert "TS-ANO-001" in {f.rule_id for f in findings}


def test_rules_all_load():
    rules = load_rules(RULES)
    assert len(rules) >= 12
    # every rule has a stable-looking id and a known detection type
    known = {"selection", "sequence", "taint", "frequency", "not_preceded_by"}
    for r in rules:
        assert r.rule_id.startswith("TS-")
        assert known & set(r.detection.keys())


def test_not_preceded_by_fires_without_approval():
    findings = _scan("unapproved_delete.jsonl")
    assert "TS-PRIV-002" in {f.rule_id for f in findings}


def test_not_preceded_by_quiet_with_approval():
    findings = _scan("approved_delete.jsonl")
    assert "TS-PRIV-002" not in {f.rule_id for f in findings}


def test_not_preceded_by_window_bounds_guard():
    from tracesig.engine import Rule, scan
    from tracesig.schema import TraceEvent

    rule = Rule(
        rule_id="TS-TEST-NPB",
        title="window test",
        severity="low",
        category="privilege",
        detection={
            "not_preceded_by": {
                "event": {"tool|matches": "delete"},
                "guard": {"tool|matches": "approve"},
                "within_events": 2,
            }
        },
    )
    # approval too far back (seq gap 5 > 2) -> still a finding
    far = [
        TraceEvent(session_id="a", seq=0, tool="approve"),
        TraceEvent(session_id="a", seq=5, tool="delete_file"),
    ]
    assert len(scan(far, [rule])) == 1
    # approval within the window (seq gap 1) -> suppressed
    near = [
        TraceEvent(session_id="b", seq=0, tool="approve"),
        TraceEvent(session_id="b", seq=1, tool="delete_file"),
    ]
    assert len(scan(near, [rule])) == 0
