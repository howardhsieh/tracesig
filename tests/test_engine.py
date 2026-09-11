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
    known = {"selection", "sequence", "taint", "frequency"}
    for r in rules:
        assert r.rule_id.startswith("TS-")
        assert known & set(r.detection.keys())
