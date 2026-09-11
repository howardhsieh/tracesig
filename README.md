# TraceSig

**Sigma-style detection rules for AI agent tool-call traces.**
An open rule format, a reference engine, and a starter rule pack — so a
detection written once runs on any agent.

[![CI](https://github.com/howardhsieh/tracesig/actions/workflows/ci.yml/badge.svg)](https://github.com/howardhsieh/tracesig/actions)
[![PyPI](https://img.shields.io/pypi/v/tracesig)](https://pypi.org/project/tracesig/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

---

## Why

SIEM detection engineering has [Sigma](https://github.com/SigmaHQ/sigma): one
open YAML format for detection rules, and a community rule library everyone
shares. **AI agents have nothing equivalent.** Every agent framework logs
tool calls differently, there's no common rule language, and the products that
watch agent behavior are closed and priced per seat.

TraceSig is the missing open layer:

1. **A trace schema** — normalize any agent's tool-call log to one JSONL shape.
2. **A rule format + engine** — Sigma-style YAML, four detection primitives, a small dependency-light Python engine.
3. **A starter rule pack** — 12 rules for prompt-injection, exfiltration, privilege, and anomaly patterns, ready to run.

Detections are written **by provenance and behavior, not by content filtering** —
so they survive paraphrase and novel payloads.

## Install

```bash
pip install tracesig
```

## Quickstart

```bash
# scan a normalized trace with the bundled rule pack
tracesig scan examples/indirect_exfil.jsonl --rules rules/
```

```
2 finding(s)
============================================================

[CRIT] TS-EXF-001 — Untrusted web content followed by outbound email
  session: s1   category: exfiltration
  timeline:
    #0    web_fetch    https://blog.example.com/post   labels=['web']
    #2    send_email   {"to": "attacker@evil.test", ...}
```

Use it in CI to fail a build when an agent trace trips a critical rule:

```bash
tracesig scan trace.jsonl --rules rules/ --fail-on critical
```

## How a rule looks

```yaml
id: TS-EXF-001
title: Untrusted web content followed by outbound email
severity: critical
category: exfiltration
detection:
  taint:
    source_label: web
    sink|matches: "(send_email|send_message|webhook|http_post)"
```

`taint` is the core agent-security primitive: a source label (`web`, `pii`,
`file`) appears, then a sink fires — the classic indirect prompt-injection
exfiltration chain, caught by data flow rather than keywords. The other three
detection types are `selection`, `sequence`, and `frequency`. Full grammar in
[docs/rule-spec.md](docs/rule-spec.md).

## The trace schema

One normalized event per line (JSONL):

```json
{"session_id":"s1","seq":0,"tool":"web_fetch","args":"https://…","labels":["web"],"result_preview":"…"}
```

`labels` carry data provenance — the signal taint rules run on. Full spec in
[docs/trace-schema.md](docs/trace-schema.md). Provider normalizers (MCP,
OpenAI, Anthropic) land in v0.2; **[agent-policy-gateway](https://github.com/howardhsieh/agent-policy-gateway)**
already emits source labels, so its audit logs normalize directly.

## The rule pack (v0.1)

| ID | Severity | What it catches |
|---|---|---|
| TS-EXF-001 | critical | web → email/webhook (indirect injection exfil) |
| TS-EXF-002 | high | file/secret read → outbound network |
| TS-EXF-003 | high | secret-like token embedded in an outbound URL |
| TS-INJ-001 | high | override phrase in a tool result |
| TS-INJ-002 | high | tool result soliciting credentials |
| TS-INJ-003 | critical | web read → destructive action (short window) |
| TS-INJ-004 | medium | long base64/hex blob in args |
| TS-PRIV-001 | high | permission / role escalation call |
| TS-PRIV-002 | medium | destructive action without prior approval event |
| TS-ANO-001 | medium | tool-call flood (loop / DoS) |
| TS-ANO-002 | high | repeated auth calls (brute force) |
| TS-ANO-003 | high | PII → external recipient (agent DLP) |

## Where this fits

TraceSig is the **detection** layer of an open agent-security stack:

- 🔐 **[agent-policy-gateway](https://github.com/howardhsieh/agent-policy-gateway)** — *prevent* (block tool calls by policy at runtime)
- 🐤 **[llm-canary](https://github.com/howardhsieh/llm-canary)** — *trap* (canary tokens that fire on leak)
- 📡 **TraceSig** — *detect* (rules over the trace, after the fact and in CI)

## Roadmap

- v0.2 — provider normalizers (MCP / OpenAI / Anthropic / APG), `not_preceded_by` operator, cross-session correlation
- v0.3 — shared tool-category taxonomy, rule-testing harness (`tests/` per rule), community rule contributions
- Long-term — a public rule repository, the way SigmaHQ hosts community SIEM rules

Contributions welcome — a rule is a single YAML file. See [docs/rule-spec.md](docs/rule-spec.md).

## License

Apache-2.0. Built by [Howard Hsieh](https://github.com/howardhsieh).
