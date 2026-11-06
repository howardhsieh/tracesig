# TraceSig progress log

One line per daily increment.

- 2026-09-14 — Added the `not_preceded_by` detection operator (human-in-the-loop gaps) and refined TS-PRIV-002 to use it, so approved destructive actions no longer alert. Added two example traces + 3 tests.
- 2026-09-30 — v0.2.0: Claude Code and agent-policy-gateway normalizers, three bundled rule packs (core, claude-code, apg), rules ship in the wheel, new commands (normalize, rules, validate), rule validation, frequency group_by fix, PyPI release workflow.
- 2026-11-06 — Added core rule TS-ANO-004: flags 3+ `secret`-labeled reads in one session as credential harvesting (MITRE ATT&CK T1552). Added firing + benign example traces, 2 tests, README/CHANGELOG. Core pack now 13 rules, 24 total.
