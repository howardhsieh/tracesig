# Example traces

| Path | Format | What it shows |
|---|---|---|
| `indirect_exfil.jsonl` | tracesig | web page with an injection → contacts read → email to the attacker |
| `agent_loop.jsonl` | tracesig | a runaway loop calling the same tool |
| `approved_delete.jsonl`, `unapproved_delete.jsonl` | tracesig | a destructive call with and without a prior approval |
| `benign.jsonl` | tracesig | a normal research session (must stay quiet) |
| `claude-code/*.jsonl` | Claude Code transcripts | one session per Claude Code rule, plus `benign.jsonl` |
| `claude-code/otel-export.json` | Claude Code OpenTelemetry (OTLP/JSON) | the same tool events as telemetry |
| `apg/*.tracesig.jsonl` | agent-policy-gateway export | a benign session, a denied injection, and a laundering chain through a declassifier |

All data is synthetic: `example.invalid` domains and fake tokens only.

```bash
tracesig scan examples/claude-code/
tracesig scan examples/apg/
tracesig scan examples/ --pack all
```
