# TraceSig trace schema (v0.1)

A **trace** is a JSONL file — one JSON object per line, one object per tool
call the agent made, in order. This is the normalized shape rules run against.
The goal is the same one Sigma achieved for logs: *write the detection once,
run it on any agent's trace.*

## Event fields

| field | type | required | meaning |
|---|---|---|---|
| `session_id` | string | yes | groups events from one agent run/conversation |
| `seq` | int | yes | order within the session (0-based) |
| `tool` | string | yes | tool/function name the agent invoked |
| `args` | string \| object | no | arguments (objects are canonicalized to a sorted-key JSON string) |
| `labels` | string[] | no | data-provenance labels attached to this event: `web`, `pii`, `file`, `secret`, `untrusted`, … |
| `result_preview` | string | no | first N chars of the tool's result (where injection payloads land) |
| `ts` | string | no | ISO-8601 timestamp |
| `agent` | string | no | agent or model identifier |

Any other keys are preserved under `raw.` and addressable by rules.

## Example line
```json
{"session_id":"s1","seq":2,"tool":"send_email","args":{"to":"x@evil.test"},"labels":[],"result_preview":"","ts":"2026-09-11T10:00:00Z"}
```

## Where labels come from
Labels are the heart of provenance detection. A normalizer assigns them:
`web`/`untrusted` for anything fetched from the open internet, `pii` when a
tool returns personal data, `file`/`secret` for local reads. TraceSig ships a
generic loader in v0.1; **agent-policy-gateway already emits source labels in
its audit log**, so its logs normalize directly — the two projects compose.

## Normalizers (roadmap, v0.2)
`tracesig.normalize.mcp`, `.openai`, `.anthropic`, `.apg` — each maps a
provider's native tool-call log onto this schema so the same rule pack runs
everywhere.
