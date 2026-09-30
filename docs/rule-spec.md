# TraceSig rule specification (v0.2)

A rule is a YAML document. Metadata fields describe it; the `detection` block
says what to match. One detection type per rule.

## Metadata

| field | required | notes |
|---|---|---|
| `id` | yes | stable, unique identifier: `TS-<CAT>-NNN` (core), `CC-…` (claude-code), `APG-…` (apg), your own prefix for local rules |
| `title` | yes | one line |
| `severity` | yes | `critical` \| `high` \| `medium` \| `low` \| `informational` |
| `category` | yes | `injection` \| `exfiltration` \| `privilege` \| `anomaly` (free text is allowed) |
| `description` | no | what and why |
| `status` | no | `experimental` \| `stable` (default `experimental`) |
| `tags` | no | free-form, e.g. `owasp-llm01` |
| `references` | no | URLs |

## Fields you can match

Addressed by dotted path: `tool`, `args`, `labels`, `result_preview`, `agent`,
`ts`, `session_id`, `seq`, and `raw.<key>` for anything the normalizer kept
(for example `raw.verdict` on agent-policy-gateway events, or
`raw.is_sidechain` on Claude Code events). Nested keys use more dots:
`raw.args.to`.

## Operators

Append `|<op>` to a field name:

- *(none)* — case-insensitive equality
- `|contains` — substring (or any-of, if given a list)
- `|matches` — regex (case-insensitive)

List-valued fields (like `labels`) match if **any** element matches. A list
as the expected value means any of them (`tool: [send_email, send_sms]`).
Booleans compare as text, so `raw.flagged: true` works.

## Detection types

### selection
All conditions match a single event.
```yaml
detection:
  selection:
    tool|matches: "(http_get|fetch)"
    args|matches: "sk-[A-Za-z0-9]{16,}"
```

### sequence
Ordered steps within one session; optional `within_events` window (max seq gap
between first and last step).
```yaml
detection:
  sequence:
    - tool|matches: "web_fetch"
    - tool|matches: "(delete|deploy)"
  within_events: 3
```

### taint
A `source_label` appears on some event, then a later event matches the `sink`
condition — provenance-based, the core agent-security primitive.
`source_label` may be a list (any of them). The sink addresses the `tool`
field.
```yaml
detection:
  taint:
    source_label: web
    sink|matches: "(send_email|webhook)"
```

### frequency
Events matching the given conditions repeat `count`+ times in one session.
`group_by: <field>` counts each value of that field separately. With no
conditions (only `count`), repeats of the *same* tool are counted
(`group_by: tool` is implied).
```yaml
detection:
  frequency:
    tool|matches: "login"
    count: 5
    group_by: args      # optional: 5 attempts against the same account
```

### not_preceded_by
An `event` is a finding **unless** a matching `guard` event occurred earlier in
the same session — the human-in-the-loop primitive. Optional `within_events`
requires the guard to fall within that many events before the trigger; omit it
and any earlier guard in the session suppresses the match.
```yaml
detection:
  not_preceded_by:
    event:
      tool|matches: "(delete|transfer_funds|deploy)"
    guard:
      tool|matches: "(human_approval|approve|confirm)"
    within_events: 5   # optional
```

## Packs and validation

Bundled rules live in `rules/<pack>/` (`core`, `claude-code`, `apg`) and ship
inside the Python package. `tracesig validate DIR` checks rule files the way
the loader does in strict mode: required fields, a known severity, exactly one
detection type, known operators, regexes that compile, integer windows, and
unique ids. Run it in CI for your own rule folders.

## Roadmap (v0.3+)
Time windows (`within: 10m`), cross-session correlation, a shared taxonomy of
tool categories, more normalizers (OpenAI Agents SDK, LangGraph, MCP gateway
logs), SARIF and Sigma export.
