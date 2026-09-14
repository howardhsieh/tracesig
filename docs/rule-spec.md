# TraceSig rule specification (v0.1)

A rule is a YAML document. Metadata fields describe it; the `detection` block
says what to match. One detection type per rule.

## Metadata

| field | required | notes |
|---|---|---|
| `id` | yes | stable identifier, `TS-<CAT>-NNN` |
| `title` | yes | one line |
| `severity` | yes | `critical` \| `high` \| `medium` \| `low` \| `informational` |
| `category` | yes | `injection` \| `exfiltration` \| `privilege` \| `anomaly` |
| `description` | no | what and why |
| `status` | no | `experimental` \| `stable` (default `experimental`) |
| `tags` | no | free-form, e.g. `owasp-llm01` |
| `references` | no | URLs |

## Fields you can match

Addressed by dotted path: `tool`, `args`, `labels`, `result_preview`, `agent`,
`ts`, `session_id`, `seq`, and `raw.<key>` for anything the normalizer kept.

## Operators

Append `|<op>` to a field name:

- *(none)* — case-insensitive equality
- `|contains` — substring (or any-of, if given a list)
- `|matches` — regex (case-insensitive)

List-valued fields (like `labels`) match if **any** element matches.

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
```yaml
detection:
  taint:
    source_label: web
    sink|matches: "(send_email|webhook)"
```

### frequency
An event matching the given conditions repeats `count`+ times in one session.
Omit conditions (except `count`) to count repeats of the *same* tool.
```yaml
detection:
  frequency:
    tool|matches: "login"
    count: 5
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

## Roadmap (v0.2+)
cross-session correlation, a shared taxonomy of tool categories, and provider normalizers
(MCP, OpenAI, Anthropic, agent-policy-gateway).
