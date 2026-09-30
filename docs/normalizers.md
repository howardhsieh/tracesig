# Normalizers

A normalizer turns an agent's native log into TraceSig events. `tracesig scan`
and `tracesig normalize` pick one per file automatically; `--from` forces one.

```bash
tracesig normalize ~/.claude/projects/ -o trace.jsonl   # inspect what rules see
tracesig scan ~/.claude/projects/ --session <id>         # one session only
```

## Claude Code (`claude-code`)

**Inputs.** Session transcripts in `~/.claude/projects/<project>/<session>.jsonl`,
and OpenTelemetry log exports (OTLP/JSON from a Collector file exporter, or
flat JSON lines that carry `event.name`).

**Events.** One per `tool_use` block (transcripts) or `tool_result` event
(OTel), ordered by timestamp within each session. The transcript's matching
`tool_result` fills `result_preview` (first 300 characters). `agent` is
`claude-code`; `raw.tool_use_id`, `raw.raw_tool`, `raw.is_sidechain`,
`raw.cwd` and `raw.is_error` are kept.

**Labels.**

| Tool | Labels |
|---|---|
| WebFetch, WebSearch | `web`, `untrusted` |
| `mcp__*` | `mcp`, `untrusted` |
| Read, Grep, Glob, NotebookRead | `file`, plus `secret` for credential-looking paths (`.env`, SSH keys, `~/.aws/credentials`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.pem`/`.key`, GitHub CLI, Docker and kube config) |
| Bash, PowerShell | `secret` when the command touches such a path |

**Tool names.** Bash and PowerShell calls get a category suffix so rules can
match intent: `Bash(network)` (curl, wget, nc, scp, ssh, rsync to a host,
`Invoke-WebRequest`, Python one-liners with urllib/requests/socket),
`Bash(publish)` (git push, npm/cargo/gem/docker publish or push, twine upload,
`gh release create`, `gh pr create`), `Bash(destructive)` (`rm -rf`,
`git reset --hard`, `git clean -f`, force push, DROP TABLE, `kubectl delete`,
`terraform destroy`), `Bash(install)` (package installs and `curl | sh`).

**Privacy.** Credential-looking values (API keys, tokens, private keys, URL
passwords, `curl -u`, `--password`) are redacted in `args` and
`result_preview` before rules or output see them. Nothing is sent anywhere.

## agent-policy-gateway (`apg`)

**Input.** `apg audit export <audit.jsonl> --format tracesig -o trace.jsonl`,
schema `apg-audit-trace`, `schema_version` 1. An unknown version is an error.

**Events.** One per gateway decision. `tool`, `args`, `ts`, `agent` and `seq`
map directly; every exported field stays available as `raw.<field>`, notably
`raw.verdict` (`allow`, `deny`, `review`, `redact`), `raw.flagged`,
`raw.rule`, `raw.reason`, `raw.input_untrusted`, `raw.input_secret` and
`raw.declassified_by`.

**Session.** The event's `session_id` when APG exported one; otherwise the
file name plus the agent id.

**Labels.** The event's `labels` when APG exported them; otherwise the names
in the call's *output* label (`output_sources`, `output_confidentiality`,
`output_integrity`), plus `untrusted` when the output carries any integrity
taint. Output labels describe what the tool returned, which is what taint
rules need: the call that brought web content in is the source, and a later
sink is the finding, whether or not APG blocked it (the timeline shows the
verdict).

## Writing a new normalizer

Produce dicts with at least `session_id`, `seq` and `tool`; add `labels`
wherever you know where data came from. Put it in `tracesig/normalize/`, teach
`detect_format` to recognize the input, and add an example trace plus a test
under `tests/`.
