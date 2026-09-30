# Changelog

All notable changes to TraceSig are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-30

### Added

- **Claude Code normalizer**: `tracesig scan ~/.claude/projects/` reads
  session transcripts and OpenTelemetry exports directly, with provenance
  labels (`web`, `untrusted`, `mcp`, `file`, `secret`), intent-suffixed shell
  tool names (`Bash(network)`, `Bash(publish)`, …) and credential redaction.
- **agent-policy-gateway normalizer**: `apg audit export --format tracesig`
  output is detected and mapped, keeping the gateway's verdicts as
  `raw.verdict`.
- Rule packs: `core` (the 12 original rules), `claude-code` (7 rules) and
  `apg` (4 rules). The packs ship inside the package, so `tracesig scan`
  works after `pip install` with no `--rules`. The pack is chosen from the
  trace format; `--pack` overrides.
- Commands: `tracesig normalize`, `tracesig rules`, `tracesig validate`,
  `tracesig --version`, and `python -m tracesig`.
- `scan` accepts several files and directories, `--from`, `--session`,
  `--min-severity`; JSON output includes a severity summary and the pack.
- Rule validation (`validate_rule`, strict loading): required fields,
  severities, operators, regexes, windows, duplicate ids.
- `frequency` supports `group_by`; `taint` accepts a list of source labels;
  a list of expected values means "any of".
- Release workflow that publishes to PyPI with trusted publishing when the
  version changes on `main`.

### Changed

- Bundled rules moved to `rules/core/`; `--rules rules/` still loads them all.
- `sequence` reports one finding per completing event and applies the
  `within_events` window while matching, so a later start inside the window
  is found even when an earlier start was too far away.

### Fixed

- `frequency` with no conditions counted every tool call in the session;
  it now counts repeats of the same tool, as the rule spec says. TS-ANO-001
  no longer fires on any long session.
- Taint source labels compare case-insensitively.
- TS-INJ-002 also catches "paste/share/provide your API key, token, secret"
  phrasing, not only "send".

## [0.1.0] - 2026-09-11 (untagged)

- Initial release: trace schema, rule format, engine with selection,
  sequence, taint and frequency detections (not_preceded_by added
  2026-09-14), and 12 starter rules.

[Unreleased]: https://github.com/howardhsieh/tracesig/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/howardhsieh/tracesig/compare/470b403...v0.2.0
[0.1.0]: https://github.com/howardhsieh/tracesig/commit/470b403
