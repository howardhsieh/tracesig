# Contributing to TraceSig

Rules, normalizers and example traces are all welcome.

## Add a rule

1. Write one YAML file under `rules/<pack>/` (`core` for generic tool names,
   `claude-code`, `apg`, or a new pack folder). Use a new, unique `id` with the
   pack's prefix. The format is in [docs/rule-spec.md](docs/rule-spec.md).
2. Add or extend an example trace under `examples/` that makes the rule fire,
   and make sure the benign examples stay quiet.
3. Add a test in `tests/` that asserts both.
4. Run:

   ```bash
   pip install -e ".[dev]"
   tracesig validate
   pytest -q
   ```

Good rules key on provenance and behavior (what data came from where, what
happened next), explain in `description` why the pattern matters and when it
is legitimate, and cite a reference (OWASP Agentic Top 10, MITRE ATLAS, a
write-up) in `tags` or `references`.

## Add a normalizer

See [docs/normalizers.md](docs/normalizers.md#writing-a-new-normalizer).
Normalizers must not make network calls and must redact credential-looking
values before they reach output.

## Example traces

Never commit real secrets or personal data. Use `example.invalid` domains and
obviously fake tokens.

## Security issues

Report vulnerabilities in TraceSig privately through GitHub's
"Report a vulnerability" button on the Security tab, not in a public issue.
