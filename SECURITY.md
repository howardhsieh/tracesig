# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories: open the
repository's **Security** tab and select **Report a vulnerability**
(<https://github.com/howardhsieh/tracesig/security/advisories/new>). Do not
open a public issue for a vulnerability.

Include the affected version or commit, the input that triggers the problem
(synthetic data only, never real credentials or personal data), and what
happens. You can expect an acknowledgement within 7 days. Fixes ship as a new
release and are credited in the release notes unless you prefer otherwise.

## Scope

- **The engine and normalizers**: crafted traces or rule files that cause code
  execution, file access outside the given paths, network access, unbounded
  resource use, or credential values reaching output unredacted.
- **Rule packs**: a bundled rule that can be trivially evaded in a way its
  description does not admit, or that fires on common benign activity.

TraceSig is a detection aid, not a guarantee: rules match patterns in what the
agent logged. An attacker who controls the logs, or behavior no rule
describes, is out of scope; new rules for such behavior are welcome as normal
pull requests.

## Supported versions

Only the latest release receives fixes.
