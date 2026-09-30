"""TraceSig — Sigma-style detection rules for AI agent tool-call traces."""

__version__ = "0.2.1"

from .engine import Finding, Rule, RuleError, load_rules, scan, validate_rule  # noqa: F401
from .normalize import load_events  # noqa: F401
from .schema import TraceEvent, load_jsonl  # noqa: F401
