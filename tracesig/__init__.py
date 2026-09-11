"""TraceSig — Sigma-style detection rules for AI agent tool-call traces."""

__version__ = "0.1.0"

from .engine import Finding, Rule, load_rules, scan  # noqa: F401
from .schema import TraceEvent, load_jsonl  # noqa: F401
