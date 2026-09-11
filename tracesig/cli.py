"""TraceSig CLI.

    tracesig scan trace.jsonl --rules rules/
    tracesig scan trace.jsonl --rules rules/ --json
"""

from __future__ import annotations

import argparse
import sys

from .engine import load_rules, scan
from .report import to_json, to_text
from .schema import load_jsonl


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="tracesig", description="Detection rules for AI agent tool-call traces")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a normalized JSONL trace with a rule pack")
    p_scan.add_argument("trace", help="Path to trace .jsonl")
    p_scan.add_argument("--rules", required=True, help="Rules directory")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.add_argument("--fail-on", default=None, choices=["critical", "high", "medium", "low"],
                        help="Exit non-zero if any finding at or above this severity (for CI)")

    args = parser.parse_args(argv)

    events = load_jsonl(args.trace)
    rules = load_rules(args.rules)
    findings = scan(events, rules)

    print(to_json(findings) if args.json else to_text(findings))

    if args.fail_on:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = order[args.fail_on]
        if any(order.get(f.severity, 9) <= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
