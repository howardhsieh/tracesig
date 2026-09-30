"""TraceSig command line.

    tracesig scan ~/.claude/projects/                 # Claude Code sessions
    tracesig scan apg-trace.jsonl                     # agent-policy-gateway export
    tracesig scan trace.jsonl --rules my-rules/ --fail-on high
    tracesig normalize ~/.claude/projects/ -o trace.jsonl
    tracesig rules
    tracesig validate my-rules/
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .engine import SEVERITY_ORDER, RuleError, available_packs, load_rules, pack_dirs, scan
from .normalize import FORMATS, load_events, to_jsonl
from .report import to_json, to_text

# Which bundled packs run when neither --rules nor --pack is given.
DEFAULT_PACKS = {"tracesig": ["core"], "apg": ["core", "apg"], "claude-code": ["claude-code"]}
FAIL_CHOICES = ["critical", "high", "medium", "low"]


def _err(msg: str) -> None:
    sys.stderr.write("tracesig: error: %s\n" % msg)


def _select_rules(args: argparse.Namespace, formats: List[str]):
    targets: List[str] = list(args.rules or [])
    packs: List[str] = list(args.pack or [])
    if not targets and not packs:
        for fmt in formats or ["tracesig"]:
            packs.extend(DEFAULT_PACKS.get(fmt, ["core"]))
    targets.extend(pack_dirs(dict.fromkeys(packs)))
    return load_rules(targets), packs


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        events, stats = load_events(args.trace, fmt=args.source, session=args.session)
        rules, packs = _select_rules(args, stats["formats"])
    except FileNotFoundError as exc:
        _err("not found: %s" % exc)
        return 1
    except (RuleError, ValueError) as exc:
        _err(str(exc))
        return 1
    findings = scan(events, rules)
    if args.min_severity:
        limit = SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 9) <= limit]
    sys.stdout.write(to_json(findings) + "\n" if args.json else to_text(findings))
    sys.stderr.write("tracesig %s: %d file(s), %d event(s) in %d session(s) [%s]; %d rule(s)%s\n" % (
        __version__, stats["files"], stats["events"], stats["sessions"], ", ".join(stats["formats"]) or "no events",
        len(rules), (" from pack(s) " + ", ".join(dict.fromkeys(packs))) if packs else ""))
    if stats["skipped_files"]:
        sys.stderr.write("tracesig: skipped %d file(s) in an unknown format (use --from to force one)\n"
                         % len(stats["skipped_files"]))
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings):
            return 2
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    try:
        events, stats = load_events(args.inputs, fmt=args.source, session=args.session)
    except FileNotFoundError as exc:
        _err("not found: %s" % exc)
        return 1
    except ValueError as exc:
        _err(str(exc))
        return 1
    text = to_jsonl(events)
    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    sys.stderr.write("tracesig: %d file(s) [%s] -> %d event(s) in %d session(s)\n" % (
        stats["files"], ", ".join(stats["formats"]) or "none", stats["events"], stats["sessions"]))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    try:
        targets = list(args.rules or []) + pack_dirs(args.pack or ([] if args.rules else ["all"]))
        rules = load_rules(targets)
    except (RuleError, FileNotFoundError) as exc:
        _err(str(exc))
        return 1
    if args.json:
        sys.stdout.write(json.dumps([{"id": r.rule_id, "pack": r.pack, "severity": r.severity, "category": r.category,
                                      "title": r.title, "status": r.status, "tags": r.tags} for r in rules],
                                    indent=2) + "\n")
        return 0
    for r in sorted(rules, key=lambda r: (r.pack, r.rule_id)):
        sys.stdout.write("%-12s %-12s %-9s %s\n" % (r.pack, r.rule_id, r.severity, r.title))
    sys.stdout.write("%d rule(s); packs: %s\n" % (len(rules), ", ".join(available_packs())))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    targets = args.paths or pack_dirs(["all"])
    try:
        rules = load_rules(targets, strict=True)
    except (RuleError, FileNotFoundError) as exc:
        _err(str(exc))
        return 1
    sys.stdout.write("%d rule(s) valid\n" % len(rules))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tracesig", description="Sigma-style detection rules for AI agent tool-call traces")
    parser.add_argument("--version", action="version", version="tracesig %s" % __version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="scan traces (files or directories) with detection rules")
    p_scan.add_argument("trace", nargs="+", help="trace files or directories (TraceSig JSONL, APG export, Claude Code transcripts or OTel)")
    p_scan.add_argument("--rules", action="append", metavar="PATH", help="rule file or directory (repeatable)")
    p_scan.add_argument("--pack", action="append", metavar="NAME",
                        help="bundled rule pack: core, claude-code, apg or all (repeatable; default: chosen from the trace format)")
    p_scan.add_argument("--from", dest="source", choices=FORMATS, default="auto", help="input format (default: auto-detect per file)")
    p_scan.add_argument("--session", help="only scan this session id")
    p_scan.add_argument("--min-severity", choices=FAIL_CHOICES, help="hide findings below this severity")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.add_argument("--fail-on", default=None, choices=FAIL_CHOICES,
                        help="exit 2 if any finding is at or above this severity (for CI)")
    p_scan.set_defaults(func=cmd_scan)

    p_norm = sub.add_parser("normalize", help="convert traces to the TraceSig schema (JSONL)")
    p_norm.add_argument("inputs", nargs="+", help="files or directories")
    p_norm.add_argument("--from", dest="source", choices=FORMATS, default="auto", help="input format (default: auto-detect)")
    p_norm.add_argument("--session", help="only keep this session id")
    p_norm.add_argument("-o", "--output", help="output file (default: stdout)")
    p_norm.set_defaults(func=cmd_normalize)

    p_rules = sub.add_parser("rules", help="list rules")
    p_rules.add_argument("--pack", action="append", metavar="NAME", help="bundled pack to list (default: all)")
    p_rules.add_argument("--rules", action="append", metavar="PATH", help="rule file or directory")
    p_rules.add_argument("--json", action="store_true", help="JSON output")
    p_rules.set_defaults(func=cmd_rules)

    p_val = sub.add_parser("validate", help="check rule files (default: the bundled packs)")
    p_val.add_argument("paths", nargs="*", help="rule files or directories")
    p_val.set_defaults(func=cmd_validate)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
