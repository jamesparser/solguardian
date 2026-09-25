"""SolGuardian command line.

    solguardian analyze samples/solidity/Vault.sol
    solguardian analyze samples/solana/vault
    solguardian analyze samples --out out/samples --html

Runs fully offline. Exit code: 0 unless `--fail-on <severity>` is given and a finding at
or above that severity exists (then 1), which is how it becomes a CI gate after the
hackathon.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .agents.orchestrator import run_pipeline
from .core.detector import all_detectors
from .core.finding import Severity
from .core.scanner import ScanResult, scan
from .core.scorecard import load_expectations, score
from .core.skills import load_skills
from .core.source import build_target
from .report import html_report, json_report, md_report
from .report.pocs import write_pocs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EXPECT = os.path.join(ROOT, "samples", "EXPECTED_FINDINGS.json")


def _resolve_expect(explicit: Optional[str], target_path: str) -> Optional[str]:
    """Find the ground-truth file whether the user pointed at samples/ or one file."""
    for candidate in (
        explicit,
        os.path.join(target_path, "EXPECTED_FINDINGS.json"),
        os.path.join(os.path.dirname(os.path.abspath(target_path)), "EXPECTED_FINDINGS.json"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(target_path))), "EXPECTED_FINDINGS.json"),
        DEFAULT_EXPECT,
    ):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def cmd_analyze(args: argparse.Namespace) -> int:
    target = build_target(args.path)
    if not target.files:
        print("solguardian: no .sol / .rs files found under %s" % args.path, file=sys.stderr)
        return 2

    out_dir = args.out or os.path.join("out", os.path.basename(os.path.abspath(args.path).rstrip("/")))
    os.makedirs(out_dir, exist_ok=True)

    if args.serial:
        result: ScanResult = scan(target)
        agents = None
    else:
        # The CLI runs under a __main__ guard, so `auto` may upgrade to processes on a big repo;
        # library callers keep the conservative, always-safe thread default (agents/pool.py).
        summary = run_pipeline(target, parallel=True, verbose=not args.quiet,
                               workers=args.workers, backend=args.backend,
                               allow_processes=True)
        result = summary.scan_result()
        agents = summary.agents

    card = None
    expect_path = None if args.no_expect else _resolve_expect(args.expect, args.path)
    if expect_path:
        seeded = load_expectations(expect_path)
        if seeded:
            card = score(result.findings, seeded)

    json_path = json_report.write(result, os.path.join(out_dir, "report.json"), card, agents)
    md_path = md_report.write(result, os.path.join(out_dir, "report.md"), card, agents, args.path)
    pocs = write_pocs(result.findings, out_dir)
    html_path = None
    if args.html:
        html_path = os.path.join(out_dir, "report.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_report.build(result, card, target_arg=args.path))

    if not args.quiet:
        _print_summary(result, card, out_dir, json_path, md_path, html_path, pocs)

    if args.fail_on:
        threshold = Severity(args.fail_on)
        if any(f.severity.weight >= threshold.weight for f in result.findings):
            return 1
    return 0


def _print_summary(result, card, out_dir, json_path, md_path, html_path, pocs) -> None:
    findings = result.findings
    print("")
    print("SolGuardian %s - %d file(s), %d lines, %d detector(s) in %.2fs"
          % (__version__, len(result.target.files), result.target.line_count,
             len(set(result.detectors_run)), result.duration_ms / 1000.0))
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    print("findings: %d  (%s)" % (len(findings), ", ".join(
        "%d %s" % (counts[s.value], s.value) for s in Severity.ordered() if counts.get(s.value))))
    print("")
    width = max([len(_short(f.location)) for f in findings] + [12])
    for i, f in enumerate(findings, start=1):
        print("  %-9s %-8s %4.2f  %-*s  %s" % (
            f.severity.value.upper(), f.rule, f.confidence, width, _short(f.location), f.title))
    if card is not None:
        print("")
        print("ground truth: caught %d/%d seeded issues (%.0f%% recall), %d extra unseeded findings"
              % (len(card.caught), len(card.seeded), 100 * card.recall, len(card.unseeded)))
        if card.missed:
            print("  missed: %s" % ", ".join(m.key for m in card.missed))
    print("")
    print("wrote: %s, %s, %d PoC stub(s)%s%s" % (
        json_path, md_path, len(pocs),
        (", " + html_path) if html_path else "", ""))
    print("outputs in: %s" % out_dir)


def _short(text: str) -> str:
    import os as _os

    parts = text.split(":")
    if len(parts) >= 2:
        return "%s:%s" % (_os.path.basename(parts[0]), ":".join(parts[1:]))
    return text


def cmd_list(args: argparse.Namespace) -> int:
    from .agents.adjudicator import Adjudicator
    from .agents.evm_hunter import EvmHunter
    from .agents.report_writer import ReportWriter
    from .agents.solana_hunter import SolanaHunter

    print("agents (the orchestrator fans each hunter out over the files, one worker per shard):")
    for cls in (EvmHunter, SolanaHunter, Adjudicator, ReportWriter):
        ids = ", ".join(getattr(cls, "detector_ids", []) or []) or "-"
        print("  %-16s %-9s %s" % (cls.name, cls.language, ids))
    print("")
    print("detectors:")
    for detector in all_detectors():
        print("%-22s %-9s %-52s skills/%s" % (detector.id, detector.language, detector.label, detector.skill))
    print("")
    skills = load_skills()
    for slug, skill in sorted(skills.items()):
        print("%-28s %-14s %d checklist item(s)  %s"
              % (skill.path, ",".join(skill.applies_to) or "-", len(skill.checklist), skill.title))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """One-command end-to-end demo over the shipped synthetic samples."""
    ns = argparse.Namespace(
        path=os.path.join(ROOT, "samples"),
        out=args.out,
        html=args.html,
        quiet=False,
        serial=False,
        workers=None,
        backend="auto",
        expect=None,
        no_expect=False,
        fail_on=None if args.allow_findings else "critical",
    )
    print("== solguardian analyze samples ==")
    rc = cmd_analyze(ns)
    print("")
    print("exit code %d (%s)" % (
        rc,
        "CI gate tripped on critical findings, which is the point" if rc else "no finding at/above the gate",
    ))
    return rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="solguardian",
        description="Automated exploit hunting for Solidity (EVM / HyperEVM) and Rust (Solana / Anchor).",
    )
    parser.add_argument("--version", action="version", version="SolGuardian %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="scan a file or project directory")
    analyze.add_argument("path", help=".sol file, .rs file, or project directory")
    analyze.add_argument("--out", help="output directory (default: out/<target>)")
    analyze.add_argument("--html", action="store_true", help="also emit a static report.html")
    analyze.add_argument("--quiet", action="store_true", help="no console table")
    analyze.add_argument("--serial", action="store_true", help="skip the parallel agent pipeline")
    analyze.add_argument("--workers", type=int, default=None, metavar="N",
                        help="parallel agent instances (default: auto = min(files, CPUs))")
    analyze.add_argument("--backend", choices=("auto", "threads", "processes"), default="auto",
                        help="how shards run: threads (default) or processes (faster on large "
                             "repos; requires a __main__ guard when driven from Python)")
    analyze.add_argument("--expect", help="path to EXPECTED_FINDINGS.json (ground truth)")
    analyze.add_argument("--no-expect", action="store_true", help="disable ground-truth scoring")
    analyze.add_argument("--fail-on", choices=[s.value for s in Severity.ordered()],
                        help="exit 1 if any finding is at or above this severity (CI gate)")
    analyze.set_defaults(func=cmd_analyze)

    listing = sub.add_parser("list", help="list detectors and skill packs")
    listing.set_defaults(func=cmd_list)

    demo = sub.add_parser("demo", help="end-to-end run over the shipped samples")
    demo.add_argument("--out", default=os.path.join("out", "demo"))
    demo.add_argument("--html", action="store_true")
    demo.add_argument("--allow-findings", action="store_true",
                      help="always exit 0 (default behaviour exits 1 to show the CI gate working)")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
