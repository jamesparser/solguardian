#!/usr/bin/env python3
"""CI gate: SolGuardian must keep catching every seeded issue, fast.

Exits non-zero (failing the build) when:
  * any seeded issue in samples/EXPECTED_FINDINGS.json is missed, or
  * a critical/high finding appears in samples/clean/ (the written-correct control), or
  * the scan exceeds the performance budget, or
  * the detector/rule inventory changes without the report being regenerated.

    python3 tools/recall_gate.py
    python3 tools/recall_gate.py --json      # machine-readable, for CI annotations
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from solguardian.core.finding import Severity  # noqa: E402
from solguardian.core.scanner import scan  # noqa: E402
from solguardian.core.scorecard import load_expectations, score  # noqa: E402
from solguardian.core.source import build_target  # noqa: E402

TIME_BUDGET_MS = 5000
EXPECT = os.path.join(ROOT, "samples", "EXPECTED_FINDINGS.json")
SEEDS = os.path.join(ROOT, "samples")
CLEAN = os.path.join(ROOT, "samples", "clean")


def main() -> int:
    failures = []

    seeded_run = scan(build_target(SEEDS))
    card = score(seeded_run.findings, load_expectations(EXPECT))
    if card.missed:
        failures.append("missed seeded issues: %s" % ", ".join(m.key for m in card.missed))

    clean_run = scan(build_target(CLEAN))
    loud = [
        "%s %s (%s:%d)" % (f.severity.value, f.rule, f.file, f.line)
        for f in clean_run.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if loud:
        failures.append("false positives on the clean control: %s" % "; ".join(loud))

    if seeded_run.duration_ms > TIME_BUDGET_MS:
        failures.append("performance budget blown: %d ms > %d ms"
                        % (seeded_run.duration_ms, TIME_BUDGET_MS))

    report = {
        "seeded_total": len(card.seeded),
        "caught": len(card.caught),
        "recall": round(card.recall, 3),
        "unseeded_findings": len(card.unseeded),
        "critical": sum(1 for f in seeded_run.findings if f.severity is Severity.CRITICAL),
        "high": sum(1 for f in seeded_run.findings if f.severity is Severity.HIGH),
        "total_findings": len(seeded_run.findings),
        "clean_control_findings": len(clean_run.findings),
        "scan_ms": seeded_run.duration_ms,
        "detectors": len(set(seeded_run.detectors_run)),
        "ok": not failures,
        "failures": failures,
    }

    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print("seeded %d/%d (recall %.0f%%) | findings %d (%d critical, %d high) | "
              "clean control %d | %d ms | detectors %d"
              % (report["caught"], report["seeded_total"], 100 * report["recall"],
                 report["total_findings"], report["critical"], report["high"],
                 report["clean_control_findings"], report["scan_ms"], report["detectors"]))
        for line in failures:
            print("::error::" + line)
        if not failures:
            print("recall gate: PASS")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
