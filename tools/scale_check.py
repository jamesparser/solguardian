#!/usr/bin/env python3
"""Scaling check for the multi-agent pipeline: threads vs processes vs serial.

Builds a throwaway corpus by replicating a sample contract N times, runs the same scan under
each backend, and asserts they all produce **identical** findings (same ids, rules, locations,
grades). That equivalence - not the timing - is the point: sharding must not change the report.

    python3 tools/scale_check.py                 # 12 files, 3 backends
    python3 tools/scale_check.py --files 40

The `__main__` guard below is mandatory, not ceremony: on macOS/Windows the process backend uses
`spawn`, which re-imports this file in every child. Callers that drive run_pipeline from Python
need the same guard, which is why the process backend is opt-in.
"""

from __future__ import annotations

import argparse
import os
import shutil
import statistics
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from solguardian.agents.orchestrator import run_pipeline  # noqa: E402
from solguardian.core.source import build_target  # noqa: E402

SEED_FILE = os.path.join(ROOT, "samples", "solidity", "Vault.sol")


def make_corpus(tmp: str, count: int) -> str:
    with open(SEED_FILE, "r", encoding="utf-8") as fh:
        text = fh.read()
    for i in range(count):
        # rename the contract per copy so nothing looks like a duplicate-symbol collision
        with open(os.path.join(tmp, "Vault%03d.sol" % i), "w", encoding="utf-8") as fh:
            fh.write(text.replace("contract Vault {", "contract Vault%03d {" % i))
    return tmp


def fingerprint(findings):
    return [(f.id, f.rule, f.file, f.line, f.severity.value, round(f.confidence, 3))
            for f in findings]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=12)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--repeats", type=int, default=1,
                    help="repeat each backend and report the median (timings are noisy; a single "
                         "run of this on an 8-core machine varied by ~2x during development)")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="solguardian-scale-")
    try:
        make_corpus(tmp, args.files)
        target = build_target(tmp)
        print("corpus: %d files, %d lines  (python %s, %d cpu core(s))"
              % (len(target.files), target.line_count, sys.version.split()[0],
                 __import__("os").cpu_count() or 0))
        baseline = None
        serial_median = None
        runs = [("serial", dict(parallel=False)),
                ("threads", dict(workers=args.workers, backend="threads")),
                ("processes", dict(workers=args.workers, backend="processes"))]
        for label, kwargs in runs:
            samples = []
            for _ in range(max(1, args.repeats)):
                summary = run_pipeline(target, verbose=False, **kwargs)
                samples.append(summary.duration_ms)
                fp = fingerprint(summary.findings)
                if baseline is None:
                    baseline = fp
                elif fp != baseline:
                    print("  %-10s **DIFFERENT FINDINGS** - parallelism changed the report!" % label)
                    return 1
            median = statistics.median(samples)
            agents = len([a for a in summary.agents if "hunter" in a.agent])
            if label == "serial":
                serial_median = median
                speedup = "reference"
            else:
                speedup = "%.1fx" % (serial_median / median) if median else "n/a"
            print("  %-10s %2d hunter(s)  %4d findings  median %6.0f ms  ids=IDENTICAL  %s"
                  % (label, agents, len(summary.findings), median, speedup))
            if args.repeats > 1:
                print("               runs: %s" % ", ".join(str(int(s)) for s in samples))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
