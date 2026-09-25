"""Run the hunters in parallel, then hand off to the report writer.

This mirrors the Bob IDE task shape: one orchestrator, two specialist subagents working at
the same time, one writer that turns their findings into the deliverable.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..core.detector import all_detectors
from ..core.finding import Finding, Severity
from ..core.scanner import ScanResult, dedupe, finalize
from ..core.source import Target, detect_chain
from .base import AgentResult
from .evm_hunter import EvmHunter
from .report_writer import ReportWriter
from .solana_hunter import SolanaHunter


@dataclass
class RunSummary:
    findings: List[Finding] = field(default_factory=list)
    agents: List[AgentResult] = field(default_factory=list)
    duration_ms: int = 0
    files: int = 0
    lines: int = 0
    detectors: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "files_scanned": self.files,
            "lines_scanned": self.lines,
            "detectors_available": self.detectors,
            "duration_ms": self.duration_ms,
            "findings_total": len(self.findings),
            "by_severity": {s.value: sum(1 for f in self.findings if f.severity is s) for s in Severity.ordered()},
            "by_chain": _by_chain(self.findings),
            "agents": [a.to_dict() for a in self.agents],
        }


def _by_chain(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        key = f.chain or "unknown"
        out[key] = out.get(key, 0) + 1
    return out


def run_pipeline(target: Target, parallel: bool = True, verbose: bool = True) -> RunSummary:
    started = time.time()
    detectors = all_detectors()
    hunters = [EvmHunter(detectors), SolanaHunter(detectors)]
    results: List[AgentResult] = []

    log = lambda msg: print(msg) if verbose else None
    log("[orchestrator] target=%s kind=%s files=%d lines=%d" % (target.root, target.kind, len(target.files), target.line_count))
    log("[orchestrator] dispatching %d subagents (%s)" % (len(hunters), "parallel" if parallel else "serial"))

    if parallel and len(hunters) > 1:
        with ThreadPoolExecutor(max_workers=len(hunters)) as pool:
            futures = {pool.submit(h.run, target.files): h for h in hunters}
            for future in as_completed(futures):
                hunter = futures[future]
                res = future.result()
                results.append(res)
                for line in res.log:
                    log("[%s] %s" % (hunter.name, line))
    else:
        for hunter in hunters:
            res = hunter.run(target.files)
            results.append(res)
            for line in res.log:
                log("[%s] %s" % (hunter.name, line))

    findings = [f for res in results for f in res.findings]
    for f in findings:
        if not f.chain:
            f.chain = detect_chain(f.file, "")
    findings = finalize(dedupe(findings))

    writer = ReportWriter(detectors)
    write_result = writer.run(findings)
    results.append(write_result)
    for line in write_result.log:
        log("[report-writer] %s" % line)

    summary = RunSummary(
        findings=findings,
        agents=results,
        duration_ms=int((time.time() - started) * 1000),
        files=len(target.files),
        lines=target.line_count,
        detectors=len(detectors),
    )
    log("[orchestrator] done: %d findings in %d ms" % (len(findings), summary.duration_ms))
    return summary
