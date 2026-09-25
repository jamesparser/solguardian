"""Scan orchestration: run every registered detector over a target and rank the output."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .detector import Detector, all_detectors
from .finding import Finding, Severity
from .source import Target, detect_chain


@dataclass
class ScanResult:
    target: Target
    findings: List[Finding] = field(default_factory=list)
    detectors_run: List[str] = field(default_factory=list)
    duration_ms: int = 0
    per_file: Dict[str, int] = field(default_factory=dict)
    #: agent runs when the work came from the multi-agent pipeline (empty for serial scan())
    agents: List[object] = field(default_factory=list)
    workers: int = 1

    @property
    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {s.value: 0 for s in Severity.ordered()}
        for f in self.findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    def by_chain(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.chain or "unknown"] = out.get(f.chain or "unknown", 0) + 1
        return out


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Collapse identical (file, line, rule) hits, keeping the strongest.

    Both the collision winner and the final order are decided by a *total* key, never by
    arrival order. That matters once findings come from several concurrent agents: a stable
    order is what makes ranked ids (and therefore PoC filenames) reproducible run to run no
    matter how the work was sharded.
    """
    buckets: Dict[Tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.file, f.line, f.rule)
        current = buckets.get(key)
        if current is None or _order_key(f) < _order_key(current):
            buckets[key] = f
    return sorted(buckets.values(), key=_order_key)


def _order_key(f: Finding) -> Tuple:
    """Sort key: score desc, then file/line/rule/detector for a total order."""
    return (-f.score, f.file, f.line, f.rule, f.detector, f.title)


def finalize(findings: List[Finding]) -> List[Finding]:
    """Assign stable ids, then rebuild PoC stubs so their headers carry the real id.

    Detectors build the PoC eagerly; ids only exist after ranking, so the stub is
    regenerated here once (and only here) to keep `pocs/<id>_...` filenames honest.
    """
    from ..report.pocs import build_poc

    counters = {"solana": 0, "evm": 0, "hyperevm": 0}
    for index, finding in enumerate(findings, start=1):
        key = "solana" if finding.chain == "solana" else "evm"
        counters[key] += 1
        finding.ensure_id(index, counters[key])
        finding.poc = build_poc(finding)
    return findings


def scan(target: Target, detectors: List[Detector] = None) -> ScanResult:
    started = time.time()
    detectors = detectors if detectors is not None else all_detectors()
    result = ScanResult(target=target)
    collected: List[Finding] = []

    for detector in detectors:
        result.detectors_run.append(detector.id)
        for file in target.files:
            if file.language != detector.language:
                continue
            try:
                hits = detector.detect(file)
            except Exception as exc:  # a heuristic must never kill the run
                result.per_file[file.rel] = result.per_file.get(file.rel, 0)
                target.notes.append("detector %s failed on %s: %r" % (detector.id, file.rel, exc))
                continue
            for hit in hits:
                if not hit.chain:
                    hit.chain = detect_chain(file.rel, file.text)
                collected.append(hit)
            result.per_file[file.rel] = result.per_file.get(file.rel, 0) + len(hits)

    collected = dedupe(collected)
    result.findings = finalize(collected)
    result.duration_ms = int((time.time() - started) * 1000)
    return result
