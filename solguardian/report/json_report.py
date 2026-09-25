"""report.json - the machine-readable deliverable."""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from ..core.finding import Finding
from ..core.scanner import ScanResult
from ..core.scorecard import Scorecard


def build(result: ScanResult, scorecard: Optional[Scorecard] = None, agents=None) -> Dict[str, object]:
    findings = result.findings
    payload: Dict[str, object] = {
        "tool": {
            "name": "SolGuardian",
            "version": _version(),
            "mode": "static-heuristic (AST-lite + pattern rules). No ML, no network, no RPC.",
            "skills_dir": "skills/",
        },
        "target": {
            "root": os.path.basename(result.target.root.rstrip("/")),
            "kind": result.target.kind,
            "files": [f.rel for f in result.target.files],
            "lines_scanned": result.target.line_count,
        },
        "detectors_run": sorted(set(result.detectors_run)),
        "summary": {
            "total": len(findings),
            "duration_ms": result.duration_ms,
            "by_severity": {s.value: sum(1 for f in findings if f.severity is s) for s in _severities()},
            "by_chain": _chain_counts(findings),
            "by_detector": _detector_counts(findings),
        },
        "findings": [f.to_dict() for f in findings],
    }
    if scorecard is not None:
        payload["demo_metrics"] = scorecard.to_dict()
    if agents is not None:
        payload["agent_runs"] = [a.to_dict() for a in agents]
    return payload


def write(result: ScanResult, out_path: str, scorecard: Optional[Scorecard] = None, agents=None) -> str:
    data = build(result, scorecard, agents)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return out_path


def _version() -> str:
    from .. import __version__

    return __version__


def _severities():
    from ..core.finding import Severity

    return Severity.ordered()


def _chain_counts(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        out[f.chain or "unknown"] = out.get(f.chain or "unknown", 0) + 1
    return out


def _detector_counts(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        out[f.detector] = out.get(f.detector, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))
