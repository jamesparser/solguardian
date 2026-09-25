"""Subagent base.

Each hunter owns a slice of the detector registry and returns findings plus a short log.
The orchestrator runs the hunters concurrently (real threads) so the demo shows parallel
work the way Bob's subagents do, and so one hunter failing never sinks the report.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from ..core.detector import Detector
from ..core.finding import Finding
from ..core.source import SourceFile


@dataclass
class AgentResult:
    agent: str
    findings: List[Finding] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: int = 0

    def to_dict(self):
        return {
            "agent": self.agent,
            "files_scanned": self.files_scanned,
            "findings": len(self.findings),
            "duration_ms": self.duration_ms,
            "log": self.log,
        }


class Agent:
    name: str = "agent"
    language: str = "solidity"
    detector_ids: List[str] = []

    def __init__(self, detectors: List[Detector]) -> None:
        self.detectors = [d for d in detectors if d.id in self.detector_ids]

    def run(self, files: List[SourceFile]) -> AgentResult:
        started = time.time()
        result = AgentResult(agent=self.name)
        relevant = [f for f in files if f.language == self.language]
        result.files_scanned = len(relevant)
        if not relevant:
            result.log.append("%s: no %s files in scope, skipping" % (self.name, self.language))
            result.duration_ms = int((time.time() - started) * 1000)
            return result

        result.log.append(
            "%s: %d file(s), %d detector(s) [%s]"
            % (self.name, len(relevant), len(self.detectors), ", ".join(d.id for d in self.detectors))
        )
        for file in relevant:
            for detector in self.detectors:
                t0 = time.time()
                try:
                    hits = detector.detect(file)
                except Exception as exc:  # heuristic safety: never abort the run
                    result.log.append("  ! %s on %s raised %r" % (detector.id, file.rel, exc))
                    continue
                for hit in hits:
                    result.findings.append(hit)
                if hits:
                    result.log.append(
                        "  %-22s %s -> %d finding(s) (%d ms)"
                        % (detector.id, file.rel, len(hits), int((time.time() - t0) * 1000))
                    )
        result.log.append(
            "%s: done, %d finding(s) in %d ms"
            % (self.name, len(result.findings), int((time.time() - started) * 1000))
        )
        result.duration_ms = int((time.time() - started) * 1000)
        return result
