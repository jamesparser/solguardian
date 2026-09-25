"""Subagent base.

Each hunter owns a slice of the detector registry and returns findings plus a short log.
The orchestrator can run many instances of the same hunter concurrently - one per file shard -
so an agent is cheap to construct and holds no shared mutable state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from ..core.detector import Detector, all_detectors
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
    #: display name, appears in the log and in report.json's agent_runs
    name: str = "agent"
    #: "solidity" | "rust" | "any"
    language: str = "solidity"
    #: ids from core.detector this agent is allowed to run
    detector_ids: List[str] = []

    def __init__(self, detectors: Optional[List[Detector]] = None, name: Optional[str] = None) -> None:
        """`detectors` may be omitted (resolved from the registry) or pre-built by the caller."""
        pool: List[Detector] = list(detectors) if detectors else all_detectors()
        if self.detector_ids:
            wanted = set(self.detector_ids)
            pool = [d for d in pool if d.id in wanted]
            missing = wanted - {d.id for d in pool}
            if missing:
                pool = pool + [cls() for cls in _registry_classes() if cls.id in missing]
        # keep registry order so sharded runs are deterministic
        order = {d.id: i for i, d in enumerate(all_detectors())}
        self.detectors = sorted(pool, key=lambda d: order.get(d.id, 999))
        if name:
            self.name = name

    def run(self, files: List[SourceFile]) -> AgentResult:
        started = time.time()
        result = AgentResult(agent=self.name)
        relevant = [f for f in files if f.language == self.language] if self.language != "any" else list(files)
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


def _registry_classes():
    from ..core.detector import REGISTRY

    return REGISTRY
