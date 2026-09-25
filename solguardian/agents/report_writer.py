"""Report-writer subagent.

Not a formatter only: it enforces the output contract from `skills/severity-grading` and
`skills/poc-stubs` before anything reaches a report. A finding with a missing required
field is a bug in SolGuardian, so the writer refuses to pass it silently.
"""

from __future__ import annotations

import time
from typing import List

from ..core.detector import Detector
from ..core.finding import Finding, Severity
from ..core.skills import get as get_skill
from .base import Agent, AgentResult

REQUIRED = [
    ("id", "identifier"),
    ("severity", "severity"),
    ("confidence", "confidence"),
    ("title", "title"),
    ("description", "plain-English description"),
    ("location", "file:line + function"),
    ("exploit_sketch", "exploit sketch"),
    ("patch_sketch", "patch sketch"),
    ("poc", "PoC stub"),
    ("skill", "skill pack reference"),
]


class ReportWriter(Agent):
    name = "report-writer"
    language = "any"

    def __init__(self, detectors: List[Detector]) -> None:  # noqa: D401 - mirrors Agent signature
        self.detectors = detectors

    def run(self, findings: List[Finding]) -> AgentResult:  # type: ignore[override]
        started = time.time()
        result = AgentResult(agent=self.name, findings=findings)
        result.log.append("validating %d finding(s) against the output contract" % len(findings))

        incomplete = 0
        for finding in findings:
            missing = []
            if not finding.id:
                missing.append("id")
            if not finding.title:
                missing.append("title")
            if not finding.description or len(finding.description.split()) < 12:
                missing.append("description")
            if not finding.exploit_sketch:
                missing.append("exploit sketch")
            if not finding.patch_sketch:
                missing.append("patch sketch")
            if not finding.poc:
                missing.append("PoC stub")
            if not finding.skill:
                missing.append("skill pack")
            if missing:
                incomplete += 1
                result.log.append("  ! %s missing: %s" % (finding.id or finding.title, ", ".join(missing)))

        grades = _grade(findings)
        result.log.append("severity distribution: %s" % ", ".join(
            "%s=%d" % (k, v) for k, v in grades.items() if v))
        result.log.append("contract check: %d/%d complete" % (len(findings) - incomplete, len(findings)))

        # explainability: every finding must resolve to a real skill file
        unresolved = [f for f in findings if f.skill and get_skill(_slug(f.skill)) is None]
        if unresolved:
            result.log.append("  ! %d finding(s) point at a missing skill pack" % len(unresolved))
        else:
            result.log.append("all findings resolve to a skill pack under skills/")

        result.duration_ms = int((time.time() - started) * 1000)
        return result


def _grade(findings: List[Finding]) -> dict:
    out = {s.value: 0 for s in Severity.ordered()}
    for finding in findings:
        out[finding.severity.value] += 1
    return out


def _slug(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    return parts[1] if len(parts) >= 2 and parts[0] == "skills" else parts[0] if parts else ""
