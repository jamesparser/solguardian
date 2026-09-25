"""Ground-truth scoring against samples/EXPECTED_FINDINGS.json.

A demo claim of "it found bugs" is worthless without a denominator. Each seeded issue in
the synthetic samples is listed in that file with a line window and the expected rule /
detector. Recall = seeded issues caught. Precision is reported as unseeded findings so
the honesty note in the README stays meaningful.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .finding import Finding


@dataclass
class SeededIssue:
    key: str
    file: str          # basename match
    lines: List[int]   # [start, end] window (1-indexed)
    classes: List[str]
    rules: List[str]
    detectors: List[str]
    severity: str
    note: str = ""

    def matches(self, finding: Finding) -> bool:
        if os.path.basename(finding.file) != os.path.basename(self.file):
            return False
        if not (self.lines[0] <= finding.line <= self.lines[1]):
            return False
        if self.rules and finding.rule not in self.rules:
            return False
        if self.detectors and finding.detector not in self.detectors:
            return False
        if self.classes:
            blob = (finding.rule + finding.detector + " ".join(finding.tags) + finding.title).lower()
            if not any(cls.lower().replace("-", "") in blob.replace("_", "").replace("-", "") for cls in self.classes):
                return False
        return True


@dataclass
class Scorecard:
    seeded: List[SeededIssue] = field(default_factory=list)
    caught: Dict[str, Finding] = field(default_factory=dict)
    missed: List[SeededIssue] = field(default_factory=list)
    unseeded: List[Finding] = field(default_factory=list)

    @property
    def recall(self) -> float:
        if not self.seeded:
            return 0.0
        return len(self.caught) / float(len(self.seeded))

    def to_dict(self) -> Dict[str, object]:
        return {
            "seeded_total": len(self.seeded),
            "caught": len(self.caught),
            "recall": round(self.recall, 3),
            "missed": [
                {"key": m.key, "file": m.file, "lines": m.lines, "severity": m.severity, "note": m.note}
                for m in self.missed
            ],
            "unseeded_findings": [f.id for f in self.unseeded],
            "detail": [
                {
                    "key": s.key,
                    "caught": s.key in self.caught,
                    "finding_id": self.caught[s.key].id if s.key in self.caught else None,
                    "rule": self.caught[s.key].rule if s.key in self.caught else None,
                    "detector": self.caught[s.key].detector if s.key in self.caught else None,
                    "severity_expected": s.severity,
                    "severity_found": self.caught[s.key].severity.value if s.key in self.caught else None,
                    "note": s.note,
                }
                for s in self.seeded
            ],
        }


def load_expectations(path: str) -> Optional[List[SeededIssue]]:
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    issues: List[SeededIssue] = []
    for entry in data.get("seeded", []):
        issues.append(
            SeededIssue(
                key=entry["key"],
                file=entry["file"],
                lines=list(entry["lines"]),
                classes=entry.get("classes", []),
                rules=entry.get("rules", []),
                detectors=entry.get("detectors", []),
                severity=entry.get("severity", "high"),
                note=entry.get("note", ""),
            )
        )
    return issues


def score(findings: List[Finding], seeded: List[SeededIssue]) -> Scorecard:
    card = Scorecard(seeded=seeded)
    used: set = set()
    for issue in seeded:
        for finding in findings:
            if finding.id in used:
                continue
            if issue.matches(finding):
                card.caught[issue.key] = finding
                used.add(finding.id)
                break
    card.missed = [i for i in seeded if i.key not in card.caught]
    card.unseeded = [f for f in findings if f.id not in used]
    return card
