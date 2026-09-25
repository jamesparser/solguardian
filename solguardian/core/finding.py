"""The finding model shared by every detector and every reporter.

A finding is deliberately verbose: a ranked severity number is useless to an auditor
without the plain-English reason, the evidence line, an educational exploit sketch and
a patch sketch. SolGuardian emits all of it, machine-readable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return _WEIGHTS[self]

    @classmethod
    def ordered(cls) -> List["Severity"]:
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO]


_WEIGHTS = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 6.5,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}


@dataclass
class PocStub:
    """A minimal, non-runnable-by-itself test skeleton. Educational, never a weapon."""

    language: str          # "solidity" | "rust"
    filename: str          # relative name inside pocs/
    code: str
    how_to_run: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "language": self.language,
            "filename": self.filename,
            "how_to_run": self.how_to_run,
            "code": self.code,
        }


@dataclass
class Finding:
    detector: str
    rule: str
    title: str
    severity: Severity
    confidence: float                      # 0.0 - 1.0, heuristic honesty
    file: str                              # path relative to the analysed root
    line: int
    end_line: Optional[int] = None
    function: str = ""
    contract: str = ""
    chain: str = ""                        # "evm" | "hyperevm" | "solana" | ""
    description: str = ""                  # 2-5 sentences, human readable
    evidence: str = ""                     # the source line(s) that triggered it
    exploit_sketch: List[str] = field(default_factory=list)
    patch_sketch: List[str] = field(default_factory=list)
    poc: Optional[PocStub] = None
    skill: str = ""                        # skills/<slug>/SKILL.md that justifies it
    checklist: List[str] = field(default_factory=list)  # items the skill required
    cwe: str = ""
    tags: List[str] = field(default_factory=list)
    id: str = ""
    # set by the adjudicator agent after ranking: which *other* detectors independently
    # flagged the same code. 0/[] unless a second detector agrees - never used to inflate
    # severity or confidence.
    corroborated_by: List[str] = field(default_factory=list)
    independent_confirmation: int = 0

    # ------------------------------------------------------------------
    @property
    def location(self) -> str:
        base = "%s:%d" % (self.file, self.line)
        if self.function:
            base += " (%s)" % self.function
        return base

    @property
    def score(self) -> float:
        """Ranking key: severity dominates, confidence breaks ties."""
        conf = max(0.05, min(1.0, self.confidence))
        return round(self.severity.weight * (0.6 + 0.4 * conf), 4)

    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")[:48] or "finding"

    def short_code(self) -> str:
        """Two-letter rule family, e.g. CEI-001 -> CEI, SIGNER-001 -> SIG."""
        head = self.rule.split("-")[0].upper()
        return head[:2] if len(head) <= 3 else {"SIGN": "SI", "REMO": "RA", "ACCT": "AC",
                                                "ACCE": "AC", "DESE": "DS", "MATH": "MA",
                                                "INIT": "IN"}.get(head, head[:2])

    def ensure_id(self, index: int, family_index: int = 0) -> "Finding":
        if not self.id:
            fam = "SG-SOL" if self.chain == "solana" else "SG-EVM"
            self.id = "%s-%03d" % (fam, family_index or index)
            self.tags.append(self.rule)
        return self

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "detector": self.detector,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity.value,
            "severity_weight": self.severity.weight,
            "confidence": round(self.confidence, 2),
            "score": self.score,
            "chain": self.chain,
            "location": {
                "file": self.file,
                "line": self.line,
                "end_line": self.end_line or self.line,
                "function": self.function,
                "contract": self.contract,
            },
            "description": self.description,
            "evidence": self.evidence,
            "exploit_sketch": self.exploit_sketch,
            "patch_sketch": self.patch_sketch,
            "poc": self.poc.to_dict() if self.poc else None,
            "skill": self.skill,
            "skill_checklist": self.checklist,
            "cwe": self.cwe,
            "tags": self.tags,
            "corroborated_by": self.corroborated_by,
            "independent_confirmation": self.independent_confirmation,
        }
