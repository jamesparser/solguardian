"""Detector base class + registry.

Detectors are real code (no model calls), so the tool still produces a full report if
Bobcoins run out mid-hackathon. A detector declares which skill pack justifies it and
fills the required output fields for every finding it emits.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Type

from .finding import Finding, Severity
from .skills import Skill, get as get_skill
from .source import SourceFile


@dataclass
class DetectorContext:
    files: List[SourceFile]


class Detector:
    #: short machine id, used in finding ids and report grouping
    id: str = "base"
    #: human label
    label: str = "Base detector"
    #: "solidity" | "rust"
    language: str = "solidity"
    #: skills/<slug> pack that defines the checklist this detector enforces
    skill: str = ""
    #: default CWE reference
    cwe: str = ""

    # ------------------------------------------------------------------
    def detect(self, file: SourceFile) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    # ------------------------------------------------------------------
    def make(
        self,
        file: SourceFile,
        *,
        rule: str,
        title: str,
        severity: Severity,
        confidence: float,
        line: int,
        description: str,
        evidence: str,
        exploit: List[str],
        patch: List[str],
        function: str = "",
        contract: str = "",
        chain: str = "",
        checklist_needles: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        poc: Optional[str] = None,
        end_line: Optional[int] = None,
    ) -> Finding:
        """Build a finding with every mandatory output field filled in."""
        from ..report.pocs import build_poc  # local import: avoids the detector<->report cycle

        skill: Optional[Skill] = get_skill(self.skill)
        checklist = skill.items(checklist_needles or []) if skill else []
        if skill and not checklist:
            checklist = skill.checklist[:3]
        finding = Finding(
            detector=self.id,
            rule=rule,
            title=title,
            severity=severity,
            confidence=confidence,
            file=file.rel,
            line=line,
            end_line=end_line,
            function=function,
            contract=contract,
            chain=chain or ("solana" if file.language == "rust" else "evm"),
            description=description,
            evidence=evidence.strip(),
            exploit_sketch=exploit,
            patch_sketch=patch,
            skill=skill.path if skill else "",
            checklist=checklist,
            cwe=self.cwe,
            tags=tags or [],
        )
        finding.poc = build_poc(finding, poc)
        return finding


REGISTRY: List[Type[Detector]] = []


def register(cls: Type[Detector]) -> Type[Detector]:
    REGISTRY.append(cls)
    return cls


def _ensure_loaded() -> None:
    """Importing the detectors package registers every detector exactly once."""
    if REGISTRY:
        return
    from .. import detectors  # noqa: F401  (side-effect import: registration)


def all_detectors() -> List[Detector]:
    _ensure_loaded()
    return [cls() for cls in REGISTRY]


def detectors_for(language: str) -> List[Detector]:
    _ensure_loaded()
    return [cls() for cls in REGISTRY if cls.language == language]
