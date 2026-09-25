"""Adjudicator: the third agent role - cross-checking what the hunters claimed.

The hunters work independently and never see each other's output, so an agreement between two
of them is real corroboration, not a consensus that was negotiated. The adjudicator looks at
the merged, ranked set and records, for every finding, which *other detectors* independently
flagged the same function - which is exactly the signal a reviewer uses to decide what to open
first ("three different rules fired on claimTreasuryGrant()").

It is deliberately annotation-only: it never changes severity or confidence, so it cannot make
the report look better than the rules justify, and it cannot break recall or the seeded
severity expectations. Ranking and ids are frozen before it runs.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List

from ..core.detector import Detector, all_detectors
from ..core.finding import Finding
from .base import Agent, AgentResult


class Adjudicator(Agent):
    name = "adjudicator"
    language = "any"

    def __init__(self, detectors: List[Detector]) -> None:
        self.detectors = detectors

    def run(self, findings: List[Finding]) -> AgentResult:  # type: ignore[override]
        started = time.time()
        result = AgentResult(agent=self.name, findings=findings)
        result.log.append("cross-checking %d finding(s) from %d independent detector pass(es)"
                          % (len(findings), len(self._detector_ids())))

        # group by (file, contract, function): same code region, different detectors
        by_site: Dict[tuple, List[Finding]] = defaultdict(list)
        for f in findings:
            by_site[(f.file, f.contract, f.function or f.line // 20)].append(f)

        corroborated = 0
        for _site, group in by_site.items():
            if len(group) < 2:
                continue
            for f in group:
                others = [g for g in group if g.detector != f.detector and g.rule != f.rule]
                # replace, never append: the pass may run again over the same finding objects
                # (a re-run, or a test that re-adjudicates), and the annotation must not
                # accumulate duplicates and overstate agreement between the agents.
                f.corroborated_by = sorted({"%s (%s)" % (g.rule, g.id) for g in others})
                f.independent_confirmation = len({g.detector for g in others})
                if others:
                    corroborated += 1

        strongest = self._strongest_corroboration(findings)
        result.log.append("%d finding(s) independently confirmed by another detector"
                          % corroborated)
        if strongest:
            result.log.append("best-corroborated site: %s <- %d rules"
                              % (strongest[0], len(strongest[1])))
        disagreements = self._grade_spread(by_site)
        if disagreements:
            result.log.append("%d site(s) where detectors disagree on severity (kept as separate "
                              "findings, not averaged)" % disagreements)
        else:
            result.log.append("no severity conflicts between detectors at any site")
        result.duration_ms = int((time.time() - started) * 1000)
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _detector_ids() -> List[str]:
        from ..core.detector import all_detectors

        return [d.id for d in all_detectors()]

    @staticmethod
    def _strongest_corroboration(findings: List[Finding]):
        best = max(findings, key=lambda f: f.independent_confirmation, default=None)
        if best is None or not best.corroborated_by:
            return None
        return (best.location, best.corroborated_by)

    @staticmethod
    def _grade_spread(by_site: Dict[tuple, List[Finding]]) -> int:
        """Sites where two detectors disagree on severity - surfaced, not silently merged."""
        conflicts = 0
        for group in by_site.values():
            if len({f.severity for f in group}) > 1 and len({f.detector for f in group}) > 1:
                conflicts += 1
        return conflicts
