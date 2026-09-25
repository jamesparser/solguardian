"""EVM detector: reentrancy / checks-effects-interactions violations.

Skill: skills/reentrancy/SKILL.md
"""

from __future__ import annotations

from typing import List

from ..core.detector import Detector, register
from ..core.evmutil import (
    call_sites,
    has_reentrancy_guard,
    state_writes,
    strip_parens,
)
from ..core.finding import Severity
from ..core.source import SourceFile, detect_chain



@register
class EvmReentrancyDetector(Detector):
    id = "evm_reentrancy"
    label = "Reentrancy (state after external call)"
    language = "solidity"
    skill = "reentrancy"
    cwe = "CWE-841"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import solidity

        src = solidity.parse(file.rel, file.index)
        chain = detect_chain(file.rel, file.text)
        findings: List[dict] = []

        for fn in src.functions:
            if not fn.has_body:
                continue
            calls = call_sites(fn.body, fn.body_start, src.index)
            if not calls:
                continue
            writes = state_writes(fn.body, fn.body_start, src.index)
            guarded, why = has_reentrancy_guard(fn, src.functions)

            for cline, receiver, kind, low_level, moves_value in calls:
                # what still happens after the call returns?
                after = [w for w in writes if w[0] > cline]
                later_calls = [c for c in calls if c[0] > cline]
                if guarded and not after:
                    continue
                if not after and not later_calls:
                    if not (low_level and not moves_value):
                        continue  # single interaction, nothing to re-enter against

                if after:
                    touched = ", ".join(sorted({strip_parens(w[1]) for w in after})[:3])
                    if guarded:
                        continue
                    severity = Severity.CRITICAL if moves_value else Severity.HIGH
                    confidence = 0.9 if moves_value else 0.75
                    findings.append(
                        self.make(
                            file,
                            rule="CEI-001",
                            title="Reentrancy: state updated after external call in %s()" % fn.name,
                            severity=severity,
                            confidence=confidence,
                            line=cline,
                            end_line=max(w[0] for w in after),
                            function=fn.name,
                            contract=fn.contract,
                            chain=chain,
                            description=(
                                "%s() performs an external interaction (%s.%s) at line %d and only "
                                "updates contract state afterwards (%s). A callee can re-enter %s() "
                                "during that callback and still see the pre-call balance, so the same "
                                "funds can be withdrawn repeatedly. No reentrancy guard and no "
                                "checks-effects-interactions ordering were found in this function."
                                % (fn.name, receiver or "target", kind, cline, touched, fn.name)
                            ),
                            evidence=file.line_text(cline),
                            exploit=[
                                "Deploy a malicious callee whose fallback/receive() calls back into %s()." % fn.name,
                                "On the first call, pass an amount the contract still thinks you are owed.",
                                "Inside the callback, call %s() again before the balance subtraction at "
                                "line %d has executed - the old balance is still readable." % (fn.name, after[0][0]),
                                "Repeat until the contract's native/ERC20 balance is drained.",
                            ],
                            patch=[
                                "Update all accounting before the external call (checks-effects-interactions).",
                                "Or add OpenZeppelin ReentrancyGuard: `nonReentrant` on %s()." % fn.name,
                                "Prefer push payments with an explicit withdraw-then-send ordering.",
                            ],
                            checklist_needles=["state", "guard", "effects", "callback"],
                            tags=["reentrancy", "eth", "value-transfer"],
                        )
                    )
                    break  # one finding per function is enough for a ranked report

                if later_calls:
                    findings.append(
                        self.make(
                            file,
                            rule="CEI-002",
                            title="Multiple sequential external calls without a guard in %s()" % fn.name,
                            severity=Severity.MEDIUM,
                            confidence=0.55,
                            line=cline,
                            function=fn.name,
                            contract=fn.contract,
                            chain=chain,
                            description=(
                                "%s() makes more than one external call (%s then a later interaction) with no "
                                "reentrancy guard. Even without a state write in between, the second callee runs "
                                "while the first callee may still be inside its own callback, which is the classic "
                                "read-only-reentrancy and cross-function reentrancy setup. %s"
                                % (fn.name, receiver, "Flagged as medium because the harm depends on the callees.")
                            ),
                            evidence=file.line_text(cline),
                            exploit=[
                                "Assume callee A is attacker-controlled.",
                                "From A's callback, call an entry point that reads state produced by B.",
                                "Use the stale/mid-transaction view to gain an advantage (liquidation, mint, price).",
                            ],
                            patch=[
                                "Add `nonReentrant` to every function in the re-entrancy graph, including views used off-chain.",
                                "Complete all internal accounting between interactions.",
                            ],
                            checklist_needles=["guard", "cross-function"],
                            tags=["reentrancy", "read-only-reentrancy"],
                        )
                    )
                    break
        return findings
