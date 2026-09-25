"""EVM detector: dangerous delegatecall + proxy storage-collision notes.

Rules:
  DC-001 delegatecall to a caller-controlled / unvalidated address
  DC-002 implementation or logic pointer written without a guard (proxy collision surface)
  DC-003 storage-layout note: unstructured storage writes near a proxy slot base

Skill: skills/delegatecall-proxy/SKILL.md
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.evmutil import has_auth_guard
from ..core.finding import Severity
from ..core.source import SourceFile, detect_chain

DELEGATE = re.compile(r"(?P<recv>[A-Za-z_$][\w$.\[\]()]*?)\s*\.\s*delegatecall\s*(?P<val>\{[^}]*\})?\s*\(")
IMPL_WRITE = re.compile(
    r"\b(?P<slot>implementation|_implementation|logic|masterCopy|beacon|_BEACON_SLOT?)\s*=\s*(?P<rhs>[^;]+);"
)
UNSTRUCTURED = re.compile(r"\b(?:t_store|sstore|mstore)\s*\(|\bassembly\b")


@register
class EvmDelegatecallDetector(Detector):
    id = "evm_delegatecall"
    label = "Dangerous delegatecall / proxy storage"
    language = "solidity"
    skill = "delegatecall-proxy"
    cwe = "CWE-471"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import solidity

        src = solidity.parse(file.rel, file.index)
        chain = detect_chain(file.rel, file.text)
        findings: List[dict] = []

        # which state vars are attacker-influenceable? (unprotected setters)
        unguarded_names = set()
        for fn in src.functions:
            if not fn.has_body:
                continue
            guarded, _why = has_auth_guard(fn)
            if guarded:
                continue
            for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*=", fn.body):
                unguarded_names.add(m.group(1))

        for m in DELEGATE.finditer(src.index.masked):
            line = src.index.line_of(m.start())
            fn = next(
                (c for c in src.functions if c.has_body and c.body_start <= m.start() < c.body_end), None
            )
            if fn is None:
                continue
            receiver = re.sub(r"\s+", "", m.group("recv") or "")
            guarded, why = has_auth_guard(fn)
            from_params = receiver in re.sub(r"\s+", " ", fn.params)
            from_unguarded_state = receiver in unguarded_names

            if from_params:
                severity, conf, rule = Severity.CRITICAL, 0.92, "DC-001"
                reason = (
                    "the delegatecall target `%s` is an instruction argument, so any caller chooses the code that "
                    "runs inside this contract's storage." % receiver
                )
            elif from_unguarded_state:
                severity, conf, rule = Severity.CRITICAL, 0.85, "DC-001"
                reason = (
                    "the delegatecall target `%s` is a storage variable that is writable by an unguarded function, "
                    "so the target is effectively attacker-controlled." % receiver
                )
            elif receiver in ("implementation", "logic", "_implementation"):
                severity, conf, rule = Severity.HIGH, 0.7, "DC-001"
                reason = "the delegatecall target is a logic pointer; verify who can change it."
            else:
                severity, conf, rule = Severity.MEDIUM, 0.55, "DC-001"
                reason = "delegatecall target `%s` could not be tied to a validated constant address." % receiver

            findings.append(
                self.make(
                    file,
                    rule=rule,
                    title="delegatecall to unvalidated target in %s()" % fn.name,
                    severity=severity,
                    confidence=conf,
                    line=line,
                    function=fn.name,
                    contract=fn.contract,
                    chain=chain,
                    description=(
                        "%s() executes `%s.delegatecall(...)`. %s delegatecall keeps this contract's storage and "
                        "msg.sender, so the callee can rewrite owner/admin/implementation slots, mint, drain, or call "
                        "selfdestruct. Authorisation on the wrapper (%s) does not help if the target itself is "
                        "attacker-chosen." % (fn.name, receiver or "target", reason, "guarded" if guarded else "absent")
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Deploy a malicious implementation contract.",
                        "Call %s() with your contract as the target (or first move the pointer via the unguarded setter)." % fn.name,
                        "Inside the callee, write the admin/owner slot, then use the admin path to take the funds.",
                    ],
                    patch=[
                        "Only delegatecall to a constant, admin-upgraded-with-timelock implementation address.",
                        "Add EIP-1967 slots + an `onlyProxyAdmin` + timelock upgrade path.",
                        "Validate `target.code.length > 0` and that the target is in an allowlist.",
                    ],
                    checklist_needles=["delegatecall", "target", "timelock"],
                    tags=["delegatecall", "upgradeability"],
                )
            )

        for m in IMPL_WRITE.finditer(src.index.masked):
            line = src.index.line_of(m.start())
            fn = next(
                (c for c in src.functions if c.has_body and c.body_start <= m.start() < c.body_end), None
            )
            if fn is None:
                continue
            guarded, _why = has_auth_guard(fn)
            if guarded:
                continue
            findings.append(
                self.make(
                    file,
                    rule="DC-002",
                    title="Unguarded write to proxy logic pointer `%s`" % m.group("slot"),
                    severity=Severity.HIGH,
                    confidence=0.8,
                    line=line,
                    function=fn.name,
                    contract=fn.contract,
                    chain=chain,
                    description=(
                        "%s() assigns `%s` with no authorisation check. Whoever controls that slot controls the logic "
                        "every delegatecall in this proxy resolves to, which is equivalent to owning the contract and "
                        "all of its storage. This is the storage-collision/upgrade footgun class: the slot is also "
                        "shared with the implementation's own layout, so ordering matters."
                        % (fn.name, m.group("slot"))
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Point `%s` at a contract you wrote." % m.group("slot"),
                        "Trigger the fallback/delegate path - all subsequent calls run your code in this storage.",
                    ],
                    patch=[
                        "Guard with `onlyProxyAdmin` + AccessControl role, and emit an Upgraded event.",
                        "Use EIP-1967/ERC-1967 upgradeable proxies from OpenZeppelin rather than a hand-rolled slot.",
                        "Keep implementation state in a namespaced storage gap to avoid collisions.",
                    ],
                    checklist_needles=["pointer", "collision", "timelock"],
                    tags=["delegatecall", "proxy", "storage-collision"],
                )
            )

        if UNSTRUCTURED.search(src.index.masked) and any("delegatecall" in f.title for f in findings):
            findings.append(
                self.make(
                    file,
                    rule="DC-003",
                    title="Assembly storage writes alongside delegatecall logic (collision audit note)",
                    severity=Severity.INFO,
                    confidence=0.4,
                    line=1,
                    contract=src.contracts[0].name if src.contracts else "",
                    chain=chain,
                    description=(
                        "This file mixes inline assembly / low-level storage writes with delegatecall-driven logic. "
                        "That combination is where proxy storage collisions hide: the implementation's slot 0 may be "
                        "the proxy's own admin slot. No concrete bug is claimed - treat it as a manual-review pointer."
                    ),
                    evidence="(file-level note)",
                    exploit=[
                        "Review every `sstore`/`t_store` target against the proxy's slot layout.",
                        "Check that the implementation declares its variables after the ERC-1967 gap.",
                    ],
                    patch=[
                        "Adopt UUPS/TransparentUpgradeableProxy layouts instead of raw slots.",
                        "Add a storage-layout test that diffs slots between implementation versions.",
                    ],
                    checklist_needles=["layout", "collision"],
                    tags=["proxy", "review-note"],
                )
            )
        return findings
