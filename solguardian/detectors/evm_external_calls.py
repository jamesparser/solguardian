"""EVM detector: unchecked external calls & return values.

Rules:
  EC-001 low-level .call()/send()/transfer() result discarded
  EC-002 interface call returning bool whose result is dropped
  EC-003 .transfer()/.send() with the 2300 gas stipend against possibly-contract recipients

Skill: skills/external-calls/SKILL.md (shared severity model in skills/severity-grading)
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.source import SourceFile, detect_chain

CALL_STMT = re.compile(
    r"(?P<lhs>[^;=]*)?(?P<recv>[A-Za-z_$][\w$.]*\s*(?:\([^();]*\))?)\s*\."
    r"(?P<kind>call|send|transfer)\s*(?P<value>\{[^}]*\})?\s*\((?P<args>[^;]*)\)\s*;",
)
BOOL_RETURNING = re.compile(r"\btransfer\b|\bsend\b|\bcall\b")
# native push payments: `payable(x).transfer(v)` / `address(x).transfer(v)` / `x.send(v)`
NATIVE_PUSH = re.compile(
    r'(?:\bpayable|\baddress)\s*\([^()]*\)\s*\.\s*(?:send|transfer)\s*\('
    r'|\b(?:msg\.sender|to|recipient|payee)\s*\.\s*(?:send|transfer)\s*\('
)


def _assigned_before(masked_before_stmt: str) -> bool:
    """True when the result is bound: `(bool ok,) = ...` or `bool ok = ...` or `require(...call...)`."""
    tail = masked_before_stmt[-400:]
    if re.search(r"\(\s*(?:bool\s+\w+)?[^()]*,\s*\)?\s*=?\s*$", tail):
        return True
    if re.search(r"(bool|uint\d*|bytes\d*)\s+\w+\s*=\s*$", tail):
        return True
    if re.search(r"(require|assert|if)\s*\(?\s*$", tail):
        return True
    return False


@register
class EvmExternalCallDetector(Detector):
    id = "evm_external_calls"
    label = "Unchecked external call return values"
    language = "solidity"
    skill = "external-calls"
    cwe = "CWE-252"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import solidity

        src = solidity.parse(file.rel, file.index)
        chain = detect_chain(file.rel, file.text)
        masked = src.index.masked
        findings: List[dict] = []

        for m in CALL_STMT.finditer(masked):
            kind = m.group("kind")
            line = src.index.line_of(m.start())
            fn = None
            for candidate in src.functions:
                if candidate.has_body and candidate.body_start <= m.start() < candidate.body_end:
                    fn = candidate
            if fn is None:
                continue
            # is the return value consumed?
            prefix = masked[max(0, masked.rfind(";", 0, m.start()) + 1):m.start()]
            consumed = _assigned_before(prefix) or bool(prefix.strip().rstrip(".").strip())
            if consumed:
                # still check `ok;` statements (write-only "check")
                stmt = masked[m.start(): masked.find(";", m.end()) + 1]
                if not re.search(r"^\s*ok\s*;", stmt):
                    continue

            receiver = re.sub(r"\s+", " ", m.group("recv") or "").strip()
            value_group = m.group("value") or ""
            moves_value = bool(value_group) or kind in ("send", "transfer")
            # `address(x).transfer(v)` reverts on failure by design, so an ignored result is
            # not a bug there - only the 2300-gas stipend assumption is. Everything else
            # (`call`, `send`, and ERC20-style `token.transfer`) returns a bool that must be used.
            native_value_push = bool(m.group("value")) or (kind == "transfer" and bool(re.match(r"^(payable|address)\s*\(", receiver)))
            if native_value_push:
                continue

            if not consumed and re.match(r"^\s*ok\s*;", masked[m.end():masked.find(";", m.end()) + 1]):
                title = "Silenced call result (`ok;`) in %s()" % fn.name
                severity, conf = Severity.HIGH, 0.9
                why = (
                    "`ok;` is a statement that reads the boolean and throws it away. It compiles, it satisfies a "
                    "linter, and it does nothing: the failure branch is unreachable."
                )
            elif moves_value:
                title = "Unchecked value transfer result in %s()" % fn.name
                severity, conf = Severity.HIGH, 0.85
                why = (
                    "%s.%s() can fail silently: low-level `call` returns false instead of reverting, and "
                    "`send`/`transfer` return false when the recipient cannot accept the value." % (receiver or "target", kind)
                )
            else:
                title = "Unchecked external call result in %s()" % fn.name
                severity, conf = Severity.MEDIUM, 0.7
                why = (
                    "The boolean result of %s.%s() is discarded, so a failed interaction leaves the contract "
                    "behaving as if it succeeded." % (receiver or "target", kind)
                )

            findings.append(
                self.make(
                    file,
                    rule="EC-001" if not consumed else "EC-002",
                    title=title,
                    severity=severity,
                    confidence=conf,
                    line=line,
                    function=fn.name,
                    contract=fn.contract,
                    chain=chain,
                    description=(
                        "%s() calls out to %s and ignores the result. %s "
                        "State that was already updated before the call is not rolled back, so the contract's view "
                        "of itself diverges from the chain - for accounting code that is a direct loss of user funds."
                        % (fn.name, receiver or "an external address", why)
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Make the callee fail on purpose: revert, run out of gas, or return false (non-standard ERC20).",
                        "Trigger %s() so the accounting step succeeds while the value move fails." % fn.name,
                        "Withdraw/claim again with the state still advanced.",
                    ],
                    patch=[
                        "`(bool ok, ) = target.call{value: v}(\"\"); require(ok, \"transfer failed\");`",
                        "Or use OpenZeppelin Address.sendValue with an explicit revert.",
                        "For non-standard ERC20s use `SafeERC20.safeTransfer` instead of `transfer`.",
                    ],
                    checklist_needles=["return", "revert", "safe"],
                    tags=["unchecked-call", "error-handling"],
                )
            )

        # EC-003: fixed stipend transfers to arbitrary addresses
        for m in NATIVE_PUSH.finditer(masked):
            line = src.index.line_of(m.start())
            fn = next(
                (c for c in src.functions if c.has_body and c.body_start <= m.start() < c.body_end), None
            )
            if fn is None:
                continue
            if re.search(r"\bsafeTransfer\b|\btransferFrom\b", src.index.line_text(line)):
                continue
            findings.append(
                self.make(
                    file,
                    rule="EC-003",
                    title="Native `.%s()` gas-stipend transfer in %s()" % (_push_kind(masked, m.end()), fn.name),
                    severity=Severity.LOW,
                    confidence=0.5,
                    line=line,
                    function=fn.name,
                    contract=fn.contract,
                    chain=chain,
                    description=(
                        "%s() forwards value with `.%s()`, which forwards exactly 2300 gas. That is enough for a plain "
                        "wallet but not for most smart-contract recipients, so payments to contracts (multisigs, "
                        "other vaults, account-abstraction wallets) fail - and on %s the stipend assumption has changed "
                       "more than once. Reported as low because it is availability, not theft."
                        % (fn.name, "transfer/send", "HyperEVM" if chain == "hyperevm" else "this chain")
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "No attacker needed: legitimate users with contract wallets simply cannot be paid.",
                        "If the result is unchecked, the contract marks the payout as done anyway.",
                    ],
                    patch=[
                        "Prefer withdrawal patterns the user triggers, with `Address.sendValue` + checked result.",
                        "Never assume 2300 gas is enough for every recipient.",
                    ],
                    checklist_needles=["stipend", "gas"],
                    tags=["gas-stipend", "availability"],
                )
            )
        return dedupe(findings)


def _push_kind(masked: str, end: int) -> str:
    tail = masked[end:end + 60]
    return "send" if re.search(r"\bsend\b", masked[max(0, end - 60):end]) else "transfer"


def dedupe(items: List[dict]) -> List[dict]:
    """EC-001/EC-002 can both fire on the same line; keep the strongest."""
    best = {}
    for f in items:
        key = (f.file, f.line, f.rule[:5])
        if key not in best or f.score > best[key].score:
            best[key] = f
    return sorted(best.values(), key=lambda x: -x.score)
