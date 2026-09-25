"""EVM detector: selfdestruct, arbitrary send, and stranded-fund footguns.

Rules:
  SD-001 selfdestruct()/suicide() reachable, especially with a caller-chosen beneficiary
  SD-002 value sent to a caller-chosen destination
  SF-001 authorisation gated on a state variable that is never assigned (unreachable path)
  SF-002 value can enter the contract but can never leave (no accounting, no withdrawal)
  SF-003 token recovery ignores the transfer result

Skills: skills/fund-recovery/SKILL.md, skills/severity-grading/SKILL.md
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..core.detector import Detector, register
from ..core.evmutil import has_auth_guard
from ..core.finding import Severity
from ..core.source import SourceFile, detect_chain

SELFDESTRUCT = re.compile(r"\b(selfdestruct|suicide)\s*\(\s*(?P<arg>[^)]*)\)")
ARBITRARY_SEND = re.compile(r"(?P<to>[A-Za-z_$][\w$.\[\]()]*?)\s*(?:\.payable\b)?\s*\.\s*call\s*\{[^}]*value[^}]*\}")
RECEIVE = re.compile(r"\bfunction\s+receive\s*\(|\breceive\s*\(\s*\)\s*external\s+payable")
FALLBACK = re.compile(r"\bfallback\s*\(\s*\)\s*external\s+payable")
TIMEOLOCK = re.compile(r"\b(timelock|Delay|governance|GOVERNANCE|multiSig|Multisig|delay)\b")

DECL = re.compile(
    r"^\s*(?P<type>address|uint\d*|int\d*|bool|bytes\d*|mapping\s*\([^;{]*?\)|[A-Za-z_$][\w$]*)\s+"
    r"(?P<rest>(?:public|private|internal|external|constant|immutable|payable|transient|\s)*)"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?P<init>=)?\s*(?P<tail>[^;]*);",
    re.M,
)
SKIP_WORDS = {
    "function", "modifier", "event", "require", "return", "emit", "pragma", "import", "if",
    "for", "while", "else", "constructor", "receive", "fallback", "using", "struct", "enum",
    "mapping", "public", "private", "internal", "external", "returns", "new", "assembly", "let",
}


def declared_state_vars(src) -> Dict[str, Tuple[int, str]]:
    """name -> (line, type) for storage variables declared directly in contract bodies."""
    found: Dict[str, Tuple[int, str]] = {}
    for contract in src.contracts:
        body = src.index.masked[contract.body_start:contract.body_end]
        base = contract.body_start
        for m in DECL.finditer(body):
            name = m.group("name")
            kind = m.group("type")
            if name in SKIP_WORDS or kind in SKIP_WORDS:
                continue
            line = src.index.line_of(base + m.start())
            if name not in found:
                found[name] = (line, kind)
    return found


def assigned_names(masked: str) -> Dict[str, int]:
    """names that appear on the left of an assignment somewhere in the file."""
    out: Dict[str, int] = {}
    for m in re.finditer(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*(?:\[[^\]]*\])?\s*(=|\+=|-=)(?!=)", masked):
        out.setdefault(m.group("name"), m.start())
    return out


@register
class EvmSelfdestructDetector(Detector):
    id = "evm_selfdestruct"
    label = "selfdestruct / arbitrary send / stuck funds"
    language = "solidity"
    skill = "fund-recovery"
    cwe = "CWE-284"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import solidity

        src = solidity.parse(file.rel, file.index)
        chain = detect_chain(file.rel, file.text)
        masked = src.index.masked
        findings: List[dict] = []

        def fn_at(pos: int):
            for fn in src.functions:
                if fn.has_body and fn.body_start <= pos < fn.body_end:
                    return fn
            return None

        # --- SD-001 selfdestruct -------------------------------------------
        for m in SELFDESTRUCT.finditer(masked):
            fn = fn_at(m.start())
            line = src.index.line_of(m.start())
            arg = (m.group("arg") or "").strip()
            guarded, why = has_auth_guard(fn) if fn else (False, "")
            beneficiary_is_param = bool(fn and arg and arg in re.sub(r"\s+", " ", fn.params))
            timelocked = bool(TIMEOLOCK.search(" ".join(fn.modifiers)) if fn else False)
            if beneficiary_is_param:
                severity, conf = Severity.CRITICAL, 0.9
            elif not guarded:
                severity, conf = Severity.CRITICAL, 0.85
            else:
                severity, conf = Severity.HIGH, 0.7
            findings.append(
                self.make(
                    file,
                    rule="SD-001",
                    title="Reachable `selfdestruct`%s in %s"
                    % (" with caller-chosen beneficiary" if beneficiary_is_param else "", fn.name + "()" if fn else "(file scope)"),
                    severity=severity,
                    confidence=conf,
                    line=line,
                    function=fn.name if fn else "",
                    contract=fn.contract if fn else (src.contracts[0].name if src.contracts else ""),
                    chain=chain,
                    description=(
                        "%s() can destroy %s and force-send the whole native balance to %s. %s "
                        "Destructible state also kills any index that assumed code persists, and it makes an "
                        "irreversible action available without a timelock or governance delay."
                        % (
                            fn.name if fn else "A function",
                            src.contracts[0].name if src.contracts else "this contract",
                            ("an address the caller picks (`%s`)" % arg) if beneficiary_is_param else "a fixed address",
                            ("Authorisation found: %s - but there is no delay or second signature." % why)
                            if guarded
                            else "There is no authorisation check at all on this path.",
                        )
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Call %s() (directly, or through the unguarded entry that reaches it)." % (fn.name if fn else "destruct path"),
                        "The contract's storage is wiped and its ETH balance is pushed to the chosen beneficiary.",
                        "Every user balance recorded in the contract becomes unrecoverable.",
                    ],
                    patch=[
                        "Remove selfdestruct from application code; use a pause flag plus an explicit withdrawal route.",
                        "If a migration really is needed, gate it behind a timelock + multi-sig governance role and a "
                        "fixed beneficiary.",
                        "Note that EIP-678 (Cancun and later) limits selfdestruct to same-transaction creation, but the "
                        "storage/balance sweep still applies on pre-Pectra deployments and on HyperEVM.",
                    ],
                    checklist_needles=["destruct", "timelock", "irreversible"],
                    tags=["selfdestruct", "irreversible"],
                )
            )

        # --- SD-002 value to a caller-chosen destination --------------------
        for m in ARBITRARY_SEND.finditer(masked):
            fn = fn_at(m.start())
            if fn is None:
                continue
            line = src.index.line_of(m.start())
            to = re.sub(r"\s+", "", m.group("to") or "")
            guarded, why = has_auth_guard(fn)
            if to in re.sub(r"\s+", " ", fn.params):
                severity, conf = (Severity.HIGH, 0.75) if guarded else (Severity.CRITICAL, 0.8)
                findings.append(
                    self.make(
                        file,
                        rule="SD-002",
                        title="Value sent to a caller-chosen address in %s()" % fn.name,
                        severity=severity,
                        confidence=conf,
                        line=line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() moves native value to `%s`, which is supplied by the caller rather than derived from "
                            "the contract's own accounting. %s Any caller (or any caller that can reach this path) chooses "
                            "the destination, so shared funds can be redirected at will."
                            % (
                                fn.name,
                                to,
                                ("Guarded by %s, so it is a trust-the-operator issue." % why) if guarded else "It is unguarded.",
                            )
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Call %s() with `to` set to an address you control." % fn.name,
                            "Repeat for each victim's recorded balance if the function is parameterised by user.",
                        ],
                        patch=[
                            "Derive the recipient from the caller (`msg.sender`) or from a per-user withdrawal map.",
                            "Use pull-payments: credit an internal balance, let users claim it themselves.",
                        ],
                        checklist_needles=["destination", "pull", "accounting"],
                        tags=["arbitrary-send", "value-flow"],
                    )
                )

        # --- SF-001 unreachable authorisation --------------------------------
        vars_declared = declared_state_vars(src)
        assigned = assigned_names(masked)
        for name, (line, kind) in vars_declared.items():
            if kind not in ("address",):
                continue
            if name in assigned:
                continue
            if re.search(r"\b%s\b" % name, "constructor") :
                pass
            uses = [m for m in re.finditer(r"\brequire\s*\([^;]*\b%s\b[^;]*\)" % re.escape(name), masked)]
            if not uses:
                continue
            for u in uses:
                uline = src.index.line_of(u.start())
                fn = fn_at(u.start())
                findings.append(
                    self.make(
                        file,
                        rule="SF-001",
                        title="Stranded funds: %s() is gated on `%s`, which is never assigned"
                        % (fn.name if fn else "a function", name),
                        severity=Severity.HIGH,
                        confidence=0.8,
                        line=uline,
                        function=fn.name if fn else "",
                        contract=fn.contract if fn else (src.contracts[0].name if src.contracts else ""),
                        chain=chain,
                        description=(
                            "`%s` is declared as a storage address and used as the only authorisation for %s, but "
                            "nothing in this contract ever assigns it. It is therefore zero (`address(0)`), and no "
                            "caller can ever satisfy the check. The function is dead code, which means value that only "
                            "this path can move - ETH and tokens held by the contract - is permanently stranded."
                            % (name, fn.name + "()" if fn else "the only recovery path")
                        ),
                        evidence=file.line_text(uline),
                        exploit=[
                            "No attacker required: send value to the contract (or let it accumulate) and the recovery "
                            "path can never be executed.",
                            "If the gate is `msg.sender == address(0)`, the check can even be satisfied by a crafted "
                            "creation flow, turning dead code into an open door.",
                        ],
                        patch=[
                            "Assign the variable in the constructor or an initialiser, or delete the path.",
                            "Add a test asserting the recovery function is callable by the intended role.",
                            "Prefer AccessControl roles with `grantRole` at deploy time over bare address variables.",
                        ],
                        checklist_needles=["initialised", "stranded", "recovery"],
                        tags=["stuck-funds", "unreachable-guard"],
                    )
                )

        # --- SF-002 value in, no value out ----------------------------------
        has_ingress = bool(RECEIVE.search(masked) or FALLBACK.search(masked) or re.search(r"\bpayable\b", masked))
        has_egress = bool(re.search(r"\.\s*(call|send|transfer)\s*(\{[^}]*value[^}]*\})?\s*\(|sendValue|withdrawTo", masked))
        if has_ingress and not has_egress and src.contracts:
            line = src.index.line_of(RECEIVE.search(masked).start()) if RECEIVE.search(masked) else src.contracts[0].line
            findings.append(
                self.make(
                    file,
                    rule="SF-002",
                    title="No native-value withdrawal path in %s" % src.contracts[0].name,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    line=line,
                    contract=src.contracts[0].name,
                    chain=chain,
                    description=(
                        "%s accepts native value (a `receive`/`fallback` or payable entry) but contains no call that "
                        "moves native value out. Native balance is therefore unaccounted: user ETH sent to the wrong "
                        "entry point, or dust from refunds, can never be recovered by anyone."
                        % src.contracts[0].name
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Send value through the ingress path; it never appears in the accounting mapping.",
                        "The contract's own admin cannot recover it either - there is no egress function.",
                    ],
                    patch=[
                        "Add an `onlyOwner`-gated `recoverEther()` or make every ingress path update accounting.",
                        "Reject unexpected value: drop `receive()` and let deposits go through one explicit function.",
                    ],
                    checklist_needles=["egress", "accounting", "recovery"],
                    tags=["stuck-funds", "native-value"],
                )
            )

        # --- SF-003 token recovery ignores the result -----------------------
        for m in re.finditer(r"token\.call\s*\(abi\.encodeWithSelector\(", masked):
            line = src.index.line_of(m.start())
            fn = fn_at(m.start())
            tail = masked[m.start():masked.find(";", m.end()) + 1]
            if "require" not in tail and "ok" not in tail:
                continue
            findings.append(
                self.make(
                    file,
                    rule="SF-003",
                    title="Token recovery result is never checked in %s()" % (fn.name if fn else "recover"),
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    line=line,
                    function=fn.name if fn else "",
                    contract=fn.contract if fn else "",
                    chain=chain,
                    description=(
                        "The recovery path does a low-level `token.call(...)` and then discards the boolean (the code "
                        "shape here is `(bool ok, ) = ...; ok;`). A non-standard or pausable token that returns false "
                        "makes the caller believe the rescue succeeded, so a failed recovery looks like a completed one."
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Choose a token that returns false instead of reverting (USDT-style) or that is paused.",
                        "The recovery call reports success while nothing moved.",
                    ],
                    patch=[
                        "`require(ok && (abi.decode(ret, (bool)) ), \"transfer failed\")` or use SafeERC20.safeTransfer.",
                        "Revert on any zero-length return data as well.",
                    ],
                    checklist_needles=["return", "safe", "non-standard"],
                    tags=["unchecked-call", "token-recovery"],
                )
            )
        return findings
