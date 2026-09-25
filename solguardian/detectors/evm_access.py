"""EVM detector: access control.

Rules:
  AC-001 privileged / value-moving function reachable by anyone (no modifier, no sender check)
  AC-002 tx.origin used for authorisation
  AC-003 security-critical parameter (oracle, fee, cap, reserve) writable by anyone
  AC-004 user-facing entry point that writes state without any check (trigger / griefing note)

Deliberate de-duplication with the other packs: a function whose only privileged behaviour
is a `delegatecall` or a `selfdestruct` is owned by `evm_delegatecall` / `evm_selfdestruct`,
and a logic-pointer write is owned by the proxy pack, so the same root cause is not counted
three times in one report.

Skill: skills/access-control/SKILL.md
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..core.detector import Detector, register
from ..core.evmutil import has_auth_guard, state_writes, strip_parens
from ..core.finding import Severity
from ..core.source import SourceFile, detect_chain
from ..core.solidity import SolFunction, SolSource

ADMIN_NAME = re.compile(
    r"^(admin|owner|set[A-Z]|upgrade|migrate|decommission|drain|recover|sweep|pause|unpause|mint|burn|"
    r"grant|revoke|initialize|init|execute|emergency|register|whitelist|blacklist|reserve|withdrawAll|close)",
)
SELF_SERVICE = re.compile(r"^(withdraw|deposit|claim|refund|redeem|pay|close|liquidate|repay|borrow|open|update|sync|harvest|stake|unlock|cancel)")
SENSITIVE_STATE = re.compile(
    r"(owner|admin|oracle|priceFeed|feed|reserve|fee|cap|limit|authority|role|paused|mint|supply|treasury|signer|upgrader|implementation|logic|beacon)",
    re.I,
)
# already owned by another detector pack
OTHER_PACK_BODY = re.compile(r"\b(selfdestruct|suicide|delegatecall)\s*\(")
LOGIC_POINTER = re.compile(r"^\s*(implementation|_implementation|logic|beacon|_BEACON)\b")
VALUE_MOVE = re.compile(
    r"(?P<recv>[A-Za-z_$][\w$.\[\]()]*?)\s*\.\s*(?P<kind>call|send|transfer)\s*(?P<val>\{[^}]*\})?\s*\((?P<args>[^;]*)\)"
)
GENERIC_AUTH_COMPARE = re.compile(
    r"(==|!=)\s*(owner|admin|authority|treasury|signer|governance|timelock|_owner|pendingOwner|expected\w*)\b"
    r"|\b(ecrecover|tryRecover|recover)\s*\("
)


def _value_destinations(fn: SolFunction) -> List[str]:
    """Who can end up receiving the value this function moves?

    native push (`payable(x).transfer(v)`, `to.call{value: v}("")`, `x.send(v)`)
        -> x, i.e. the receiver / the unwrapped payable() argument
    token-style call (`token.transfer(user, amt)`, `token.call(selector)`)
        -> the first argument when it names a recipient, otherwise the receiver
    """
    dests: List[str] = []
    for m in VALUE_MOVE.finditer(fn.body):
        kind = m.group("kind")
        recv = re.sub(r"\s+", "", m.group("recv") or "")
        raw_args = (m.group("args") or "").split(",")
        first = re.sub(r"\s+", "", raw_args[0]) if raw_args and raw_args[0].strip() else ""
        inner = re.search(r"(?:payable|address)\s*\(\s*([^)]*)\)", recv)
        native = bool(m.group("val")) or kind == "send" or bool(inner)
        if inner:
            dests.append(re.sub(r"\s+", "", inner.group(1)))
        elif native:
            dests.append(recv)
        elif first and first != '""' and re.match(r"^[A-Za-z_$][\w$\.\[\]()]*$", first):
            dests.append(first)
        else:
            dests.append(recv)
    return dests


def _dest_is_attacker_influenceable(src, fn: SolFunction, dest: str) -> bool:
    """Can an unprivileged caller decide where this value goes?

    True when the destination is an instruction argument, or a storage variable that some
    *unguarded* function writes. A destination only ever assigned by the constructor or by an
    `onlyOwner` setter is admin-controlled: sending to it permissionless is a sequencing note,
    not an unauthenticated drain, and reporting it as AC-001 is the false positive this pack
    must avoid.
    """
    if dest in _params(fn):
        return True
    if dest in ("msg.sender", "address(this)", "tx.origin", ""):
        return False
    writers = [
        other
        for other in src.functions
        if other.has_body
        and other.name != fn.name
        and re.search(r"\b%s\s*(?:=[^=]|\+=)" % re.escape(dest), other.body)
    ]
    if not writers:
        return False  # constructor-only assignment (constructors are not matched as functions)
    return any(not has_auth_guard(other)[0] for other in writers)


def _params(fn: SolFunction) -> List[str]:
    names: List[str] = []
    for part in fn.params.split(","):
        m = re.findall(r"([A-Za-z_$][\w$]*)\s*$", part.strip())
        if m:
            names.append(m[-1])
    return names


@register
class EvmAccessControlDetector(Detector):
    id = "evm_access"
    label = "Access control"
    language = "solidity"
    skill = "access-control"
    cwe = "CWE-284"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import solidity

        src = solidity.parse(file.rel, file.index)
        chain = detect_chain(file.rel, file.text)
        findings: List[dict] = []

        for fn in src.functions:
            if not fn.has_body or fn.visibility not in ("public", "external"):
                continue
            guarded, why = has_auth_guard(fn)
            if not guarded and GENERIC_AUTH_COMPARE.search(fn.body):
                # signature / recovered-address authorisation: handled by evm_sig_replay
                self._maybe_tx_origin(file, fn, src, chain, findings)
                continue

            writes = state_writes(fn.body, fn.body_start, src.index)
            sensitive = [w for w in writes if SENSITIVE_STATE.search(w[1])]
            dests = _value_destinations(fn)
            admin_name = bool(ADMIN_NAME.match(fn.name))
            self_service = bool(SELF_SERVICE.match(fn.name))
            moves_value = bool(dests)
            # A function whose every ledger read is keyed on msg.sender can only ever move the
            # caller's own value. That scoping is itself the authorisation (pull payments).
            scoped_reads = bool(re.search(r"\[\s*msg\.sender\s*\]", fn.body))

            if guarded:
                self._maybe_tx_origin(file, fn, src, chain, findings)
                continue

            # a function whose privileged behaviour is a delegatecall/selfdestruct is owned
            # by the more specific pack; don't double-count the same root cause
            if OTHER_PACK_BODY.search(fn.body) and not sensitive:
                self._maybe_tx_origin(file, fn, src, chain, findings)
                continue

            # ---------------- AC-001: value exit with no authorisation ---------
            if moves_value:
                only_self = all(d == "msg.sender" for d in dests)
                influenceable = [d for d in dests if _dest_is_attacker_influenceable(src, fn, d)]
                if (only_self or scoped_reads) and not influenceable:
                    pass  # self-service / pull-payment: caller-scoped by construction
                elif dests and not influenceable:
                    # destination is constructor/admin-controlled -> not an unauthenticated
                    # drain; unassigned-destination cases belong to skills/fund-recovery
                    pass
                else:
                    # "the destination is a parameter" only de-risks a call when the function also
                    # proves the caller owns what it spends. adminDrain(to, amount) takes a
                    # destination *and* zeroes the ledger: that is a drain, not a griefing path.
                    ledger_key = any(d in _params(fn) for d in dests)
                    scoped = bool(re.search(r"\[\s*msg\.sender\s*\]", fn.body))
                    zeroes = bool(re.search(r"(totalDeposits|totalSupply|balanceOf)\s*(=|-=)\s*", fn.body)) and not scoped
                    if scoped:
                        severity, confidence = Severity.MEDIUM, 0.65
                    elif ledger_key and not zeroes:
                        severity, confidence = Severity.HIGH, 0.75
                    else:
                        severity, confidence = Severity.CRITICAL, 0.9
                    findings.append(
                        self.make(
                            file,
                            rule="AC-001",
                            title="Missing access control on %s()" % fn.name,
                            severity=severity,
                            confidence=confidence,
                            line=fn.line,
                            end_line=fn.body_line_range[1],
                            function=fn.name,
                            contract=fn.contract,
                            chain=chain,
                            description=(
                                "%s() is %s, moves value to `%s`, and writes %s, yet nothing in the function proves who "
                                "the caller is: no `only*` modifier, no `require(msg.sender == ...)`, no role check, and no "
                                "caller-scoped accounting. So the state it touches is not limited to the caller's own "
                                "balance - any address can call it. %s"
                                % (
                                    fn.name,
                                    fn.visibility,
                                    "`".join(dests[:2]),
                                    strip_parens(writes[0][1]) if writes else "contract state",
                                    "This is a total-loss path: the destination is fully caller-chosen."
                                    if severity is Severity.CRITICAL
                                    else "The destination is a named user, so the direct risk is griefing/replay of that "
                                    "user's claim rather than an empty contract.",
                                )
                            ),
                            evidence=file.line_text(fn.line),
                            exploit=[
                                "Call %s() from an EOA you control, with the arguments you want." % fn.name,
                                "No key compromise or front-running is required - the entry point is permissionless.",
                                "Repeat until the shared balance is gone (or until every victim's claim has been consumed).",
                            ],
                            patch=[
                                "Add `onlyOwner` / AccessControl `onlyRole(GUARDIAN_ROLE)` to %s()." % fn.name,
                                "Or make the function self-service: derive the destination from `msg.sender` and let "
                                "users pull their own funds.",
                                "Emit an event and add a per-call cap so a wrong grant of authority is bounded.",
                            ],
                            checklist_needles=["modifier", "authenticated", "state"],
                            tags=["access-control", "value-flow"],
                        )
                    )

            # ---------------- AC-003: security-critical parameter --------------
            elif sensitive:
                logic_ptr = [w for w in sensitive if LOGIC_POINTER.match(w[1])]
                if logic_ptr:
                    pass  # owned by skills/delegatecall-proxy (DC-002)
                else:
                    touched = ", ".join(sorted({strip_parens(w[1]) for w in sensitive})[:3])
                    findings.append(
                        self.make(
                            file,
                            rule="AC-003",
                            title="Missing access control on %s() (writable: %s)" % (fn.name, touched),
                            severity=Severity.HIGH,
                            confidence=0.82,
                            line=fn.line,
                            end_line=fn.body_line_range[1],
                            function=fn.name,
                            contract=fn.contract,
                            chain=chain,
                            description=(
                                "%s() rewrites security-critical storage (%s) with no authorisation check. An unguarded "
                                "price feed, fee, cap or reserve parameter is the usual first step of a composed exploit: "
                                "the attacker does not break the vault directly, they turn the vault's own inputs until a "
                                "legitimate code path pays them. On %s treat HyperCore-style reads with the same caution."
                                % (fn.name, touched, "HyperEVM" if chain == "hyperevm" else "this chain")
                            ),
                            evidence=file.line_text(fn.line),
                            exploit=[
                                "Call %s() to install a price/parameter you control." % fn.name,
                                "Then trigger the normal accounting path (mint, redeem, liquidate) that reads it.",
                            ],
                            patch=[
                                "Guard with `onlyOwner`/role, plus an `Upgraded`/`ParamSet` event.",
                                "Add a max-move bound and a timelock for security-critical values.",
                                "Prefer AccessControl roles over a single `owner` address.",
                            ],
                            checklist_needles=["modifier", "state", "bound"],
                            tags=["access-control", "config"],
                        )
                    )

            # ---------------- AC-001 / AC-004: admin-named or state-writing ----
            elif admin_name and writes:
                findings.append(
                    self.make(
                        file,
                        rule="AC-001",
                        title="Missing access control on %s()" % fn.name,
                        severity=Severity.HIGH,
                        confidence=0.78,
                        line=fn.line,
                        end_line=fn.body_line_range[1],
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() has an admin-shaped name and writes %s, but is %s with no authorisation check. Either "
                            "the guard was forgotten, or the naming implies a role the code never enforces - both end the "
                            "same way for users."
                            % (fn.name, ", ".join(sorted({strip_parens(w[1]) for w in writes})[:3]) or "state", fn.visibility)
                        ),
                        evidence=file.line_text(fn.line),
                        exploit=[
                            "Call %s() directly; the contract believes you are the operator." % fn.name,
                        ],
                        patch=[
                            "Add the modifier the name implies (`onlyAdmin`/`onlyKeeper`).",
                            "Or rename + document it as permissionless if that is really the design.",
                        ],
                        checklist_needles=["modifier", "authenticated"],
                        tags=["access-control"],
                    )
                )
            elif self_service and writes and not dests and re.search(r"address\s+\w+", fn.params):
                findings.append(
                    self.make(
                        file,
                        rule="AC-004",
                        title="Unauthenticated trigger on user-facing %s()" % fn.name,
                        severity=Severity.LOW,
                        confidence=0.4,
                        line=fn.line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() updates state for a caller-supplied subject without any check that the caller is that "
                            "subject or a keeper. Value only ever moves to the named user, so this is not a drain - it is a "
                            "sequencing/griefing surface: anyone can trigger another user's path early, and MEV searchers "
                            "can take the profitable ordering. Graded low because the funds themselves stay correct."
                            % fn.name
                        ),
                        evidence=file.line_text(fn.line),
                        exploit=[
                            "Watch for a victim's profitable state change and call %s() first yourself." % fn.name,
                            "Profit comes from ordering, not from moving their funds.",
                        ],
                        patch=[
                            "Require `msg.sender == user` or an operator role.",
                            "Or make the effect idempotent so early triggering is harmless.",
                        ],
                        checklist_needles=["trigger", "keeper"],
                        tags=["access-control", "review-note"],
                    )
                )

            self._maybe_tx_origin(file, fn, src, chain, findings)
        return findings

    # ------------------------------------------------------------------
    def _maybe_tx_origin(
        self,
        file: SourceFile,
        fn: SolFunction,
        src: SolSource,
        chain: str,
        findings: List[dict],
    ) -> None:
        for m in re.finditer(r"\btx\.origin\b", fn.body):
            line = src.index.line_of(fn.body_start + m.start())
            cond = src.index.line_text(line)
            if not re.search(r"require|if|==|!=", cond):
                continue  # logging / events only
            findings.append(
                self.make(
                    file,
                    rule="AC-002",
                    title="tx.origin used for authorisation in %s()" % fn.name,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    line=line,
                    function=fn.name,
                    contract=fn.contract,
                    chain=chain,
                    description=(
                        "%s() authorises the caller with `tx.origin` instead of `msg.sender`. tx.origin is the EOA that "
                        "started the transaction and it keeps equaling the owner even when the owner is tricked into "
                        "calling a malicious contract first. Any phishing-style interaction therefore hands over full "
                        "authorisation of this function, which is exactly why Solidity deprecated the pattern."
                        % fn.name
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Lure the authorised EOA into calling a contract you control (a small incentive is enough).",
                        "From that contract's fallback, call %s(): `tx.origin == owner` still holds." % fn.name,
                        "Authorisation is granted while `msg.sender` is your contract.",
                    ],
                    patch=[
                        "Compare against `msg.sender`.",
                        "If anti-contract phishing resistance is genuinely wanted, add `require(tx.origin == msg.sender)` "
                        "*in addition to* the sender check, never instead of it.",
                    ],
                    checklist_needles=["tx.origin", "sender"],
                    tags=["access-control", "tx-origin"],
                )
            )
