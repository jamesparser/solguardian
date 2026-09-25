"""Shared EVM heuristics: what counts as an external call, a state write, or a guard.

Keeping these in one place means the detectors agree with each other (and with the
skills/ checklists) about vocabulary, which is where most false positives come from.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .solidity import SolFunction
from .textutil import SourceIndex

# --- external interaction ------------------------------------------------------
EXTERNAL_CALL = re.compile(
    r"(?P<recv>[A-Za-z_$][\w$.\[\]()\s]*?)"
    r"\s*\.\s*(?P<kind>call|delegatecall|staticcall|send|transfer)\s*"
    r"(?P<value>\{value:\s*[^}]+\})?\s*\(",
)
LOW_LEVEL_KINDS = {"call", "delegatecall", "staticcall"}
HIGH_LEVEL_KINDS = {"send", "transfer"}

# --- state mutation ------------------------------------------------------------
STATE_WRITE = re.compile(
    r"(?P<lhs>[A-Za-z_$][\w$.]*\s*(?:\[[^\]]*\])*)"
    r"\s*(?P<op>=(?!=)|\+=|-=|\*=|/=|%=)"
    r"\s*(?P<rhs>[^;]*)",
)
NON_STATE_LHS = {
    "require", "if", "else", "return", "emit", "uint256", "uint128", "int256", "address",
    "bool", "bytes32", "bytes", "string", "memory", "storage", "calldata", "for", "while",
    "mapping", "struct", "public", "external", "internal", "private", "constant",
}

ROLE_MAP = re.compile(r"\[\s*msg\.sender\s*\]|\bhasRole\b|\bonlyRole\b|\bhasAuthority\b")

GUARD_RE = re.compile(
    r"\b(require|assert)\s*\((?P<cond>[^;]*)\)", re.S
)
AUTH_GUARD = re.compile(
    r"(msg\.sender|tx\.origin|_msgSender\(\)|hasRole|onlyRole|hasAuthority|isAdmin|isOwner|owner|admin)"
)
MODIFIER_GUARD = re.compile(r"^(only|if|when|is|not|with|restricted|authorized|admin|owner|pausable|updatable)", re.I)
REENTRANCY_GUARD = re.compile(r"(nonReentrant|reentrancyGuard|_locked|unlocked|lockState|notEntered|entered)", re.I)

# reads of the native/ERC20 balance used as an accounting source
SPOT_PRICE = re.compile(r"(getReserves\(|getAmountsFor\(|getAmountOut\(|quote\(|spotPrice\(| getPrice\(|latestAnswer\(|getPriceOfAsset\()")


def strip_parens(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def call_sites(body_masked: str, offset: int, index: SourceIndex) -> List[Tuple[int, str, str, bool, bool]]:
    """(line, receiver, kind, is_low_level, moves_value) for every external interaction.

    `moves_value` is true for `send`/`transfer` and for any `call` carrying a
    `{value: ...}` option - the difference that separates a critical reentrancy from a
    medium one, so it is computed once here instead of being re-guessed per detector.
    """
    out: List[Tuple[int, str, str, bool, bool]] = []
    for m in EXTERNAL_CALL.finditer(body_masked):
        kind = m.group("kind")
        receiver = strip_parens(m.group("recv") or "")
        value_opt = bool(m.group("value"))
        out.append(
            (
                index.line_of(offset + m.start()),
                receiver,
                kind,
                kind in LOW_LEVEL_KINDS,
                value_opt or kind in ("send", "transfer"),
            )
        )
    return out


def state_writes(body_masked: str, offset: int, index: SourceIndex) -> List[Tuple[int, str, str]]:
    """(line, lhs, op) for assignments that look like storage writes."""
    out: List[Tuple[int, str, str]] = []
    for m in STATE_WRITE.finditer(body_masked):
        lhs = strip_parens(m.group("lhs"))
        head = lhs.split("[")[0].split(".")[0].strip()
        if head in NON_STATE_LHS or not head:
            continue
        if re.match(r"^(uint\d*|int\d*|bytes\d*|bool|address|string|mapping)\b", lhs):
            continue  # declaration, not a write
        out.append((index.line_of(offset + m.start()), lhs, m.group("op")))
    return out


def guards_in(fn: SolFunction) -> List[Tuple[int, str]]:
    """(line, condition text) for require/assert in a function body."""
    out: List[Tuple[int, str]] = []
    for m in GUARD_RE.finditer(fn.body):
        out.append((fn.source.index.line_of(fn.body_start + m.start()), strip_parens(m.group("cond"))))
    return out


OWNER_SCOPED = re.compile(
    r"(?:balanceOf|balances?|pending[A-Z]?\w*|shares?|positions?|allowance|\w+Of)\s*\[\s*msg\.sender\s*\]"
    r"\s*(?:>=|>|<|<=|-|\+)"
)


def has_auth_guard(fn: SolFunction, extra: Optional[str] = None) -> Tuple[bool, str]:
    """Does this function prove *who* is calling it?

    Proven by: an only*/restricted modifier, a role check, an explicit
    `msg.sender == ...` comparison, or - the implicit case auditors rely on -
    caller-scoped accounting (`require(balanceOf[msg.sender] >= amount)`), which makes
    the function only ever able to act on the caller's own state.
    """
    for mod in fn.modifiers:
        if MODIFIER_GUARD.match(mod):
            return True, "modifier %s()" % mod
    for _line, cond in guards_in(fn):
        if re.search(r"msg\.sender\s*==|==\s*msg\.sender|tx\.origin\s*==|\bhasRole\b|onlyRole|hasAuthority|isOwner|isAdmin", cond):
            return True, "require(%s)" % cond
        if re.search(r"\b\w*s\[\s*msg\.sender\s*\]\b|\b\w+\(msg\.sender\)", cond) and re.search(
            r">=|>|<|<=|!=|\brequire\b|,", cond
        ):
            return True, "caller-scoped check require(%s)" % cond
        if ROLE_MAP.search(cond):
            return True, "role check require(%s)" % cond
    if extra and re.search(r"\b%s\b" % extra, " ".join(fn.modifiers)):
        return True, "modifier %s()" % extra
    return False, ""


def has_reentrancy_guard(fn: SolFunction, contract_functions: List[SolFunction]) -> Tuple[bool, str]:
    for mod in fn.modifiers:
        if REENTRANCY_GUARD.search(mod):
            return True, "modifier %s()" % mod
    for line, cond in guards_in(fn):
        if REENTRANCY_GUARD.search(cond):
            return True, "require(%s) @L%d" % (cond, line)
    # transient/manual lock pattern: `locked = true` before the call and reset after
    writes = state_writes(fn.body, fn.body_start, fn.source.index)
    lock_writes = [w for w in writes if REENTRANCY_GUARD.search(w[1])]
    if lock_writes:
        return True, "manual lock flag %s" % lock_writes[0][1]
    return False, ""


def is_value_transfer(receiver: str, kind: str, value_group: Optional[str]) -> bool:
    if kind in ("send", "transfer") or value_group:
        return True
    return kind == "call" and bool(value_group)


def function_by_name(contract_fns: List[SolFunction], name: str) -> Optional[SolFunction]:
    for fn in contract_fns:
        if fn.name == name:
            return fn
    return None


def state_var_names(index: SourceIndex, masked: str) -> List[str]:
    """Top-level contract storage variables (best effort)."""
    names: List[str] = []
    for m in re.finditer(
        r"^\s*(?:[\w$.\[\]]+\s+)*(?:(?:public|private|internal|external)\s+)*"
        r"(?:mapping\s*\([^;=]*\)\s*)?(?:[\w$.\[\]]+\s+)*"
        r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:=)?[^;]*;",
        masked,
        re.M,
    ):
        name = m.group("name")
        if name in NON_STATE_LHS:
            continue
        if name not in names:
            names.append(name)
    return names
