"""AST-lite parser for Solidity.

Not a compiler. It gives detectors exactly what they need with correct line numbers:
contract scope ranges, function/modifier declarations, their visibility, mutability,
modifier list, body span, and a statement index per function. Implemented on the
comment/string-masked source so matches never come from prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .textutil import SourceIndex

CONTRACT_RE = re.compile(
    r"\b(?P<kind>contract|library|interface|abstract\s+contract)\s+(?P<name>[A-Za-z_$][\w$]*)\b"
)
CONTRACT_START_BRACE = re.compile(r"\b(?P<kind>contract|library|interface)\s+(?P<name>[A-Za-z_$][\w$]*)[^{;]*\{")
FUNC_DECL = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^()]*(?:\([^()]*\)[^()]*)*)\)"
    r"(?P<tail>[^;{}]*)"
)
MODIFIER_USE_RE = re.compile(r"\b(?P<name>[A-Za-z_$][\w$]*)\b(?P<args>\([^{}]*\))?")
STATE_VAR = re.compile(
    r"^(?!\s*(?://))(?P<attrs>(?:public|private|internal|external|constant|immutable|payable)\s+)*"
    r"(?P<type>[A-Za-z_$][\w$.\[\]]*(?:\s+mapping\s*\([^)]*\))?)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?P<init>=[^;]*)?;"
)


@dataclass
class SolFunction:
    name: str
    contract: str
    line: int                      # declaration line (1-indexed)
    body_start: int                # char index of '{'
    body_end: int                  # char index after '}'
    params: str
    modifiers: List[str]
    visibility: str
    mutability: str
    source: Optional["SolSource"] = None

    # -- body helpers ----------------------------------------------------
    @property
    def has_body(self) -> bool:
        return self.body_end > self.body_start

    @property
    def body(self) -> str:
        return self.source.masked[self.body_start:self.body_end]

    @property
    def body_line_range(self) -> Tuple[int, int]:
        if not self.has_body:
            return (self.line, self.line)
        return (self.source.index.line_of(self.body_start), self.source.index.line_of(self.body_end - 1))

    def is_payable(self) -> bool:
        return "payable" in self.mutability or "payable" in " ".join(self.modifiers)

    def uses_modifier(self, *names: str) -> bool:
        lowered = {m.lower() for m in self.modifiers}
        return any(n.lower() in lowered for n in names)

    def statements(self) -> List[Tuple[int, str]]:
        """(line, statement text) for top-level-ish statements inside the body."""
        out: List[Tuple[int, str]] = []
        text = self.body
        depth = 0
        chunk_start = 0
        for i, ch in enumerate(text):
            if ch in "({[":
                depth += 1
            elif ch in ")}]":
                depth -= 1
            elif ch == ";" and depth <= 1:
                raw = text[chunk_start:i].strip()
                if raw:
                    line = self.source.index.line_of(self.body_start + chunk_start)
                    out.append((line, re.sub(r"\s+", " ", raw)))
                chunk_start = i + 1
        tail = text[chunk_start:].strip()
        if tail and len(tail) > 2:
            out.append(
                (self.source.index.line_of(self.body_start + chunk_start), re.sub(r"\s+", " ", tail))
            )
        return out

    def __str__(self) -> str:  # pragma: no cover
        return "function %s.%s @L%d" % (self.contract, self.name, self.line)


@dataclass
class SolContract:
    name: str
    kind: str
    line: int
    body_start: int
    body_end: int
    source: "SolSource"

    @property
    def body(self) -> str:
        return self.source.masked[self.body_start:self.body_end]


@dataclass
class SolSource:
    path: str
    index: SourceIndex
    pragmas: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    contracts: List[SolContract] = field(default_factory=list)
    functions: List[SolFunction] = field(default_factory=list)
    state_vars: Dict[str, str] = field(default_factory=dict)   # name -> declaration line tag

    # ------------------------------------------------------------------
    @property
    def masked(self) -> str:
        return self.index.masked

    @property
    def text(self) -> str:
        return self.index.raw

    def contract_for(self, pos: int) -> Optional[SolContract]:
        best: Optional[SolContract] = None
        for c in self.contracts:
            if c.body_start <= pos < c.body_end:
                if best is None or c.body_start > best.body_start:
                    best = c
        return best

    def functions_in(self, contract: str) -> List[SolFunction]:
        return [f for f in self.functions if f.contract == contract]

    @property
    def external_state_writers(self) -> List[str]:
        return [f.name for f in self.functions if f.visibility in ("public", "external")]


def parse(path: str, index: SourceIndex) -> SolSource:
    src = SolSource(path=path, index=index)
    masked = index.masked

    src.pragmas = [m.group(0).strip() for m in re.finditer(r"pragma[^;]*;", masked)]
    src.imports = [m.group(1).strip() for m in re.finditer(r'import\s+["\']([^"\']+)["\']', masked)]

    # contracts: take the first '{' after the header, then balance it
    consumed: List[Tuple[int, int]] = []
    for m in CONTRACT_START_BRACE.finditer(masked):
        start, end = index.block(m.end() - 1)
        if any(s <= m.start() < e for s, e in consumed):
            continue
        consumed.append((start, end))
        src.contracts.append(
            SolContract(
                name=m.group("name"),
                kind=m.group("kind"),
                line=index.line_of(m.start()),
                body_start=start,
                body_end=end,
                source=src,
            )
        )

    # functions
    for m in FUNC_DECL.finditer(masked):
        contract = src.contract_for(m.start())
        if contract is None:
            continue
        if not (contract.body_start <= m.start() < contract.body_end):
            continue
        tail = m.group("tail") or ""
        # body starts at first '{' after the signature; ';' means abstract/interface decl
        brace = masked.find("{", m.end())
        semi = masked.find(";", m.end())
        if brace == -1:
            continue
        if semi != -1 and semi < brace:
            brace = -1  # no body (interface / abstract)
        visibility = "internal"
        for vis in ("external", "public", "internal", "private"):
            if re.search(r"\b%s\b" % vis, tail):
                visibility = vis
                break
        mutability = ""
        mm = re.search(r"\b(pure|view|payable|nonpayable)\b", tail)
        if mm:
            mutability = mm.group(1)

        modifiers: List[str] = []
        # the `tail` group already swallowed `visibility modifiers returns(...)`
        mod_zone = tail
        mod_zone = re.sub(r"\b(returns)\b[^()]*\([^()]*\)", " ", mod_zone)
        for cand in MODIFIER_USE_RE.finditer(mod_zone):
            word = cand.group("name")
            if word in ("public", "external", "internal", "private", "pure", "view",
                        "payable", "nonpayable", "virtual", "override", "returns"):
                continue
            modifiers.append(word)

        src.functions.append(
            SolFunction(
                name=m.group("name"),
                contract=contract.name,
                line=index.line_of(m.start()),
                body_start=brace if brace != -1 else -1,
                body_end=(brace + 1) if brace != -1 else -1,
                params=re.sub(r"\s+", " ", m.group("params")).strip(),
                modifiers=modifiers,
                visibility=visibility,
                mutability=mutability,
                source=src,
            )
        )
        if brace != -1:
            _, fn_end = index.block(brace)
            src.functions[-1].body_end = fn_end

    # state variables (simple top-level declarations inside contract body)
    for c in src.contracts:
        for m in STATE_VAR.finditer(c.body):
            name = m.group("name")
            if name in ("function", "mapping", "public", "private", "internal"):
                continue
            src.state_vars.setdefault(name, "%s:%d" % (c.name, index.line_of(c.body_start + m.start())))

    return src
