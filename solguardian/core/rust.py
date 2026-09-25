"""AST-lite parser for Rust / Anchor programs.

Gives detectors: program entry functions (`pub fn ...(ctx: Context<Accounts>)`),
`#[derive(Accounts)]` structs with per-field type + `#[account(...)]` constraints, and
raw masked lines for CPI / math / deserialization heuristics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .textutil import SourceIndex

ACCOUNTS_STRUCT = re.compile(r"#\[derive\((?P<derives>[^)]*)\)\]\s*(?:pub\s+)?struct\s+(?P<name>[A-Za-z_]\w*)[^{]*\{")
FN_DECL = re.compile(
    r"\bpub\s+(?:unsafe\s+)?fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^<>]*(?:<[^<>]*>[^<>]*)*>)?"      # optional generics: fn foo<'info>(...)
    r"\s*\((?P<params>[^()]*(?:\([^()]*\)[^()]*)*)\)"
)
FIELD_RE = re.compile(
    r"^\s*(?P<attrs>(#\[[^\]]*\]\s*)*)pub\s+(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<type>[^,;]+)[,;]?\s*$"
)
ACCOUNT_ATTR = re.compile(r"#\[account\((?P<args>[^]]*)\)\]")
CONSTRAINT_TOKENS = (
    "init", "init_if_needed", "mut", "has_one", "associated_token", "mint", "token",
    "payer", "seeds", "bump", "program", "owner", "space", "realloc", "close",
)


def _context_struct(params: str) -> str:
    """Pull the accounts-struct name from `Context<X>` or `Context<'_, '_, '_, 'info, X<'info>>`."""
    start = re.search(r"Context\s*<", params)
    if not start:
        return ""
    depth = 0
    i = start.end() - 1
    while i < len(params):
        ch = params[i]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                inner = params[start.end():i]
                names = re.findall(r"\b([A-Z][A-Za-z0-9_]*)", inner)
                return names[-1] if names else ""
        i += 1
    names = re.findall(r"\b([A-Z][A-Za-z0-9_]*)", params[start.end():])
    return names[-1] if names else ""


@dataclass
class RsField:
    name: str
    type: str
    line: int
    attrs: str

    @property
    def account_constraints(self) -> List[str]:
        m = ACCOUNT_ATTR.search(self.attrs)
        if not m:
            return []
        text = m.group("args")
        tokens = []
        for tok in re.split(r"[,=]", text):
            tok = tok.strip()
            base = tok.split("(")[0].strip()
            if base:
                tokens.append(base)
        return tokens

    def has_constraint(self, token: str) -> bool:
        m = ACCOUNT_ATTR.search(self.attrs)
        if not m:
            return False
        return bool(re.search(r"\b%s\b" % re.escape(token), m.group("args")))

    @property
    def raw_account(self) -> bool:
        t = self.type.replace(" ", "")
        return t.startswith("AccountInfo") or t == "UncheckedAccount" or t.startswith("UncheckedAccount")

    @property
    def is_signer(self) -> bool:
        return "Signer" in self.type

    @property
    def base_type(self) -> str:
        t = re.sub(r"<.*", "", self.type).strip()
        return t.replace("Box(", "").replace(")", "").strip()


def parse_fields(body: str, body_start: int, index: SourceIndex) -> List[RsField]:
    """Fields of an accounts struct, with their attributes attached.

    Anchor attributes are usually multi-line:

        #[account(
            mut,
            has_one = authority,
            seeds = [b"vault", authority.key().as_ref()],
            bump = config.bump
        )]
        pub vault_config: Account<'info, VaultConfig>,

    Single-line regex over the field cannot see those, so every rule that asks "is this PDA
    seeds-verified?" would be wrong. Accumulate each `#[...]` group (tracking bracket depth)
    and bind it to the next declared field.
    """
    fields: List[RsField] = []
    pending: List[str] = []
    depth = 0
    buf = ""
    for line_match in re.finditer(r"[^\n]*", body):
        line = line_match.group(0)
        lineno = index.line_of(body_start + 1 + line_match.start())
        stripped = line.strip()
        if depth == 0 and stripped.startswith("#["):
            buf = ""
            depth = stripped.count("[") - stripped.count("]")
            buf += line + "\n"
            if depth <= 0:
                depth = 0
                pending.append(buf)
                buf = ""
            continue
        if depth > 0:
            buf += line + "\n"
            depth += line.count("[") - line.count("]")
            if depth <= 0:
                depth = 0
                pending.append(buf)
                buf = ""
            continue
        fm = FIELD_RE.match(line)
        if fm:
            attrs = (fm.group("attrs") or "") + "".join(pending)
            pending = []
            fields.append(
                RsField(
                    name=fm.group("name"),
                    type=re.sub(r"\s+", "", fm.group("type")),
                    line=lineno,
                    attrs=attrs,
                )
            )
        elif stripped and not stripped.startswith("//"):
            pending = []
    return fields


@dataclass
class RsAccountsStruct:
    name: str
    line: int
    body_start: int
    body_end: int
    fields: List[RsField]
    derives: List[str]
    source: "RsSource"

    def field(self, name: str) -> Optional[RsField]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def account_fields(self) -> List[RsField]:
        return [f for f in self.fields if ACCOUNT_ATTR.search(f.attrs) or not f.attrs]


@dataclass
class RsFunction:
    name: str
    line: int
    body_start: int
    body_end: int
    params: str
    context_accounts: str = ""      # Context<X> name if present
    source: Optional["RsSource"] = None

    @property
    def body(self) -> str:
        if self.source is None or self.body_end <= self.body_start:
            return ""
        return self.source.index.masked[self.body_start:self.body_end]

    @property
    def body_line_range(self) -> Tuple[int, int]:
        if self.source is None or self.body_end <= self.body_start:
            return (self.line, self.line)
        return (self.source.index.line_of(self.body_start), self.source.index.line_of(self.body_end - 1))

    def statements(self) -> List[Tuple[int, str]]:
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
                    out.append(
                        (self.source.index.line_of(self.body_start + chunk_start),
                         re.sub(r"\s+", " ", raw))
                    )
                chunk_start = i + 1
        return out


@dataclass
class RsSource:
    path: str
    index: SourceIndex
    structs: List[RsAccountsStruct] = field(default_factory=list)
    functions: List[RsFunction] = field(default_factory=list)
    is_anchor: bool = False
    uses_anchor_lang: bool = False

    def accounts_struct_for(self, name: str) -> Optional[RsAccountsStruct]:
        for s in self.structs:
            if s.name == name:
                return s
        return None

    def handler_functions(self) -> List[RsFunction]:
        return [f for f in self.functions if f.context_accounts]


def parse(path: str, index: SourceIndex) -> RsSource:
    src = RsSource(path=path, index=index)
    masked = index.masked
    src.uses_anchor_lang = bool(re.search(r"use\s+anchor_lang", masked))
    src.is_anchor = src.uses_anchor_lang or "#[program]" in masked or "Context<" in masked

    for m in ACCOUNTS_STRUCT.finditer(masked):
        start, end = index.block(m.end() - 1)
        body = masked[start:end]
        fields: List[RsField] = parse_fields(body, start, index)
        src.structs.append(
            RsAccountsStruct(
                name=m.group("name"),
                line=index.line_of(m.start()),
                body_start=start,
                body_end=end,
                fields=fields,
                derives=[d.strip() for d in m.group("derives").split(",")],
                source=src,
            )
        )

    for m in FN_DECL.finditer(masked):
        brace = masked.find("{", m.end())
        semi = masked.find(";", m.end())
        if brace == -1 or (semi != -1 and semi < brace):
            continue
        _, end = index.block(brace)
        params = re.sub(r"\s+", " ", m.group("params"))
        ctx_name = _context_struct(params)
        src.functions.append(
            RsFunction(
                name=m.group("name"),
                line=index.line_of(m.start()),
                body_start=brace,
                body_end=end,
                params=params,
                context_accounts=ctx_name,
                source=src,
            )
        )

    return src
