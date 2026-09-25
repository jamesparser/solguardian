"""Shared helpers for the Anchor/Rust detectors."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .rust import RsAccountsStruct, RsFunction, RsSource

PRIVILEGED_WORDS = (
    "authority", "admin", "owner", "operator", "treasury", "reporter", "oracle",
    "guardian", "signer", "proposer", "multisig", "fee_receiver", "withdraw", "payer",
)
VALUE_WORDS = ("lamports", "transfer", "mint", "burn", "close", "realloc", "withdraw", "credit")

CTX_ACCOUNT = re.compile(r"ctx\.accounts\.([A-Za-z_]\w*)")
CTX_ACCOUNT_BORROW = re.compile(r"ctx\.accounts\.([A-Za-z_]\w*)\s*(?:\.data\.borrow|\.to_account_info\(\)|\.key\(\)|\.lamports\(\))")
MUTATION = re.compile(
    r"ctx\.accounts\.([A-Za-z_]\w*)\s*(?:\.\s*(?P<attr>data|lamports|assign|transfer|msg)\b|\.([A-Za-z_]\w*)\s*(=|\+=|-=|/=|\*=))"
    r"|&mut\s+ctx\.accounts\.([A-Za-z_]\w*)"
    r"|ctx\.accounts\.([A-Za-z_]\w*)\.lamports_mut\b"
)


def handlers(src: RsSource) -> List[RsFunction]:
    return [f for f in src.functions if f.context_accounts]


def struct_for(src: RsSource, fn: RsFunction) -> Optional[RsAccountsStruct]:
    return src.accounts_struct_for(fn.context_accounts)


def referenced_accounts(fn: RsFunction) -> Set[str]:
    return set(CTX_ACCOUNT.findall(fn.body))


def mutated_accounts(fn: RsFunction) -> Set[str]:
    names: Set[str] = set()
    for m in MUTATION.finditer(fn.body):
        for group in m.groups():
            if group and re.fullmatch(r"[A-Za-z_]\w*", group or ""):
                names.add(group)
    return names


def privileged_hint(name: str) -> bool:
    low = name.lower()
    return any(word in low for word in PRIVILEGED_WORDS)


def value_hint(name: str) -> bool:
    low = name.lower()
    return any(word in low for word in VALUE_WORDS)


def signers_in(struct: Optional[RsAccountsStruct]) -> List[str]:
    if struct is None:
        return []
    return [f.name for f in struct.fields if f.is_signer]


def raw_fields(struct: Optional[RsAccountsStruct]) -> List:
    if struct is None:
        return []
    return [f for f in struct.fields if f.raw_account]


def lines_with(masked: str, pattern: str, flags: int = 0) -> List[Tuple[int, re.Match]]:
    """(line offset in the string, match) - callers translate with SourceIndex."""
    return [(m.start(), m) for m in re.finditer(pattern, masked, flags)]


def enclosing(src: RsSource, pos: int) -> Optional[RsFunction]:
    best: Optional[RsFunction] = None
    for fn in src.functions:
        if fn.body_start <= pos < fn.body_end:
            if best is None or fn.body_start > best.body_start:
                best = fn
    return best


def account_names(struct: Optional[RsAccountsStruct]) -> Dict[str, object]:
    if struct is None:
        return {}
    return {f.name: f for f in struct.fields}


def all_struct_fields(src: RsSource) -> Iterable[Tuple[RsAccountsStruct, object]]:
    for struct in src.structs:
        for field in struct.fields:
            yield struct, field
