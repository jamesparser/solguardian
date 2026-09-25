"""Solana detector: unsafe deserialization / raw account data.

Rules:
  DESER-001 raw pointer cast over borrowed account data (no owner, length or discriminator check)
  DESER-002 `try_deserialize` on a foreign account without validating its owner first
  DESER-003 account data read without a data_len / realloc guard

Skill: skills/solana-account-validation/SKILL.md
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.rsutil import handlers
from ..core.source import SourceFile

UNSAFE_CAST = re.compile(
    r"unsafe\s*\{[^}]*?\*\s*\(\s*(?P<expr>[A-Za-z0-9_.&()\[\]*\s]*?)\s*as\s*\*const\s+(?P<ty>[A-Za-z_]\w*)\s*\)[^}]*?\}"
)
DATA_BORROW = re.compile(r"(?P<acc>[A-Za-z_]\w*(?:\.\w+)*?)\s*\.\s*data\s*\.\s*borrow\s*\(\s*\)")
TRY_DESER = re.compile(r"(?P<expr>[A-Za-z0-9_.&()\[\]]*?)\s*\.\s*try_deserialize\b")
OWNER_CHECK = re.compile(r"\.owner\s*==|owner\s*!=|require!\s*\([^)]*owner|Address::from|impl_target|ITensor|iter_key")
LEN_CHECK = re.compile(r"data\.len\s*\(\s*\)\s*(>=|<|==)|try_from_slice|BORSH|discriminator|MIN_LEN|\bsize_of\b")


@register
class SolanaDeserializationDetector(Detector):
    id = "solana_deser"
    label = "Unsafe deserialization / remaining accounts"
    language = "rust"
    skill = "solana-account-validation"
    cwe = "CWE-125"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import rust

        src = rust.parse(file.rel, file.index)
        findings: List[dict] = []

        for fn in handlers(src):
            body = fn.body
            base = fn.body_start

            # --- DESER-001 ---------------------------------------------------
            for m in UNSAFE_CAST.finditer(body):
                line = src.index.line_of(base + m.start())
                context = src.index.masked[max(0, m.start() - 400):m.end() + 200]
                owner_ok = bool(OWNER_CHECK.search(context))
                len_ok = bool(LEN_CHECK.search(context))
                findings.append(
                    self.make(
                        file,
                        rule="DESER-001",
                        title="Unsafe cast of account data into `%s` in %s()" % (m.group("ty"), fn.name),
                        severity=Severity.CRITICAL if not (owner_ok and len_ok) else Severity.HIGH,
                        confidence=0.9 if not owner_ok else 0.7,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() reinterprets borrowed account bytes as `*const %s` and dereferences it. The layout of "
                            "an account is entirely caller-supplied: there is %s here, so the program reads memory it "
                            "never validated. That is a type-conflict / out-of-bounds read on a chain where the runtime "
                            "will not save you - and even when it only reads garbage, the value becomes trusted state."
                            % (
                                fn.name,
                                m.group("ty"),
                                "no owner check and no length/discriminator check"
                                if not (owner_ok and len_ok)
                                else ("only a partial check" if owner_ok != len_ok else "a check"),
                            )
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Create an account with the program's own PDA-looking address (or any short account) and pass it in.",
                            "The cast reads whatever bytes exist - attacker-chosen numbers become `limiter`, authority, etc.",
                            "Use the forged field to unlock the privileged branch of the handler.",
                        ],
                        patch=[
                            "Use Anchor's typed account (`Account<'info, %s>`), which verifies owner + discriminator." % m.group("ty"),
                            "If raw access is unavoidable: check `account.owner == &id()`, then "
                            "`%s::try_deserialize(&mut &data[8..])` and never dereference a cast." % m.group("ty"),
                            "Add `require!(data.len() >= 8 + size_of::<%s>(), ...)` before reading." % m.group("ty"),
                        ],
                        checklist_needles=["owner", "deserialize", "length"],
                        tags=["solana", "unsafe", "deserialization"],
                    )
                )

            # --- DESER-002 ---------------------------------------------------
            for m in TRY_DESER.finditer(body):
                context = src.index.masked[max(0, m.start() - 300):m.end() + 150]
                if OWNER_CHECK.search(context):
                    continue
                line = src.index.line_of(base + m.start())
                findings.append(
                    self.make(
                        file,
                        rule="DESER-002",
                        title="Account deserialised without an owner check in %s()" % fn.name,
                        severity=Severity.HIGH,
                        confidence=0.7,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() calls `try_deserialize` on account bytes without first asserting the account is owned "
                            "by this program. Any account whose bytes happen to Borsh-decode into the expected shape is "
                            "accepted, including one the attacker crafted under a different owner."
                            % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Craft an account owned by a different program that decodes into the expected struct.",
                            "The handler trusts the decoded fields because ownership was never verified.",
                        ],
                        patch=[
                            "`require!(acc.owner == &crate::id(), VaultError::InvalidOwner);` before deserialising.",
                            "Or use `Account<'info, T>` and let Anchor enforce it.",
                        ],
                        checklist_needles=["owner", "deserialize"],
                        tags=["solana", "deserialization", "owner-check"],
                    )
                )

            # --- DESER-003 ---------------------------------------------------
            for m in DATA_BORROW.finditer(body):
                context = src.index.masked[max(0, m.start() - 250):m.end() + 250]
                if LEN_CHECK.search(context) or OWNER_CHECK.search(context):
                    continue
                before = body[max(0, m.start() - 60):m.start()]
                if "ctx.accounts" not in before and "remaining_accounts" not in before:
                    continue
                line = src.index.line_of(base + m.start())
                findings.append(
                    self.make(
                        file,
                        rule="DESER-003",
                        title="Raw account data read with no length/owner guard in %s()" % fn.name,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() borrows `%s.data` directly. Reading foreign-owned account bytes without a length and "
                            "owner guard is how programs end up trusting an attacker-shaped layout; it also panics when "
                            "the account is smaller than the assumed struct, which is a cheap DoS on that path."
                            % (fn.name, m.group("acc"))
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Pass a zero-length or wrong-sized account in that slot to force the panic.",
                            "Or pass a hand-built payload whose fields you control.",
                        ],
                        patch=[
                            "Guard first: owner, `data.len() >= expected`, then parse with a checked deserializer.",
                            "Prefer typed accounts over manual `data.borrow()`.",
                        ],
                        checklist_needles=["length", "owner", "deserialize"],
                        tags=["solana", "deserialization", "panic"],
                    )
                )
        return findings
