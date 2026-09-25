"""Solana detector: missing signer checks.

Skill: skills/solana-account-validation/SKILL.md
Skills also reference skills/severity-grading/SKILL.md for the ranking model.

Rules:
  SIGNER-001 privileged account is `UncheckedAccount` / `AccountInfo` and never `Signer`
  SIGNER-002 state/value mutation authorised only by an unvalidated account key
  SIGNER-003 manual `is_signer` check missing where the handler trusts a key argument
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.rsutil import (
    handlers,
    mutated_accounts,
    privileged_hint,
    raw_fields,
    signers_in,
    struct_for,
    value_hint,
)
from ..core.source import SourceFile

PROGRAM_LIKE_FIELD = re.compile(
    r"^(token_program|system_program|rent_program|program_authority|.*_program$|.*_authority_pda)$|^(vault_program|signer_program)$"
)
IS_SIGNER_CHECK = re.compile(r"\.is_signer\b|require!\s*\(\s*\w+\.is_signer|SignatureMissing|MissingSigner")
PRIVILEGED_OPS = re.compile(
    r"(\.lamports_mut\s*\(|\.assign\s*\(|lamports\s*\(\s*\)\s*[\+\-]=|ctx\.accounts\.\w+\.\w+\s*=[^=]|"
    r"\+=|-=|token::(mint|burn|transfer|close_account|set_authority))"
)


@register
class SolanaSignerDetector(Detector):
    id = "solana_signer"
    label = "Missing signer checks"
    language = "rust"
    skill = "solana-signer"
    cwe = "CWE-287"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import rust

        src = rust.parse(file.rel, file.index)
        findings: List[dict] = []

        for fn in handlers(src):
            struct = struct_for(src, fn)
            if struct is None:
                continue
            body = fn.body
            checked = bool(IS_SIGNER_CHECK.search(body))
            signers = signers_in(struct)
            mutated = mutated_accounts(fn)
            raws = raw_fields(struct)

            for field in raws:
                # A program / PDA slot is not meant to be a signer; the CPI and authority
                # packs cover those. Demanding Signer<'info>' here is the classic noise maker.
                if PROGRAM_LIKE_FIELD.match(field.name):
                    continue
                # A PDA whose derivation is verified by `seeds` is authorised by its address,
                # and the `*_authority` / `*_payer` slot of a CPI struct is that PDA - it is
                # signed by the program, not by the client, so `Signer<'info>` is wrong there.
                if "seeds" in (field.attrs or ""):
                    continue
                if field.name.endswith("_authority") or field.name.endswith("_payer"):
                    continue
                privileged = privileged_hint(field.name)
                touched = field.name in mutated or bool(
                    re.search(r"ctx\.accounts\.%s\b" % field.name, body)
                )
                if not (privileged or touched):
                    continue
                if checked and re.search(r"%s[\w.]*\.is_signer" % field.name, body):
                    continue
                # does any *other* signer exist, and is this field merely read?
                mutates = bool(re.search(r"ctx\.accounts\.%s\s*\.\s*(lamports_mut|data|assign)" % field.name, body)) or \
                    bool(re.search(r"ctx\.accounts\.%s\.[A-Za-z_]\w*\s*(\+=|-=|=)" % field.name, body))
                if not privileged and not mutates:
                    continue
                severity = Severity.CRITICAL if mutates and not signers else (
                    Severity.HIGH if privileged and not signers else Severity.MEDIUM
                )
                findings.append(
                    self.make(
                        file,
                        rule="SIGNER-001",
                        title="Missing signer check on `%s` in %s()" % (field.name, fn.name),
                        severity=severity,
                        confidence=0.88 if not signers else 0.6,
                        line=field.line,
                        function=fn.name,
                        contract=src.path.split("/")[-1] if src.path else "",
                        chain="solana",
                        description=(
                            "`%s` is declared as %s in the `%s` accounts struct, so Anchor cannot prove it was signed. "
                            "%s() still uses it to authorise %s. On Solana an unsigned account is just bytes anyone can "
                            "craft: an attacker supplies their own account with the right key/shape and the program "
                            "accepts the instruction. The handler contains no `is_signer` check either%s."
                            % (
                                field.name,
                                field.type,
                                struct.name,
                                fn.name,
                                "a privileged state change" if mutates else "a privileged decision",
                                " and no `Signer` account exists in the struct at all" if not signers else "",
                            )
                        ),
                        evidence=file.line_text(field.line),
                        exploit=[
                            "Build the instruction with a self-created account in the `%s` slot (it does not need the "
                            "real owner's key pair). " % field.name,
                            "Send the transaction - the program sees a well-formed account and no signature requirement fails.",
                            "Repeat for every victim's data the handler writes through that account.",
                        ],
                        patch=[
                            "Type it as `Signer<'info>`: `%s: Signer<'info>` (Anchor enforces the signature)." % field.name,
                            "Or add an explicit `require!(ctx.accounts.%s.is_signer, VaultError::MissingSigner);`." % field.name,
                            "Better: bind it to state with `has_one = %s` plus a PDA `seeds` constraint." % field.name,
                        ],
                        checklist_needles=["signer", "authority", "mutation"],
                        tags=["solana", "missing-signer"],
                    )
                )

            # SIGNER-002: handler mutates value/state with zero signers in the struct
            if not signers and PRIVILEGED_OPS.search(body) and raws:
                op = PRIVILEGED_OPS.search(body)
                line = src.index.line_of(fn.body_start + op.start())
                findings.append(
                    self.make(
                        file,
                        rule="SIGNER-002",
                        title="%s() writes state / moves value with no `Signer` account at all" % fn.name,
                        severity=Severity.CRITICAL,
                        confidence=0.85,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "The `%s` constraint list contains no `Signer`, yet %s() performs a privileged operation "
                            "(`%s`). Permissionless mutation is exactly the class of bug that empties programs on "
                            "Solana: there is no `msg.sender` equivalent to fall back on, so the account list is the "
                            "only authorisation surface."
                            % (struct.name, fn.name, re.sub(r"\s+", " ", op.group(0)))
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Call %s directly from any wallet - no signature from the configured authority is required." % fn.name,
                            "Point the writable accounts at whatever you want changed.",
                        ],
                        patch=[
                            "Add `authority: Signer<'info>` and `#[account(constraint = authority.key() == vault_config.authority)]`.",
                            "Or derive the writable account as a PDA and sign with `seeds` so only the program can author it.",
                        ],
                        checklist_needles=["signer", "permissionless"],
                        tags=["solana", "missing-signer", "privilege"],
                    )
                )
        return findings
