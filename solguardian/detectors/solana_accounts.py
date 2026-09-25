"""Solana detector: account validation (owner / type / confusion).

Skill: skills/solana-account-validation/SKILL.md

Rules:
  ACCT-001 `UncheckedAccount` / raw `AccountInfo` used where a typed account is required
  ACCT-002 token-ish account used without owner + mint validation
  ACCT-003 PDA seeds constraint trusts a client-supplied bump
  ACCT-004 `has_one` / explicit owner constraint missing between a PDA and its authority
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.rsutil import handlers, raw_fields, struct_for
from ..core.source import SourceFile

TOKEN_USE = re.compile(r"token::(transfer|mints|burn|close_account)|Transfer\s*\{|MintTo\s*\{|owner|\.amount\b")
STORED_BUMP = re.compile(r"bump\s*=\s*(?P<base>[A-Za-z_]\w*)\.bump\b")
CLIENT_BUMP_SET = re.compile(r"\.bump\s*=\s*bump\b|\.bump\s*=\s*\w+\s*;")


@register
class SolanaAccountValidationDetector(Detector):
    id = "solana_accounts"
    label = "Missing owner / account type checks"
    language = "rust"
    skill = "solana-account-validation"
    cwe = "CWE-863"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import rust

        src = rust.parse(file.rel, file.index)
        findings: List[dict] = []

        for fn in handlers(src):
            struct = struct_for(src, fn)
            if struct is None:
                continue
            body = fn.body

            for field in raw_fields(struct):
                # Anchor's documented escape hatch: a raw account whose *derivation* is
                # verified by `seeds` needs no type check - the address is the proof. Same for
                # the PDA `authority` slot of an SPL CPI, which is meant to be raw.
                if "seeds" in (field.attrs or ""):
                    continue
                if "authority" in field.name or field.name.endswith("_payer"):
                    continue
                used_in_cpi = bool(
                    re.search(r"%s\s*\.to_account_info\s*\(\s*\)" % field.name, body)
                ) or bool(re.search(r"ctx\.accounts\.%s\b" % field.name, body))
                constrained = "mut" in field.attrs or "seeds" in field.attrs or "constraint" in field.attrs
                if not used_in_cpi and not constrained:
                    continue
                token_ish = bool(TOKEN_USE.search(field.name)) or bool(
                    re.search(r"ctx\.accounts\.%s\s*\.\s*amount" % field.name, body)
                )
                # a `/// CHECK:` comment plus a real constraint is Anchor's escape hatch -
                # still report, but with lower confidence, because the author promised to check.
                doc_checked = "CHECK" in (field.attrs or "") or bool(
                    re.search(r"CHECK:[^\n]*%s" % field.name, src.index.masked)
                )
                severity = Severity.HIGH if (used_in_cpi and not doc_checked) else (
                    Severity.MEDIUM if used_in_cpi else Severity.LOW
                )
                findings.append(
                    self.make(
                        file,
                        rule="ACCT-001",
                        title="Unvalidated account type: `%s` is %s in %s"
                        % (field.name, field.base_type, struct.name),
                        severity=severity,
                        confidence=0.55 if doc_checked else 0.8,
                        line=field.line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "`%s` in the `%s` constraint list is typed as %s, so Anchor performs no deserialisation, "
                            "owner or discriminator check on it - yet %s() passes it into program logic%s. "
                            "That is account-confusion territory: an attacker can substitute a look-alike account "
                            "(wrong owner, wrong mint, wrong program) and the handler has no way to notice. "
                            "Typing it as `Account<'info, T>` / `Program<'info, T>` makes the runtime enforce it for free."
                            % (
                                field.name,
                                struct.name,
                                field.type,
                                fn.name,
                                " into a token CPI" if token_ish else "",
                            )
                        ),
                        evidence=file.line_text(field.line),
                        exploit=[
                            "Create any account with a matching shape (or reuse one you own) and place it in the `%s` slot." % field.name,
                            "Because ownership/discriminator are not verified, the handler treats it as trusted.",
                            "Combine with the missing signer path to redirect value.",
                        ],
                        patch=[
                            "Use a concrete type: `Account<'info, TokenAccount>` / `Program<'info, Token>` / "
                            "`Account<'info, VaultPda>`.",
                            "Or validate by hand: `require!(acc.owner == &anchor_spl::token::ID, ...)` and check the "
                            "discriminator/length.",
                            "Add `#[account(..., token::mint = expected_mint)]` style constraints for SPL accounts.",
                        ],
                        checklist_needles=["owner", "type", "confusion"],
                        tags=["solana", "account-validation", "type-confusion"],
                    )
                )

            # ACCT-002: token account used without owner/mint validation
            for m in re.finditer(r"ctx\.accounts\.(?P<acc>[A-Za-z_]\w*)\.to_account_info\s*\(\s*\)", body):
                field = struct.field(m.group("acc"))
                if field is None or not field.raw_account:
                    continue
                # The `authority:` slot of a Transfer/MintTo struct is the *signer* of the
                # transfer. For a vault that is a program PDA, and a seeds-verified
                # UncheckedAccount is the correct type there - only the accounts that actually
                # hold tokens need owner/mint validation.
                if "authority" in m.group("acc") or "payer" in m.group("acc"):
                    continue
                if "seeds" in (field.attrs or ""):
                    continue
                if re.search(r"\bauthority\s*:\s*$", body[max(0, m.start() - 60):m.start()]):
                    continue
                if not re.search(r"token::(transfer|mint_to|burn|mints|close_account)\s*\(", body):
                    continue
                line = src.index.line_of(fn.body_start + m.start())
                if re.search(r"%s\s*\.\s*owner" % m.group("acc"), body):
                    continue
                findings.append(
                    self.make(
                        file,
                        rule="ACCT-002",
                        title="Token CPI over unvalidated account `%s` in %s()" % (m.group("acc"), fn.name),
                        severity=Severity.CRITICAL,
                        confidence=0.8,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() hands `ctx.accounts.%s` to an SPL token CPI while the account is only an %s. Nothing "
                            "proves its owner is the token program, that it is the vault's token account, or that its "
                            "mint is the expected one. The CPI happily operates on whatever account the client supplied, "
                            "which is the standard way vaults end up paying out of the wrong pot."
                            % (fn.name, m.group("acc"), field.base_type)
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Point `%s` at a token account you control (or at any account whose data you can shape)." % m.group("acc"),
                            "The vault debits/credits the wrong account; your own balance is the source of truth for it.",
                        ],
                        patch=[
                            "`#[account(constraint = %s.owner == program_authority.key() && %s.mint == expected_mint)]`"
                            % (m.group("acc"), m.group("acc")),
                            "Type it `Account<'info, TokenAccount>` so Anchor deserialises and checks the owner.",
                        ],
                        checklist_needles=["owner", "mint", "token"],
                        tags=["solana", "cpi", "account-validation"],
                    )
                )

        # ACCT-003: bump comes from the client, then seeds trust the stored value.
        # Only a smell when a handler *accepts* `bump` as instruction data: storing a bump that
        # was derived with find_program_address in the same handler is the recommended pattern.
        takes_client_bump = any(
            re.search(r"\bbump\s*:\s*u8\b", fn.params) for fn in src.functions
        )
        for m in STORED_BUMP.finditer(src.index.masked):
            line = src.index.line_of(m.start())
            base = m.group("base")
            if not (takes_client_bump and CLIENT_BUMP_SET.search(src.index.masked)):
                continue
            findings.append(
                self.make(
                    file,
                    rule="ACCT-003",
                    title="PDA seeds constraint trusts a client-supplied bump",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    line=line,
                    chain="solana",
                    description=(
                        "The account constraint uses `bump = %s.bump`, and that stored bump was written from an "
                        "instruction argument in `initialize`. Anchor will therefore accept *any* bump the client first "
                        "persisted, so the seeds constraint stops pinning the address to a single canonical PDA. Bump "
                        "values are part of the address derivation: letting the client choose them is a validation gap."
                        % base
                    ),
                    evidence=file.line_text(line),
                    exploit=[
                        "Call `initialize` with a bump that still satisfies the (weak) derivation and store it.",
                        "Reuse that stored bump later to make a seeds check accept a non-canonical address.",
                    ],
                    patch=[
                        "Derive the bump: `bump` (Anchor verifies) or `let (,_ ,bump) = Pubkey::find_program_address(...)`.",
                        "Store the *derived* bump, never the client's.",
                    ],
                    checklist_needles=["seeds", "bump"],
                    tags=["solana", "pda", "seeds"],
                )
            )

        # ACCT-004: PDA mutated in a handler with no has_one back to its authority
        for fn in handlers(src):
            struct = struct_for(src, fn)
            if struct is None:
                continue
            for field in struct.fields:
                if field.base_type not in ("Account",) or "VaultConfig" not in field.type:
                    continue
                attrs = field.attrs or ""
                has_binds = "has_one" in attrs or "seeds" in attrs or "constraint" in attrs
                mutates = bool(re.search(r"ctx\.accounts\.%s\s*\.\s*[A-Za-z_]\w*\s*(=|\+=|-=)" % field.name, fn.body)) or \
                    bool(re.search(r"&mut\s+ctx\.accounts\.%s\b" % field.name, fn.body))
                signer_binds = any(f.is_signer for f in struct.fields)
                if mutates and not has_binds and not signer_binds:
                    findings.append(
                        self.make(
                            file,
                            rule="ACCT-004",
                            title="State PDA `%s` mutated without a has_one/seeds binding in %s()"
                            % (field.name, fn.name),
                            severity=Severity.HIGH,
                            confidence=0.7,
                            line=field.line,
                            function=fn.name,
                            chain="solana",
                            description=(
                                "`%s` is writable in `%s` and is mutated by %s(), but the constraint list has no "
                                "`has_one`, no `seeds`, and no `Signer`, so nothing ties that particular PDA to the "
                                "authority performing the change. Anchor can pass any existing VaultConfig account and "
                                "the handler will edit it."
                                % (field.name, struct.name, fn.name)
                            ),
                            evidence=file.line_text(field.line),
                            exploit=[
                                "Supply a VaultConfig account belonging to someone else in the `%s` slot." % field.name,
                                "The handler mutates it because no ownership/derivation check exists.",
                            ],
                            patch=[
                                "`#[account(mut, has_one = authority, seeds = [b\"vault\", authority.key().as_ref()], bump)]`.",
                                "Require an `authority: Signer<'info>` and compare it against the stored authority.",
                            ],
                            checklist_needles=["has_one", "seeds", "authority"],
                            tags=["solana", "account-validation", "has-one"],
                        )
                    )
        return findings
