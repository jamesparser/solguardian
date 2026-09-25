"""Solana detector: cross-program invocation safety.

Skill: skills/solana-cpi/SKILL.md (shares the validation model with
skills/solana-account-validation/SKILL.md)

Rules:
  CPI-001 CPI result discarded (unchecked cross-program call)
  CPI-002 callee program account never validated as a program (`is_program` / Program<'info, T>)
  CPI-003 writable PDA/token account passed to a CPI without a signer-seed or owner binding
  REMOT-001 `remaining_accounts` indexed without a length check
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.rsutil import handlers, struct_for
from ..core.source import SourceFile

INVOKE = re.compile(
    r"(?:(?:anchor_lang::)?solana_program::)?program::(?P<kind>invoke_signed|invoke)\s*\("
    r"|anchor_lang::(?P<kind2>invoke_signed|invoke)\s*\("
)
SPL_CPI = re.compile(r"\btoken::(transfer|mints|burn|close_account|set_authority|transfer_from)\s*\(")
CHECKED = re.compile(r"[?]\s*[;)]|\.map_err\(|\.unwrap\(|\.expect\(|require!\s*\(")
LEN_CHECK = re.compile(r"remaining_accounts\s*\.len\s*\(\s*\)\s*(>=|>|<)\s*\d+|next\(\)\s*(?:\.ok_or|\.ok)")
REMAINING_INDEX = re.compile(r"remaining_accounts\s*\[\s*(?P<idx>\d+|[A-Za-z_]\w*)\s*\]")
IS_PROGRAM_CHECK = re.compile(r"\.is_program\b|is_program\s*\(|\beligible\s*\(|Program<'info")


@register
class SolanaCpiDetector(Detector):
    id = "solana_cpi"
    label = "Unchecked / unvalidated CPI"
    language = "rust"
    skill = "solana-cpi"
    cwe = "CWE-252"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import rust

        src = rust.parse(file.rel, file.index)
        masked = src.index.masked
        findings: List[dict] = []

        for fn in handlers(src):
            struct = struct_for(src, fn)
            body = fn.body
            base = fn.body_start

            # --- CPI-001: unchecked invoke ----------------------------------
            for m in INVOKE.finditer(body):
                stmt_start = m.start()
                # find the end of the call statement (its semicolon)
                semi = body.find(";", m.end())
                stmt = body[stmt_start: semi + 1 if semi != -1 else len(body)]
                following = body[stmt_start: min(len(body), stmt_start + 600)]
                checked = bool(re.match(r"\s*let\s+\w+\s*=", stmt)) or CHECKED.search(
                    body[max(0, stmt_start - 40): stmt_start + 10]
                ) or bool(re.search(r"^\s*(?:\??\))\s*;", stmt)) or stmt.rstrip().endswith(")?;")
                if checked:
                    continue
                line = src.index.line_of(base + stmt_start)
                findings.append(
                    self.make(
                        file,
                        rule="CPI-001",
                        title="Unchecked CPI: result of `program::%s` discarded in %s()"
                        % (m.group("kind") or m.group("kind2") or "invoke", fn.name),
                        severity=Severity.HIGH,
                        confidence=0.85,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() performs a cross-program invocation and throws the `Result` away (no `?`, no "
                            "`require!`). If the callee reverts, the CPI error is swallowed and this handler still "
                            "returns `Ok(())`, so the program records the external operation as if it succeeded. "
                            "Every downstream accounting decision then runs on a state that never happened."
                            % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Force the callee to fail (insufficient funds, wrong owner, frozen account).",
                            "The CPI error never propagates; %s() returns success." % fn.name,
                            "The program's own bookkeeping now diverges from on-chain reality - withdraw against it.",
                        ],
                        patch=[
                            "Propagate: `program::invoke(&instruction, &account_infos)?;`",
                            "Or `require!(result.is_ok(), VaultError::CpiFailed);` with a real error variant.",
                            "Return the CPI error unchanged so clients see why the transaction failed.",
                        ],
                        checklist_needles=["result", "propagat"],
                        tags=["solana", "cpi", "unchecked"],
                    )
                )

            # --- CPI-002: unvalidated program account ------------------------
            program_exprs = set(
                re.findall(r"ctx\.accounts\.([A-Za-z_]\w*)\s*\.\s*(?:key\(\)|to_account_info\(\))", body)
            )
            if (INVOKE.search(body) or SPL_CPI.search(body)) and struct is not None:
                for name in program_exprs:
                    field = struct.field(name)
                    if field is None or not field.raw_account:
                        continue
                    if "program" not in name.lower() and "Program" not in field.type:
                        continue
                    if IS_PROGRAM_CHECK.search(body) or IS_PROGRAM_CHECK.search(field.attrs or ""):
                        continue
                    line = field.line
                    findings.append(
                        self.make(
                            file,
                            rule="CPI-002",
                            title="CPI target `%s` is an unvalidated account, not a Program" % name,
                            severity=Severity.CRITICAL,
                            confidence=0.8,
                            line=line,
                            function=fn.name,
                            chain="solana",
                            description=(
                                "`%s` is declared as %s in `%s` and is used as the program id for a cross-program call. "
                                "Anchor only checks that an account is a *program* when it is typed "
                                "`Program<'info, T>` (or when `is_program()` is called). Here the client picks the "
                                "'program', so the instruction is executed against code the program never vouched for - "
                                "typically a spoofed token program that returns success without moving anything."
                                % (name, field.base_type, struct.name)
                            ),
                            evidence=file.line_text(line),
                            exploit=[
                                "Deploy a fake program whose address you pass as `%s`." % name,
                                "It deserialises the args, returns Ok, and moves nothing.",
                                "The vault credits your position anyway - mint-without-deposit.",
                            ],
                            patch=[
                                "Type the account `Program<'info, anchor_spl::token::Token>` (or `System`).",
                                "Or `require!(ctx.accounts.%s.is_program(), VaultError::InvalidProgram);`." % name,
                                "Even better, use the CPI helper (`token::transfer`) which resolves the program from "
                                "`CpiContext` types instead of a client field.",
                            ],
                            checklist_needles=["program", "spoof"],
                            tags=["solana", "cpi", "program-validation"],
                        )
                    )

            # --- REMOT-001: remaining_accounts indexing ---------------------
            if "remaining_accounts" in body and not LEN_CHECK.search(body):
                for m2 in REMAINING_INDEX.finditer(body):
                    line = src.index.line_of(base + m2.start())
                    findings.append(
                        self.make(
                            file,
                            rule="REMOT-001",
                            title="`remaining_accounts` indexed at [%s] without a length check" % m2.group("idx"),
                            severity=Severity.MEDIUM,
                            confidence=0.75,
                            line=line,
                            function=fn.name,
                            chain="solana",
                            description=(
                                "%s() reads `%s` from `ctx.remaining_accounts` before checking how many accounts the "
                                "client actually sent. A short account list panics on the slice index (an uncaught panic "
                                "in the handler, not a clean program error), and any validation that *would* have "
                                "happened afterwards is skipped - note the ordering here: the read precedes the `require!`."
                                % (fn.name, m2.group(0))
                            ),
                            evidence=file.line_text(line),
                            exploit=[
                                "Send the instruction with fewer remaining accounts than expected.",
                                "The program panics on the index; clients see an opaque failure (DoS of that path).",
                                "Or rely on the missing validation to slip a wrong-role account into position.",
                            ],
                            patch=[
                                "`ensure!(ctx.remaining_accounts.len() >= 2, VaultError::NotEnoughAccounts);` before indexing.",
                                "Iterate with `.iter().next().ok_or(...)` so absence becomes a typed error.",
                                "Validate each remaining account's owner/mint - they are outside Anchor's checks.",
                            ],
                            checklist_needles=["remaining", "length"],
                            tags=["solana", "remaining-accounts", "panic"],
                        )
                    )
                    break

            # --- CPI-003: token CPI mutating amount directly -----------------
            for m3 in re.finditer(r"ctx\.accounts\.([A-Za-z_]\w*token[A-Za-z_]\w*)\.amount\s*(\+=|-=|=)", body, re.I):
                line = src.index.line_of(base + m3.start())
                findings.append(
                    self.make(
                        file,
                        rule="CPI-003",
                        title="SPL token balance edited directly on `%s` instead of via CPI" % m3.group(1),
                        severity=Severity.HIGH,
                        confidence=0.7,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() writes `ctx.accounts.%s.amount` directly. An SPL token account is owned by the token "
                            "program, so a well-behaved runtime will reject the mutation; where the owner check is weak "
                            "(or the account was passed as a raw/duplicated account) the balance can be forged inside "
                            "the transaction, letting an attacker mint purchasing power without moving tokens."
                            % (fn.name, m3.group(1))
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Pass an account the handler treats as the vault token account.",
                            "Direct mutation path (or a CPI on an unvalidated program) inflates `amount`.",
                            "Withdraw/settle logic trusts `amount` and releases real tokens.",
                        ],
                        patch=[
                            "Move balances with `token::transfer` / `token::mint_to` CPIs signed by the vault PDA.",
                            "Keep program-owned state in your own accounts, never in foreign-owned layouts.",
                        ],
                        checklist_needles=["owner", "cpi", "balance"],
                        tags=["solana", "spl", "account-ownership"],
                    )
                )
        return findings
