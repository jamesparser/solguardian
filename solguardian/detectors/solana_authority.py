"""Solana detector: authority footguns (static notes).

Mint / freeze / upgrade / close authority, and rent-payer economics, are where an Anchor
program looks correct and still lets one wallet rug the pool. These are deliberately
*notes*: the code may not be provably broken, but the power exists and nothing in the
source constrains how it gets exercised.

Rules:
  AUTH-001 `bump` accepted from instruction data and persisted, instead of derived
  AUTH-002 `realloc::payer` names an account that is not a funded signer
  AUTH-003 authority-like account used by a handler with no `Signer` / binding
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.rsutil import handlers, struct_for
from ..core.source import SourceFile

BUMP_PARAM = re.compile(r"pub\s+fn\s+(?P<fn>[A-Za-z_]\w*)\s*\([^)]*\bbump\s*:\s*u8\b[^)]*\)", re.S)
PERSIST_BUMP = re.compile(r"\.bump\s*=\s*bump\b")
REALLOC_PAYER = re.compile(r"realloc\s*::\s*payer\s*=\s*(?P<payer>[A-Za-z_]\w*)")
AUTH_FIELD = re.compile(r"(authority|admin|owner|upgrader|freeze|mint_auth)", re.I)


@register
class SolanaAuthorityDetector(Detector):
    id = "solana_authority"
    label = "Authority footguns (static notes)"
    language = "rust"
    skill = "solana-account-validation"
    cwe = "CWE-269"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import rust

        src = rust.parse(file.rel, file.index)
        masked = src.index.masked
        findings: List[dict] = []

        # --- AUTH-001: client-chosen bump becomes the derivation of record ----
        if PERSIST_BUMP.search(masked):
            for m in BUMP_PARAM.finditer(masked):
                line = src.index.line_of(m.start())
                fn_name = m.group("fn")
                findings.append(
                    self.make(
                        file,
                        rule="AUTH-001",
                        title="PDA authority depends on a client-supplied `bump` in %s()" % fn_name,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        line=line,
                        function=fn_name,
                        chain="solana",
                        description=(
                            "%s() takes `bump: u8` straight from the instruction and stores it, and other handlers then "
                            "use that stored value as their seeds constraint (`bump = config.bump`). A PDA is only "
                            "canonical when the bump is derived with `find_program_address`; storing the caller's number "
                            "means the first writer decides how authority is derived. Even where `init` seeds constrain "
                            "this particular deployment, the pattern is how upgrade/freeze/mint authority bugs hide."
                            % fn_name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "If the PDA is not uniquely constrained at init, pick a bump that makes a *different* "
                            "address satisfy the seeds check.",
                            "Then present an account derived from that alternative bump to handlers trusting the stored value.",
                        ],
                        patch=[
                            "Drop the parameter and let Anchor verify the bump (`seeds = [...], bump`).",
                            "Or derive it: `let (_pda, bump) = Pubkey::find_program_address(&[b\"vault\", authority.as_ref()], &id());`",
                            "If a bump must be stored, assert it equals the derived value on every read.",
                        ],
                        checklist_needles=["seeds", "authority", "bump"],
                        tags=["solana", "pda", "authority"],
                    )
                )

        for struct in src.structs:
            fields = {f.name: f for f in struct.fields}
            body = src.index.masked[struct.body_start:struct.body_end]

            # --- AUTH-002: realloc payer is not a signer ---------------------
            for m in REALLOC_PAYER.finditer(body):
                payer = m.group("payer")
                field = fields.get(payer)
                if field is not None and field.is_signer:
                    continue
                line = src.index.line_of(struct.body_start + m.start())
                findings.append(
                    self.make(
                        file,
                        rule="AUTH-002",
                        title="`realloc::payer = %s` is not a funded signer in %s" % (payer, struct.name),
                        severity=Severity.MEDIUM if field is not None else Severity.LOW,
                        confidence=0.6,
                        line=line,
                        function="",
                        chain="solana",
                        description=(
                            "`%s` resizes an account and charges the rent delta to `%s`, which is %s. Solana requires the "
                            "rent payer of a resize to be a writable, funded signer; a PDA or program-owned account "
                            "cannot pay it, so the resize fails (availability) or - if the slot can be filled by "
                            "whoever calls - the cost lands on a third party. This is a design note rather than a proof "
                            "of theft, which is why it is graded low/medium."
                            % (struct.name, payer, field.type if field else "not declared in this struct")
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Trigger the realloc path repeatedly so the charged account bleeds lamports it never agreed to.",
                            "Or front-run the growth so the rent cost lands on the victim's account.",
                        ],
                        patch=[
                            "`#[account(mut)] payer: Signer<'info>` as `realloc::payer`, verified as the tx fee payer.",
                            "Prefer fixed `space` at init over dynamic realloc in value-critical paths.",
                            "If the PDA must fund growth, fund it explicitly with a signed transfer first.",
                        ],
                        checklist_needles=["payer", "rent", "authority"],
                        tags=["solana", "realloc", "authority-note"],
                    )
                )

        # --- AUTH-003: authority-shaped account with no binding --------------
        for fn in handlers(src):
            struct = struct_for(src, fn)
            if struct is None:
                continue
            for field in struct.fields:
                if not AUTH_FIELD.search(field.name):
                    continue
                if field.is_signer or "Program<" in field.type:
                    continue
                bound = any(
                    token in (field.attrs or "")
                    for token in ("has_one", "constraint", "seeds")
                )
                if bound:
                    continue
                if not re.search(r"ctx\.accounts\.%s\b" % field.name, fn.body):
                    continue
                findings.append(
                    self.make(
                        file,
                        rule="AUTH-003",
                        title="Authority account `%s` is used by %s() with no signer and no binding"
                        % (field.name, fn.name),
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        line=field.line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "`%s` in `%s` reads like an authority (%s) but is not a `Signer`, is not tied by "
                            "`has_one`/`constraint`/`seeds`, and %s() still consumes it. Any mint / freeze / close "
                            "authority check the program assumes happens here is really happening on an account the "
                            "client chose. The privilege exists; nothing in the source limits who exercises it."
                            % (field.name, struct.name, field.type, fn.name)
                        ),
                        evidence=file.line_text(field.line),
                        exploit=[
                            "Supply a different key in the `%s` slot (or reuse an account you own that matches the shape)." % field.name,
                            "Pair it with the missing-signer path in the same handler to complete the authority chain.",
                        ],
                        patch=[
                            "`Signer<'info>` plus `#[account(constraint = %s.key() == expected_authority)]`." % field.name,
                            "Read SPL authorities from the mint/account data instead of from an unvalidated account.",
                            "Use a two-step authority handover so a single bad call cannot transfer ownership.",
                        ],
                        checklist_needles=["authority", "signer", "binding"],
                        tags=["solana", "authority", "static-note"],
                    )
                )
        return findings
