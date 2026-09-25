"""Solana detector: integer overflow / precision loss.

Skill: skills/severity-grading/SKILL.md + skills/solana-account-validation/SKILL.md
(share the "unit and ordering" checklist)

Rules:
  MATH-001 precision loss: division before multiplication in a share/rate calculation
  MATH-002 unchecked arithmetic on token amounts (no checked_*/Saturating)
  MATH-003 division by a value that can be zero (panic / DoS)
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.rsutil import handlers
from ..core.source import SourceFile

DIV_THEN_MUL = re.compile(
    r"(?P<lhs>[A-Za-z0-9_.()\[\]]+)\s*/\s*(?P<div>[A-Za-z0-9_.()\[\]]+)\s*\*\s*(?P<mul>[A-Za-z0-9_().]+)"
)
MUL_THEN_DIV = re.compile(r"[A-Za-z0-9_.()\[\]]+\s*\*\s*[A-Za-z0-9_.()\[\]]+\s*/")
UNCHECKED_ARITH = re.compile(
    r"(?P<base>ctx\.accounts\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
    r"\s*(?P<op>\+=|-=|\*=|/=)(?P<rhs>[^;]{0,60})",
)
SAFE_MATH = re.compile(r"\bchecked_(add|sub|mul|div)|\bchecked_add\(|Saturating|safe_math|\.checked_|try_(add|sub|mul|div)")
AMOUNT_HINT = re.compile(r"(amount|shares|balance|lamports|units|decimals|supply|price)", re.I)
CAST_TRUNC = re.compile(r"\bas\s+(?:u64|u32|i64|i32|u128)\b")


@register
class SolanaMathDetector(Detector):
    id = "solana_math"
    label = "Integer overflow / precision"
    language = "rust"
    skill = "solana-math"
    cwe = "CWE-682"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import rust

        src = rust.parse(file.rel, file.index)
        findings: List[dict] = []

        for fn in handlers(src):
            body = fn.body
            base = fn.body_start
            has_safe = bool(SAFE_MATH.search(body))

            # --- MATH-001: divide-then-multiply -----------------------------
            for m in DIV_THEN_MUL.finditer(body):
                stmt = body[m.start(): body.find(";", m.start()) + 1]
                if MUL_THEN_DIV.search(stmt):
                    continue
                if not AMOUNT_HINT.search(stmt) and not AMOUNT_HINT.search(m.group("lhs")):
                    continue
                line = src.index.line_of(base + m.start())
                findings.append(
                    self.make(
                        file,
                        rule="MATH-001",
                        title="Precision loss: integer division before multiplication in %s()" % fn.name,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() computes `%s`. Rust integers truncate, so dividing first throws away the remainder "
                            "before the scaling factor is applied: for `amount < divisor` the result is exactly zero, and "
                            "for larger amounts the user loses up to `divisor-1` units of precision per operation. "
                            "This is the classic share-accounting bug - deposits silently credit 0 shares.%s"
                            % (
                                fn.name,
                                re.sub(r"\s+", " ", stmt).rstrip(";").strip(),
                                " Some checked math exists elsewhere in this handler, but not here." if has_safe else "",
                            )
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Deposit an amount smaller than the divisor (`total_deposits` here) and receive 0 shares.",
                            "Do it repeatedly: the pool's recorded deposits grow while your share balance stays at zero - "
                            "or, inverted, you can take shares that were never paid for.",
                            "Round the other way at withdrawal to extract the residual dust on every user.",
                        ],
                        patch=[
                            "Multiply first, divide last: `let shares = amount.checked_mul(SCALE)?.checked_div(total)?;`",
                            "Use `u128` intermediates (`(amount as u128 * SCALE / total) as u64`).",
                            "Track a virtual offset (ERC-4626 style inflation guard) so dust cannot be free-minted.",
                        ],
                        checklist_needles=["precision", "ordering", "rounding"],
                        tags=["solana", "precision", "accounting"],
                    )
                )

            # --- MATH-003: division by a possibly-zero storage value --------
            for m in DIV_THEN_MUL.finditer(body):
                divisor = m.group("div").strip("()[] ")
                if not re.search(r"\.", divisor) and divisor.isidentifier():
                    continue
                if re.search(
                    r"\b%s\s*(?:==|!=)\s*0|require!\s*\([^)]*%s\s*>" % (re.escape(divisor), re.escape(divisor)),
                    body,
                ):
                    continue
                if re.match(r"^\s*\d[\d_]*\s*$", divisor):
                    continue
                line = src.index.line_of(base + m.start())
                findings.append(
                    self.make(
                        file,
                        rule="MATH-003",
                        title="Division by `%s` with no zero guard in %s()" % (divisor, fn.name),
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() divides by `%s`, which is program state that can legitimately be zero (a fresh vault). "
                            "On Solana an integer division by zero panics the builtin, the transaction fails with an "
                            "opaque error, and the first depositor can never complete the flow - an availability bug "
                            "rather than a theft, but it blocks the account's own happy path."
                            % (fn.name, divisor)
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Call the handler while the divisor is zero (empty vault) to force the panic.",
                            "If the zero branch is also how shares are seeded, the whole feature is unusable.",
                        ],
                        patch=[
                            "Special-case the empty pool: `let shares = if total == 0 { amount } else { ... };`",
                            "`checked_div(...).ok_or(VaultError::DivideByZero)?` so the failure is a typed error.",
                        ],
                        checklist_needles=["zero", "guard", "panic"],
                        tags=["solana", "division-by-zero", "availability"],
                    )
                )

            # --- MATH-002: unchecked accumulation ---------------------------
            if has_safe:
                continue
            for m in re.finditer(
                r"(?P<lhs>ctx\.accounts\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
                r"\s*(?P<op>=[^=]|\+=|-=)\s*(?P<rhs>[^;]*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*[\+\-\*]\s*[^;]+);",
                body,
            ):
                expr = m.group("rhs")
                if not AMOUNT_HINT.search(expr) or not AMOUNT_HINT.search(m.group("lhs")):
                    continue
                if not re.search(r"[\+\-\*]", expr):
                    continue
                line = src.index.line_of(base + m.start())
                findings.append(
                    self.make(
                        file,
                        rule="MATH-002",
                        title="Unchecked arithmetic on `%s` in %s()" % (m.group("lhs").split(".")[-1], fn.name),
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() assigns `%s` from an arithmetic expression with no `checked_*`/`Saturating` wrapper. "
                            "Token amounts are `u64`; in an anchor build with overflow checks on, an overflow panics the "
                            "instruction (DoS of the account), and anywhere the checks are off - or the value is derived "
                            "from a cast - it wraps around and produces a tiny or absurd balance."
                            % (
                                fn.name,
                                re.sub(r"\s+", " ", m.group(0)).rstrip(";").strip(),
                            )
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Feed an amount near u64::MAX (multi-token deposits, or a manipulated `limiter` multiplier).",
                            "The accumulation wraps; your recorded share count becomes attacker-controlled.",
                        ],
                        patch=[
                            "`checked_add`/`checked_mul` with a program error on overflow.",
                            "Bound instruction inputs (`require!(amount < MAX_DEPOSIT, ...)`) before arithmetic.",
                            "Cast through `u128` for intermediates.",
                        ],
                        checklist_needles=["overflow", "checked", "bounds"],
                        tags=["solana", "overflow", "unchecked-math"],
                    )
                )
            # --- cast truncation note ---------------------------------------
            cast = CAST_TRUNC.search(body)
            if cast and AMOUNT_HINT.search(body[max(0, cast.start() - 120):cast.end() + 60]):
                line = src.index.line_of(base + cast.start())
                findings.append(
                    self.make(
                        file,
                        rule="MATH-004",
                        title="Narrowing cast `%s` on an amount in %s()" % (re.sub(r"\s+", " ", cast.group(0)), fn.name),
                        severity=Severity.LOW,
                        confidence=0.5,
                        line=line,
                        function=fn.name,
                        chain="solana",
                        description=(
                            "%s() casts through a narrower integer while computing token amounts. Combined with the "
                            "multiply/divide ordering above, silent truncation is the second half of the precision bug: "
                            "the math can be right in `u128` and wrong once cast back."
                            % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Choose inputs whose intermediate exceeds the target width.",
                            "The truncated value becomes the share/balance the program trusts.",
                        ],
                        patch=[
                            "Keep intermediates in `u128` and cast only at the end, after bounds checks.",
                            "Add a unit test around `u64::MAX / 2` sized amounts.",
                        ],
                        checklist_needles=["cast", "precision"],
                        tags=["solana", "cast", "precision"],
                    )
                )
        return findings
