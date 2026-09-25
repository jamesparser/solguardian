---
id: solana-math
applies_to: solana
severities: high, medium, low
cwe: CWE-682
detector: solguardian/detectors/solana_math.py
---

# Integer overflow, rounding and precision (Solana / Anchor)

## When to use
Every share/amount/rate computation: deposits, withdrawals, exchange rates, fees, liquidation
thresholds, and anything mixing `u64` lamports with decimal-adjusted token units.

## Checklist
1. Multiplication happens **before** division; division-first expressions are precision-loss
   bugs (`amount / total * SCALE` credits 0 shares when `amount < total`).
2. Intermediates are widened (`u128`) and narrowed only at the end, after bounds checks.
3. Arithmetic uses `checked_add/sub/mul/div` or `Saturating`. If the workspace sets
   `overflow-checks = false`, silent wrapping is a fund-integrity bug rather than a panic.
4. Divisors can never be zero: the empty-vault case is special-cased or guarded with
   `require!(x > 0)`.
5. Rounding direction is deliberate and always favours the pool (virtual offset / ERC-4626-style
   inflation guard) so dust cannot be free-minted.
6. Token `decimals` are validated before unit conversion; 6-decimal lamports vs variable-decimal
   mints is the classic mismatch.
7. `as` casts are reviewed for truncation (`u128 as u64`, `i64 as u64`).

## Severity guidance
- **high**: precision loss that credits/pays wrong amounts on the main deposit path.
- **medium**: unchecked accumulation that can wrap or panic; division by zero.
- **low**: narrowing casts on non-critical paths, rounding-direction notes.

## False positives
- `checked_*` used but written on a different line from the arithmetic.
- Fixed-point libraries (`anchor_math`, `ruint`, `Ray`) that intentionally handle scaling.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, PoC stub, patch sketch,
checklist items.`
