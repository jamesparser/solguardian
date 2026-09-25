---
id: solana-cpi
applies_to: solana
severities: critical, high, medium
cwe: CWE-252
detector: solguardian/detectors/solana_cpi.py
---

# Cross-program invocation (CPI) safety

## When to use
Any `program::invoke` / `invoke_signed` / `CpiContext` / `token::transfer` / `MintTo` inside a
handler, and any use of `remaining_accounts` as a CPI source.

## Checklist
1. Every CPI result is propagated (`?`) or explicitly handled; a dropped `Result` means the
   handler reports success for an operation that never happened.
2. The callee is a `Program<'info, T>` account (or `is_program()` verified), never a raw
   `UncheckedAccount`/`AccountInfo` supplied by the client.
3. `signer_seeds` passed to `invoke_signed` match the PDA the program actually trusts, and the
   bump is derived rather than stored from user input.
4. Writable accounts handed to the callee are ones the program owns; unowned writable accounts
   trigger `OwnerChanged`/`MissingAccount` failures which must be surfaced, not swallowed.
5. `AccountMeta` flags (`is_signer`, `is_writable`) match the runtime account list - a mismatch
   is a hard panic.
6. Failure modes are checked *before* local accounting is updated; a failed CPI must not leave
   minted/credited state behind.
7. Re-entrancy across the CPI is considered: the callee may call back into this program with a
   different instruction.
8. `remaining_accounts` lengths are validated before they are used as CPI accounts.

## Severity guidance
- **critical**: spoofable program id on a value-moving CPI (fake token program).
- **high**: unchecked CPI result after which local state changes.
- **medium**: unvalidated `remaining_accounts`, missing signer seeds.
- **low/info**: notes about CPI limits (account count, invocation depth, compute units).

## False positives
- `let res = invoke(...); require!(res.is_ok(), Err::CpiFailed);` a few lines later.
- `anchor_spl` helpers already chained with `?`.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, PoC stub, patch sketch,
checklist items.`
