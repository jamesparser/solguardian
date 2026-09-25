---
id: solana-account-validation
applies_to: solana
severities: critical, high, medium
cwe: CWE-863
detector: solguardian/detectors/solana_accounts.py, solana_signer.py, solana_deser.py, solana_authority.py
---

# Solana account validation (signer / owner / type / seeds)

## When to use
Every Anchor `#[derive(Accounts)]` struct and every raw `process_instruction` handler. On
Solana the account list **is** the authorisation model: there is no `msg.sender`, so an
unvalidated account is an unauthenticated privilege.

## Checklist
1. Every account that authorises a privileged action is typed `Signer<'info>` (or its
   signature is proven by a PDA `seeds` constraint).
2. Accounts that must belong to the program are `Account<'info, T>` - never
   `UncheckedAccount` / raw `AccountInfo` - so Anchor checks owner + discriminator.
3. SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority
   (`#[account(token::mint = ..., token::authority = ...)]`).
4. PDAs are derived, not trusted: `seeds` + `bump` verified by Anchor, or
   `find_program_address`/`create_program_address` in code. A `bump` arriving from instruction
   data is a validation gap.
5. CPI callee programs are `Program<'info, T>` (or checked with `is_program()`); a
   client-supplied program id can be a spoofed token program.
6. `has_one = authority` (or an explicit `constraint = ...`) binds each mutable account to the
   authority that owns it.
7. `remaining_accounts` are length-checked **before** indexing and validated individually -
   Anchor does not check them.
8. Owner-writable fields (`data`, `lamports`) are mutated only through typed accounts, and
   `realloc` rent payers are funded signers.
9. Manual signer proofs (`require!(acc.is_signer, ...)`) exist wherever the type system is not
   doing it.

## Severity guidance
- **critical**: unsigned authority that gates a value transfer or a state mutation.
- **high**: unvalidated account type used in a CPI or as a balance source.
- **medium**: seeds/bump gaps, missing `has_one` on a PDA write.
- **low/info**: `realloc::payer` economics, `/// CHECK:` escape hatches left unevidenced.

## False positives
- Deliberate `UncheckedAccount` where the handler does its own owner/length checks (Anchor's
  documented escape hatch) - look for the `require!` before grading.
- `Program<'info, T>` fields matched by name heuristic only.
- PDAs whose seeds are fully constrained in the attribute even though a bump is stored.

## Required output fields
`id, severity, confidence, location (file:line + struct/handler), explanation, exploit sketch,
PoC stub (Anchor/Rust test skeleton), patch sketch, checklist items.`
