---
id: solana-signer
applies_to: solana
severities: critical, high, medium
cwe: CWE-287
detector: solguardian/detectors/solana_signer.py
---

# Solana signer verification

## When to use
Any handler that authorises an action by an account key rather than by a signature, and any
`UncheckedAccount`/`AccountInfo` slot whose key is compared, stored as an authority, or used
to justify a state change.

## Checklist
1. Every account whose **signature** is required is typed `Signer<'info>`; the type system is
   the cheapest proof available.
2. Where a raw `AccountInfo`/`UncheckedAccount` must be used, the handler contains an explicit
   `require!(acc.is_signer, ProgramError::MissingRequiredSignature)` (or an `Owner` check
   against a program that already enforced it).
3. A handler that mints, transfers, closes, reallocs or writes privileged state has **at least
   one** signer in its accounts struct. "Permissionless mutation" is the top Solana exploit
   class.
4. The key stored as the future authority (`vault.authority = authority.key()`) comes from a
   signer, otherwise the first writer picks the owner of the account.
5. PDA-signed CPIs (`seeder = &[*seed_bytes]`) are used for program-side authority instead of
   trusting a client key, and the seeds are derived, not passed in.
6. Multi-sig / governance authority is bound with `has_one` so a substituted key cannot be
   accepted.
7. The distinction is explicit: `Signer` proves *this key authorised the transaction*;
   `Account<'info, T>` proves *this account has this shape and owner*. Neither substitutes for
   the other.

## Severity guidance
- **critical**: unsigned account authorises a value move or privileged state write, and no
  other signer exists in the struct.
- **high**: privileged-shaped account (`authority`, `reporter`, `oracle`) used as a decision
  input without a signature.
- **medium**: a signer exists but the authority key itself is unverified.

## False positives
- `token_program` / `system_program` slots - these are programs, never signers.
- PDA accounts authorised by `seeds` + `bump` (signature is implied by derivation).
- Handler-internal accounts whose signer proof lives in the *previous* CPI in the same tx
  (rare; verify before grading).

## Required output fields
`id, severity, confidence, location (struct field line + handler), explanation, exploit
sketch, PoC stub, patch sketch, checklist items.`
