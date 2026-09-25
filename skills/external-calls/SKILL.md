---
id: external-calls
applies_to: evm, hyperevm
severities: high, medium, low
cwe: CWE-252
detector: solguardian/detectors/evm_external_calls.py
---

# External call return values

## When to use
Any `.call`, `.send`, `.transfer`, low-level token `transfer`, or interface call whose
boolean result could be ignored.

## Checklist
1. Every `.call(...)` is destructured and the `ok` boolean is `require`d (or
   `Address.sendValue`/`SafeERC20` is used).
2. `.send`/`.transfer` results are checked; a silent `false` is treated as a failure branch.
3. Non-standard ERC20s (USDT-style no-return, fee-on-transfer, rebasing) are handled with
   explicit balance diffs instead of `require(ok)`.
4. The 2300-gas stipend of `send`/`transfer` is acceptable for every plausible recipient
   (contracts, multisigs, AA wallets); otherwise use pull payments.
5. `ok == true` with empty returndata is handled (some tokens return nothing).
6. The interaction with ordering is considered: an ignored failure **after** a state write is
   a fund-loss path, not a lint nit.

## Severity guidance
- **high**: value moved, result discarded, state already updated.
- **medium**: non-value external call result discarded.
- **low**: stipend/availability assumptions on `transfer`/`send`.

## False positives
- `(bool ok, ) = ...; if (!ok) { ... }` handled by an explicit branch.
- Deliberate best-effort cleanup (refunds in a loop) with an event emitted.
- `staticcall` used purely for reads.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, PoC stub, patch sketch,
checklist items.`
