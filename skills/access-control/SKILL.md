---
id: access-control
applies_to: evm, hyperevm
severities: critical, high, medium
cwe: CWE-284
detector: solguardian/detectors/evm_access.py
---

# Access control (missing guard, arbitrary admin, tx.origin)

## When to use
Every `public`/`external` function that changes ownership, roles, fees, caps, oracle
addresses, implementations, pauses, mints, burns, or moves funds out.

## Checklist
1. Build the list of externally callable functions and mark which ones mutate privileged state.
2. Each privileged function has either a modifier (`onlyOwner`, `onlyRole`, `onlyAdmin`)
   or an explicit first-statement `require(msg.sender == ...)`.
3. `tx.origin` is **never** the authorisation basis (`msg.sender` is the caller).
4. Role grants/renouncements are themselves guarded, and no role is left unassigned.
5. Initialise-only functions (`initialize`, `setParams`, first-deploy setters) cannot be
   re-called by anyone after setup.
6. Upgradability surface: who can change `implementation`/`beacon`/`admin`? Is there a
   timelock and an event?
7. The finding names the exact entry point and the state it lets an unauthorised caller write.

## Severity guidance
- **critical**: unauthenticated function that moves funds or empties the contract
  (drain / decommission / unguarded `selfdestruct` path).
- **high**: unauthenticated write to a security-critical pointer (oracle, implementation,
  reserve factor, fee).
- **medium**: unauthenticated write to a non-critical parameter; `tx.origin` auth.
- **low/info**: missing event on an admin action, naming that hides the guard.

## False positives
- Guards implemented in an internal helper called at the top of the function.
- ERC-165/ERC-721/1155 callbacks that must be open by design (`onERC721Received`).
- OZ `onlyRole` applied via `_checkRole` inline instead of a modifier.
- Functions guarded by the *proxy* admin rather than the implementation.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, Foundry PoC stub,
patch sketch, checklist items, plus who SHOULD be able to call it.`
