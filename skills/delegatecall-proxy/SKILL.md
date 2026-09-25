---
id: delegatecall-proxy
applies_to: evm, hyperevm
severities: critical, high, medium
cwe: CWE-471
detector: solguardian/detectors/evm_delegatecall.py
---

# Dangerous delegatecall & proxy storage collisions

## When to use
`delegatecall`, `beacon`/`implementation` pointers, UUPS/Transparent proxies, `upgradeTo`,
`upgradeToAndCall`, and any "migrate"/"execute" helper.

## Checklist
1. The delegatecall target resolves to a constant or admin-upgraded implementation address -
   never a raw user argument.
2. Writes to logic pointers are guarded by an admin role **and** a timelock/delay, and emit an
   `Upgraded` event.
3. The implementation's storage layout is append-only and keeps the ERC-1967 gap; proxy slots
   are not writable by implementation code.
4. delegatecall context is remembered: `address(this)`, storage and `msg.sender` carry over, so
   the callee can rewrite owner/admin slots and reach `selfdestruct`.
5. Initialisers cannot be re-run through the delegate path (`_disableInitializers`,
   `onlyInitializing`).
6. Beacon/proxy admin ownership matches the intended governance, not the deployer EOA.
7. Unstructured storage (`t_store`, assembly `sstore`) is checked against the layout.

## Severity guidance
- **critical**: caller-supplied delegatecall target, or a pointer writable by an unguarded function.
- **high**: unguarded logic-pointer write; admin upgrade path with no delay or event.
- **medium/info**: layout/assembly review notes with no proven collision.

## False positives
- OZ UUPS with `_authorizeUpgrade` correctly restricted to a governance role.
- `delegatecall` to `address(this)` for storage-safe self-delegation.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, PoC stub, patch sketch,
checklist items, plus which slot/pointer is at risk.`
