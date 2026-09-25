---
id: reentrancy
applies_to: evm, hyperevm
severities: critical, high
cwe: CWE-841
detector: solguardian/detectors/evm_reentrancy.py
---

# Reentrancy (state written after an external call)

## When to use
Any function that transfers value (native ETH, ERC20, ERC721, HyperEVM value paths) or
calls untrusted code, then touches storage afterwards. Also use it when reviewing
`receive()`/`fallback()`, ERC777/ERC4626 hooks, and any callback into a pool or a user
contract.

## Checklist
1. Every external interaction (`call`, `delegatecall`, `staticcall` to a user-controlled
   address, `send`, `transfer`, `transferFrom`, `approve`+`callFrom`) is identified and its
   line number is recorded.
2. State writes (`balances[...]`, totals, flags, allowances, nonces) are ordered strictly
   **before** the interaction - checks-effects-interactions holds.
3. A reentrancy guard (`nonReentrant`, OZ `ReentrancyGuard`, ERC-7201 transient storage
   lock, or a manual lock flag) covers the function, or CEI ordering makes it unnecessary.
4. Cross-function reentrancy is considered: does any **other** entry point read state that
   this function updates late?
5. Read-only reentrancy is considered: are view functions used by pools/oracles/liquidators
   still callable mid-callback?
6. Callbacks from the callee (`onERC721Received`, `tokensReceived`, `ERC4626` deposit hooks,
   `pool.swap`) are treated as full re-entry opportunities, not as inert returns.
7. The finding states the concrete re-entering call and the exact line where the stale state
   is still readable.

## Severity guidance
- **critical**: native/ERC20 value moves out and the accounting update happens after the call.
- **high**: value moves but the re-entry needs an unusual callee, or state is non-value.
- **medium**: multiple sequential external calls with no guard (composition risk).
- Low/info: documentation gaps, `view` functions used off-chain only.

## False positives
- OZ `ReentrancyGuard` on the entry point plus no shared mutable state in callees.
- `staticcall` only, or interactions with contracts that provably have no callbacks
  (e.g. `transfer` to an EOA-only whitelist).
- Deliberate "pull payment" designs where the write is a no-op for the caller.
- CEI is satisfied but the regex sees a `totalDeposits -=` after a `safeTransfer` call
  helper - confirm the helper cannot re-enter before grading.

## Required output fields
`id, severity, confidence, location (file:line + function), 2-5 sentence explanation,
exploit sketch, PoC stub (Foundry skeleton), patch sketch, this skill's checklist items.`
