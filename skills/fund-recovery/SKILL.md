---
id: fund-recovery
applies_to: evm, hyperevm
severities: critical, high, medium
cwe: CWE-284
detector: solguardian/detectors/evm_selfdestruct.py
---

# selfdestruct, arbitrary send and stranded funds

## When to use
Any `selfdestruct`/`suicide`, any value sent to an address that came from calldata, any
`receive()`/`fallback`, and every "admin recovery" function.

## Checklist
1. `selfdestruct` does not exist in application code. If it does, it is reachable only behind a
   timelocked governance role with a **fixed** beneficiary, and the destruction is documented.
2. No value-moving call takes its destination from instruction arguments without deriving it from
   the contract's own accounting (`withdraw(msg.sender, ...)` beats `send(to, ...)`).
3. Every authorisation variable is actually assigned somewhere: a `require(msg.sender == X)` where
   `X` is never written is dead code, and dead recovery code means permanently stranded funds.
4. If the contract can hold native value, there is an explicit egress path for it
   (`recoverEther` behind a role), or the ingress path is removed entirely.
5. Token recovery uses `SafeERC20` and checks the return data - a rescue that silently fails is
   worse than no rescue, because everyone believes the funds are safe.
6. Force-send paths (`selfdestruct` to this contract, `syncSend`-style native transfers) cannot
   break the contract's internal accounting: never use `address(this).balance` as the source of
   truth when users can force value in.
7. Note EIP-678 semantics: post-Cancun `selfdestruct` only fully removes code/ storage when the
   target was created in the same transaction - but the balance sweep still happens, so the fund
   risk remains real on every chain this tool targets.

## Severity guidance
- **critical**: caller-chosen `selfdestruct` beneficiary, or an unguarded value send.
- **high**: reachable selfdestruct behind a plain admin key; recovery gated on a never-assigned
  address.
- **medium**: no egress for accumulated native value; unchecked ERC20 recovery result.

## False positives
- Proxies that legitimately `delegatecall` into an implementation with a guarded upgrade path.
- `receive()` that only exists to accept a known, accounted deposit flow with a matching withdraw.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, PoC stub, patch sketch,
checklist items.`
