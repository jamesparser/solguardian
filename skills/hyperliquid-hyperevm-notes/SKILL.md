---
id: hyperliquid-hyperevm-notes
applies_to: hyperevm, evm
severities: high, medium
cwe: n/a
detector: shared EVM detectors + chain tagging in solguardian/core/source.py
---

# HyperEVM (Hyperliquid) notes

Scope discipline: SolGuardian treats HyperEVM as **EVM bytecode with different trust
assumptions**. It does not build a Hyperliquid node, indexer or HIP-3 client, and it never
copies a live protocol's code. Everything below is written against the synthetic
`samples/solidity/HyperVault.sol`.

## When to use
When the target is HyperEVM Solidity (or Rust that talks to HyperCore), after the normal EVM
detectors have run — this pack changes what "trusted" means, not the rule set.

## Checklist
1. Bridge-minted balances are treated as a privileged mint path: assets entering HyperEVM come through Hyperliquid's bridge and are only as trustworthy as the bridge message.
2. HyperCore price reads validate which asset is being queried and its decimal exponent; a thin market's print is movable and must never gate settlement without a circuit breaker (see `skills/oracle-price`).
3. System/precompile addresses are hard-coded with a deployment-time `require(addr != 0)` check; no address is assumed to be populated without validation.
4. Every `send`/`transfer` stipend and `msg.value` accounting assumption ported from an L1/L2 codebase is re-tested against HyperEVM's native asset and fee model.
5. "Wait N confirmations" logic accounts for the fact that bridge-confirmed state and reorg-protected state may be observable differently on HyperEVM.
6. HyperEVM contracts carry the same admin/implementation footguns as other EVM chains — the access-control and delegatecall detectors are the primary risk, not the chain itself.
7. Rust code that communicates with HyperCore types uses message/struct validation habits from `skills/solana-account-validation` but does **not** apply Solana runtime rules: no PDAs, no CPI semantics, no lamport accounting.

## Severity guidance
Keep the underlying rule's severity; the chain tag changes the *exploit sketch* (bridge or
HyperCore price path), not the grade. Bump a single-source HyperCore price read one step above
the same pattern on an Ethereum L2 when the asset's venue liquidity is unknown — the fix (a second
source) is cheap.

## False positives
- Reading a HyperCore price for *display* rather than settlement.
- Bridge-minted tokens handled behind an allowlist of canonical addresses.

## Required output fields
`chain: "hyperevm"` on every finding, plus a bridge/price-path note in the exploit sketch. Everything else follows the standard finding contract.
