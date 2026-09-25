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
detectors have run - this pack changes what "trusted" means, not the rule set.

## Checklist
1. **Value bridge**: assets entering HyperEVM come through Hyperliquid's bridge, so a
   "canonical token" balance is only as trustworthy as the bridge message. Treat bridge-minted
   balances like a privileged mint path.
2. **HyperCore price reads**: perp spot prices are consensus inputs with their own update
   cadence and per-asset liquidity. Validate *which* asset is being asked and its exponent, and
   never assume a deep venue behind the number - a thin market's print is movable
   (`skills/oracle-price`).
3. **System / precompile addresses**: HyperEVM exposes non-EVM-native addresses for core reads.
   Hard-coding them without `require(addr != 0)` and a deployment check is fragile.
4. **Native token & gas**: the native asset and fee model differ from Ethereum, so re-test every
   `send`/`transfer` stipend and `msg.value` accounting assumption ported from an L1/L2 codebase.
5. **Finality assumptions**: any "wait N confirmations" logic needs a second look; bridge-
   confirmed state may be observable differently from reorg-protected state.
6. **Upgrade authority**: HyperEVM contracts still ship the same admin/implementation footguns as
   everywhere else - the access-control and delegatecall detectors are the real risk here, not
   the chain.
7. **Rust side**: where a project has Rust talking to HyperCore types, keep the message/struct
   validation habits from `skills/solana-account-validation`, but do **not** apply Solana runtime
   rules (no PDAs, no CPI, no lamports) to it.

## Severity guidance
Keep the underlying rule's severity; the chain tag changes the *exploit sketch* (bridge or
HyperCore price path), not the grade. Bump a single-source HyperCore price read one step above
the same pattern on an Ethereum L2 when the asset's venue liquidity is unknown - the fix (a second
source) is cheap.

## False positives
- Reading a HyperCore price for *display* rather than settlement.
- Bridge-minted tokens handled behind an allowlist of canonical addresses.

## Required output fields
`chain: "hyperevm"` on every finding, plus a bridge/price-path note in the exploit sketch.
Everything else follows the standard finding contract.
