---
id: oracle-price
applies_to: evm, hyperevm
severities: critical, high, medium
cwe: CWE-1231
detector: solguardian/detectors/evm_oracle.py
---

# Oracle & price assumptions

## When to use
Any function that converts between assets, values collateral, computes shares/NAV, or
decides liquidations - including HyperEVM vaults reading HyperCore-style spot prices.

## Checklist
1. Identify the pricing source: in-pool reserves (spot), a single Chainlink round, a
   protocol-internal `getPrice`, or an RPC-supplied number.
2. Spot price from a pool the protocol does not control is never used for valuation; a
   time-weighted or multi-round price is.
3. Chainlink reads validate all four of: `updatedAt` freshness, `answeredInRound >= roundId`,
   `answer > 0`, and (for round-critical flows) `startedAt`.
4. A second, independent source or a max-deviation circuit breaker exists for anything that
   moves value.
5. Units/exponents are asserted (1e8 Chainlink vs 1e18 pool decimals vs HyperCore asset
   exponent) before values are combined.
6. `block.timestamp`/`block.number` are not used as pricing windows.
7. The price cannot be moved inside the same transaction that consumes it (flash-loan
   resistance), including via `flash`/`swap` callbacks in the same call stack.

## Severity guidance
- **critical**: spot reserves directly set mint/redeem/liquidation amounts.
- **high**: stale/unvalidated round, or single source gating value.
- **medium**: exponent/rounding assumptions, `latestAnswer` misuse.
- **low**: timestamp-window assumptions documented but weak.

## False positives
- Reads that are only used for off-chain display.
- Chainlink `checktransparency`/`updateRoundData` flows where a separate verifier guards
  freshness.
- Deliberate TWAP implementations with a documented window and lookback.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, PoC stub, patch sketch,
checklist items.`
