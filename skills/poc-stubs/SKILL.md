---
id: poc-stubs
applies_to: evm, hyperevm, solana
severities: n/a
cwe: n/a
detector: solguardian/report/pocs.py (+ report/templates/)
---

# PoC stubs: what every finding must ship

## When to use
For every confirmed finding, before the report is written.

## Checklist
1. One stub per finding, named `pocs/<finding-id>_<slug>.t.sol` (Foundry) or
   `pocs/<finding-id>_<slug>.rs` (Anchor/Rust skeleton).
2. The header block carries finding id, title, severity, confidence, rule, skill pack and
   `file:line`, so the stub is self-describing out of context.
3. The attack path is expressed as ordered **comments** (step 1 / 2 / 3) copied from the exploit
   sketch, so a reviewer can wire the real call in minutes.
4. Two tests ship: the vulnerable path (`test_<slug>`) and a control (`test_<slug>_afterPatch`)
   that must fail once the patch lands.
5. `setUp()` wires only the synthetic sample - no RPC URL, no key, no mainnet fork needed to read
   it.
6. Nothing in a stub is a live weapon: no real addresses, no keys, no working exploit against
   deployed funds. Placeholders and an explicit `panic!("PoC stub ...")` stay in place.
7. The stub states its run command (`forge test --match-contract X -vvvv`,
   `cargo test --features test-suites x`).

## Severity guidance
Stub completeness is not a severity input. A stub is required for critical/high/medium and is
optional for low/info.

## False positives
n/a - this pack describes output shape, not a bug class.

## Required output fields
`poc.language`, `poc.filename`, `poc.how_to_run`, `poc.code` on every finding object.
