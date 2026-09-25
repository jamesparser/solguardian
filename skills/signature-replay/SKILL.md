---
id: signature-replay
applies_to: evm, hyperevm
severities: critical, high, medium
cwe: CWE-294
detector: solguardian/detectors/evm_sig_replay.py
---

# Signatures: replay, nonce, deadline, malleability

## When to use
Anything accepting `(v, r, s)`, a `bytes signature`, `permit`, meta-transactions, offline
authorisations, bridge payloads or treasury grant claims.

## Checklist
1. The digest commits to the verifying context: EIP-712 domain separator with `name`,
   `version`, `chainId`, `verifyingContract`.
2. A spend-once record exists (per-hash mapping or per-signer nonce) and is written in the same
   transaction as the payout.
3. A `deadline` is part of the signed payload and is enforced against `block.timestamp`.
4. Malleability is handled by a library (`ECDSA.recover`/`tryRecover`, enforced low-s,
   `v in {27,28}`) rather than raw `ecrecover`.
5. Signer identity is bound to a role/allowlist, not merely "an address that signed something".
6. The same signature is worthless on a fork, a testnet or a sibling deployment because the
   domain separator includes `block.chainid`.
7. Batch payloads bind the whole payload hash (no partial-subset replay).

## Severity guidance
- **critical**: a verified signature moves value with no spend-once tracking.
- **high**: unbound digest (cross-chain / cross-contract replay).
- **medium**: no deadline, or raw `ecrecover` without malleability checks.

## False positives
- OZ `EIP712` + `nonces[signer]++` implemented in a modifier or helper.
- `permit`-style flows where the token's own nonce governs replay.

## Required output fields
`id, severity, confidence, location, explanation, exploit sketch, PoC stub, patch sketch,
checklist items.`
