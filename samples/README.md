# Sample ground truth for SolGuardian

Synthetic, teaching-only contracts with **deliberately seeded** issues. Nothing here is
derived from a deployed protocol, and nothing here should ever be deployed.

| file | seeded issues |
| --- | --- |
| `solidity/Vault.sol` | reentrancy, unguarded drain, `tx.origin` auth, unchecked call, spot-price oracle |
| `solidity/HyperVault.sol` | caller-controlled delegatecall, signature replay (no nonce/deadline/binding), reachable selfdestruct, stranded-funds guard, unguarded pointer writes |
| `clean/CleanVault.sol` + `clean/clean_vault.rs` | **none** — the negative control: same shapes, validation present, must yield zero findings |
| `solana/vault` | missing signer, account type confusion, unchecked CPI, precision loss, client-supplied bump, unvalidated `remaining_accounts`, unsafe deserialization |

## Scoring

`EXPECTED_FINDINGS.json` is the denominator for the demo metric ("17/17 seeded issues
caught"). Run:

```bash
python3 -m solguardian analyze samples
```

The CLI auto-discovers this file, prints recall, and lists which seeded keys were caught by
which detector. Precision is reported as *unseeded* findings: SolGuardian is a heuristic
tool and flags more than the seed set on purpose (it also flags real issues in the samples
that were not counted as seeded). See `skills/severity-grading/SKILL.md` for the grading
contract and `../DATA_SOURCES.md` for provenance.
