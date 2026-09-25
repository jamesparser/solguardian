# Bob task 02 - EVM / Solidity detectors

**Screenshot to save:** `bob_sessions/solguardian_task02_evm_detectors_summary.png`
**Planned cost:** ~10 Bobcoins
**Bob features to show:** Agent mode editing multiple files, running tests in the terminal

```
Work in solguardian/detectors/ on the seven EVM detectors already scaffolded:
evm_reentrancy, evm_access, evm_external_calls, evm_delegatecall, evm_oracle,
evm_sig_replay, evm_selfdestruct.

Ground rules (from AGENTS.md and skills/severity-grading/SKILL.md):
1. All pattern matching runs against SourceIndex.masked, never raw text, so comments and
   string literals can never produce a finding.
2. Every detector returns findings built with self.make(...) so the output contract is
   filled in one place: severity, confidence, line, evidence, exploit sketch, patch sketch,
   PoC stub, skill checklist.
3. Use the shared helpers in core/evmutil.py - call_sites(), state_writes(), guards_in(),
   has_auth_guard() - instead of re-inventing regexes, so packs agree with each other.
4. De-duplicate by root cause across packs: a delegatecall or selfdestruct issue belongs to
   evm_delegatecall / evm_selfdestruct, not to evm_access.

Now: run the sample through the CLI (`python3 -m solguardian analyze samples/solidity/Vault.sol`),
read out/samples/report.json, and for each seeded issue in samples/EXPECTED_FINDINGS.json
either prove it is caught or fix the detector. Then remove any false positive the run reveals
and add a regression test for it in tests/test_solguardian.py under TestGroundTruth.

Finish by running: python3 -m unittest discover -s tests -v
```

Before screenshotting: test run green, and `report.md` shows the 5 Vault.sol seeded issues.
