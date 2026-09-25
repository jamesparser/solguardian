# Bob task 06 - End-to-end run + commit flow

**Screenshot to save:** `bob_sessions/solguardian_task06_end_to_end_demo_summary.png`
**Planned cost:** ~4 Bobcoins
**Bob features to show:** full run, then the review/commit flow

```
Final pass over SolGuardian:

1. Run the whole pipeline and confirm: 17/17 seeded issues caught, **zero findings on
   `samples/clean/`**, no missed key, report
   generated in under 5 seconds, PoC stubs written for every finding.
     python3 -m solguardian analyze samples --out out/samples --html
2. Run the test suite and the agent pipeline parity check.
     python3 -m unittest discover -s tests -v
3. Regenerate the committed demo outputs under demo/ from the samples run.
4. Review the diff for anything that must not be committed: secrets, RPC urls, personal
   data, real protocol names copied from audits. Report what you find; do not commit it.
5. Propose the commit split (small commits per workstream) and the README wording that
   states honestly that the detectors are heuristic.
```

## The 90-second on-camera path (this is the ≥90s live demo section)

1. `git clone` already done → open the repo in Bob IDE.
2. Open `samples/solidity/Vault.sol` in the editor, point at `withdraw()` (visible bug).
3. Bob chat (Agent mode), paste:
   ```
   Run SolGuardian on samples/solidity/Vault.sol and explain the top three findings in
   plain English, citing the skill checklist each one satisfied.
   ```
4. Show the ranked table in the terminal, then `out/vault/report.md` side by side.
5. Run `solguardian analyze samples --html` and open `out/samples/report.html`.
6. Show `bob_sessions/` with the earlier task summaries.
7. End on `python3 -m unittest discover -s tests -v` finishing green.

Narration beats: "audits take weeks", "this is deterministic code, not a model guessing",
"every finding carries a PoC stub and a patch sketch", "the same CLI works after the
hackathon, with zero Bobcoins left".
