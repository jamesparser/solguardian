# Bob task 03 - Solana / Anchor detectors (parallel subagents)

**Screenshot to save:** `bob_sessions/solguardian_task03_solana_detectors_summary.png`
**Planned cost:** ~8 Bobcoins
**Bob features to show:** **parallel subagents** - open the subagent panel while it works

```
Spawn parallel subagents for the Solana side and let them work at the same time:

Agent A - solguardian/detectors/solana_signer.py and solana_authority.py
Agent B - solguardian/detectors/solana_accounts.py and solana_deser.py
Agent C - solguardian/detectors/solana_cpi.py and solana_math.py

Shared brief for all three:
- the parser is core/rust.py: handlers() gives `pub fn ... (ctx: Context<X>)`,
  struct_for() resolves X (including `Context<'_, '_, '_, 'info, X<'info>>`), and each
  RsField carries `attrs`, `raw_account`, `is_signer`
- match against index.masked only
- Solana authorisation IS the account list: report an UncheckedAccount/AccountInfo that
  gates a privileged action, and never assume a `msg.sender` exists
- do not demand Signer<'info> for program slots (token_program, system_program) or for
  PDAs authorised by seeds - that is the noise this tool must not produce
- every finding cites skills/solana-account-validation/SKILL.md (or solana-signer /
  solana-cpi / solana-math) and lists the checklist items it satisfied

Target file: samples/solana/vault/programs/vault/src/lib.rs
Expected: the seven seeded keys in samples/EXPECTED_FINDINGS.json, nothing else in
TestGroundTruth.test_negative_cases_not_flagged.
```

Before screenshotting: show the subagent panel with 3 concurrent agents, then
`python3 -m solguardian analyze samples/solana` output.
