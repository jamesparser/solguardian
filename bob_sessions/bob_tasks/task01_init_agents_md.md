# Bob task 01 - `/init` + AGENTS.md

**Screenshot to save:** `bob_sessions/solguardian_task01_agents_md_init_summary.png`
**Planned cost:** ~4 Bobcoins
**Bob features to show on camera:** repo indexing, `/init`, Agent mode

Run in Bob IDE chat (Agent mode) on the cloned repo:

```
/init
```

Then paste as the follow-up instruction:

```
You are setting up SolGuardian for the IBM Bob 2.0 Hackathon (Jason Parser Research).

Write AGENTS.md for this repo. It must tell a future coding agent:
- product: automated exploit hunter for Solidity (EVM + HyperEVM) and Rust (Solana/Anchor)
- hard rules: Bob IDE is a core component; detectors must be deterministic code that runs
  offline with zero API keys; synthetic samples only, never client or mainnet data;
  never commit secrets; MIT; original work only
- layout: solguardian/{core,detectors,report,agents}, skills/, samples/, bob_sessions/
- the finding contract every detector must satisfy: id, severity, confidence, plain-English
  description, file:line + function, exploit sketch, PoC stub, patch sketch, skill reference
- how to run: python3 -m solguardian analyze samples; python3 -m unittest discover -s tests
- severity model lives in skills/severity-grading/SKILL.md and is authoritative

Keep it under ~120 lines and make every rule checkable by a test.
```

Before screenshotting: confirm `AGENTS.md` was created and Bob shows the file diff.
