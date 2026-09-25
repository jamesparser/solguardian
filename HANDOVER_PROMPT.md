# SOLGUARDIAN — BLANK-SLATE BUILD PROMPT
# Copy everything below the line into your coding agent (or attach this file).
# Self-contained. No other context required.

================================================================================
# MISSION
================================================================================
You are the implementation agent for **SolGuardian**, a hackathon project for the
**IBM Bob 2.0 Hackathon** (lablab.ai × IBM). Submissions close:
**Sep 27, 2026 22:00 Bangkok (UTC+7)**. Start now. Demoable end-to-end by
**Sunday 12:00 Bangkok**. Submit before 22:00.

**Product:** Automated exploit hunter for smart contracts on
**Ethereum / EVM (Solidity)**, **Solana (Rust / Anchor)**, and **Hyperliquid**
(HyperEVM Solidity + related Rust where applicable).

**Team / brand:** Jason Parser Research  
**GitHub org user:** `jamesparser`  
**Repo (use this):** https://github.com/jamesparser/solguardian  
**Team page:** https://lablab.ai/ai-hackathons/ibm-bob-2-hackathon/jason-parser-research

**One-line pitch:** Point SolGuardian at contract source; specialized agents hunt
real exploit classes and emit ranked findings with a minimal PoC stub and a patch sketch.

You implement everything. Be decisive. Prefer a working demo over polish.

================================================================================
# CRITICAL ENVIRONMENT RULES
================================================================================
1. **IBM Bob IDE is mandatory** and must be a **core component** of the solution
   (not optional tooling). Judges disqualify projects that do not showcase Bob.
   - Bob is IBM's AI coding IDE (chat, Agent mode, subagents, skills, MCP).
   - You are **not** building a Bob plugin as the product.
   - You **are** building a real tool **inside Bob**, developed and demoed there.
   - Portable CLI core must still run outside Bob (useful after the hackathon).

2. **Bob account / Bobcoins**
   - Finish IBMid login first (email verification code required to complete signup).
   - After the hackathon invite email (“added to ibm-hackathon-xxxx”), in Bob IDE:
     Settings → General → switch instance to **`ibm-coding-challenge-uat`**
     (region **us-east**). Never burn a personal Bob account.
   - Only **40 Bobcoins** exist. No top-up. Spend on orchestration/review/skills.
     Implement detectors as real code so the tool works even if Bob is exhausted.

3. **`bob_sessions/` is a required deliverable**
   - Folder `bob_sessions/` in the public repo.
   - PNG screenshots of **Bob task session consumption summaries**.
   - How: Bob IDE chat → Tasks → open task → click task header → screenshot the
     session consumption summary.
   - Name like: `solguardian_task01_evm_detectors_summary.png`
   - Capture **as you complete each workstream**, never at the last minute.

4. **Data rules (strict)**
   - Synthetic/teaching sample contracts you write + public documentation only.
   - Forbidden: client data, company confidential data, personal info, social scrapes.
   - Keep `DATA_SOURCES.md` listing every source you used.

5. **Repo rules**
   - Public GitHub repo under `jamesparser`. MIT license.
   - **Never commit secrets** (API keys, mnemonics, RPC keys). Use `.gitignore` + `.bobignore`.
   - Original work. Do **not** reuse or rebrand any other hackathon project
     (especially agent-to-agent messaging hubs). This must be a distinct product.

6. **Submission format (lablab)**
   - Video **≤3 minutes**, ≥90s live demo with narration, must show Bob in use.
   - Two written statements, **≤500 words each**:
     Problem & Solution; IBM Bob Usage.
   - Public repo link, cover image, slides, demo URL (GitHub Pages OK).
   - Later: post-hackathon feedback form (needed for participant rewards).

================================================================================
# PRODUCT SPEC
================================================================================
## In scope (must ship)
A pipeline: **target source → findings report**.

### Targets
A. **Solidity / EVM** (Ethereum, Arbitrum, Base, **HyperEVM / Hyperliquid**, etc.)
B. **Solana / Anchor (Rust)**
C. **Hyperliquid-specific notes** on HyperEVM Solidity (same EVM detectors) plus
   any simple Rust/program pitfalls you can cover without inventing a new chain
   client. Do not build a Hyperliquid node or indexer.

### Detectors — EVM / Solidity
1. Reentrancy (state after external call)
2. Access control (missing onlyOwner / arbitrary admin / tx.origin)
3. Unchecked external call return value
4. Dangerous delegatecall / proxy storage collision notes
5. Oracle / price assumptions (spot price, single feed)
6. Signature / replay / nonce / deadline gaps
7. selfdestruct / arbitrary send / stuck funds notes

### Detectors — Solana / Anchor
1. Missing signer checks
2. Missing owner / account type checks (account confusion)
3. CPI / privilege / `has_one` / seeds validation gaps
4. Integer overflow / precision (unchecked math)
5. Authority footguns (upgrade / freeze / mint) as static notes
6. Unsafe deserialization / remaining accounts issues

### Each finding must include
- id, severity (critical/high/medium/low), confidence
- short title + 2–5 sentence **human-readable** explanation
- location: file:line or function
- exploit sketch (educational steps — not a live weapon against mainnet)
- **PoC stub** (Foundry test skeleton **or** Anchor/Rust test skeleton)
- patch sketch (1–6 lines of guidance)

### Outputs
- `report.json` (machine-readable)
- `report.md` (human / demo)
- `pocs/` stub files
- optional `report.html` static page (good for video / GitHub Pages)

## Out of scope (do NOT build)
- Full symbolic execution / custom bytecode VM / SMT solver
- Live mainnet scanners requiring paid RPC/API keys
- Hyperledger, hash-receipt blockchains, on-chain notary systems
- Agent payments (x402/x401), A2A messaging protocols
- Bob plugin marketplaces, UI polish wars, login systems
- Anything requiring credentials you do not have

## Skills packs (required — this is the “ClawHub” idea)
Create `skills/` with **verified checklists** the agents/rules use:
- `skills/reentrancy/SKILL.md`
- `skills/access-control/SKILL.md`
- `skills/oracle-price/SKILL.md`
- `skills/solana-account-validation/SKILL.md`
- `skills/hyperliquid-hyperevm-notes/SKILL.md`
- `skills/severity-grading/SKILL.md`
- `skills/poc-stubs/SKILL.md`
Each skill file: when to use, checklist, false-positive notes, required output fields.
These make the system explainable and reusable.

================================================================================
# REPO LAYOUT (create this on a blank machine)
================================================================================
solguardian/
  README.md
  LICENSE                    # MIT
  STATEMENTS.md              # two ≤500-word submission drafts
  DATA_SOURCES.md
  BUILD.md                   # how to run CLI + how Bob was used
  bob_sessions/              # REQUIRED PNGs
  skills/                    # checklists above
  samples/
    solidity/Vault.sol       # synthetic seeded bugs
    solidity/HyperVault.sol  # HyperEVM-style synthetic
    solana/vault/            # synthetic Anchor project or .rs excerpts
  solguardian/               # Python package (preferred) OR src/ for TS
    __init__.py
    cli.py                   # `solguardian analyze <path>`
    detectors/
      evm_reentrancy.py
      evm_access.py
      evm_external_calls.py
      evm_oracle.py
      evm_sig_replay.py
      solana_signer.py
      solana_accounts.py
      solana_cpi.py
    report/
      json_report.py
      md_report.py
    pocs/
      foundry_stub.t.sol
      anchor_stub.rs
  tests/
  .gitignore
  .bobignore

**Stack:** Python 3.11+ preferred (fast to ship). TypeScript acceptable if Bob
makes that smoother. Detectors = AST/regex/heuristics + structured reasoning.
No ML training. No Docker required.

**CLI (must work outside Bob):**
```
solguardian analyze samples/solidity/Vault.sol
solguardian analyze samples/solana/vault
# writes report.json + report.md
```

================================================================================
# BOB IDE USAGE PLAN (eligibility — do not skip)
================================================================================
Do major workstreams **in Bob IDE** and screenshot each task summary.

Suggested Bob tasks (name screenshots to match):
1. `solguardian_task01_agents_md_init_summary.png` — `/init` + AGENTS.md
2. `solguardian_task02_evm_detectors_summary.png`
3. `solguardian_task03_solana_detectors_summary.png`
4. `solguardian_task04_skills_pack_summary.png`
5. `solguardian_task05_report_cli_summary.png`
6. `solguardian_task06_end_to_end_demo_summary.png`

Bob must show: **Agent mode**, **parallel subagents** (e.g. EVM hunter, Solana
hunter, report writer), **document understanding** on samples/skills, code
review/commit flows.

**Bobcoin budget (~40):** init 4 · EVM 10 · Solana 8 · skills 6 · report/CLI 6 · demo 4 · reserve 2.

================================================================================
# SAMPLES (synthetic only)
================================================================================
Seed ~8 intentional issues total, clearly marked educational.

`Vault.sol` (EVM):
- reentrancy in withdraw
- missing access control on adminDrain
- tx.origin auth
- unchecked call return
- spot-price oracle assumption

`HyperVault.sol`:
- same EVM classes, framed as HyperEVM lending/vault pattern (no real protocol copy)

`solana/vault`:
- missing signer
- account type confusion
- unchecked CPI
- precision loss

================================================================================
# DEMO METRICS (show these)
================================================================================
- Seeded critical/high findings caught (aim ≥7/8)
- Time to first full report (<5 minutes)
- Every finding explained in plain English in ~15 seconds
- PoC stub per confirmed finding

================================================================================
# VIDEO SCRIPT (≤3 min, you record or prepare the script + screen path)
================================================================================
0:00–0:25  Pain: audits are slow; exploit classes get missed  
0:25–1:00  What SolGuardian is (README or 1 slide)  
1:00–2:20  LIVE in IBM Bob IDE: open sample → run SolGuardian → parallel
           subagents → findings + PoC stub (this section ≥90s)  
2:20–2:45  Metrics + bob_sessions/ evidence  
2:45–3:00  Jason Parser Research · built with IBM Bob

Narration required. Show the Bob UI, not only a terminal.

================================================================================
# WORKING AGREEMENTS
================================================================================
- Implement in small commits. After each Bob workstream, save a PNG to `bob_sessions/`.
- Demo path before polish. If time is short, keep **at least 2 Solana detectors**.
- Do not invent network credentials. Samples run offline.
- When the hackathon Bob invite arrives, switch the IDE account **before** heavy use.
- If a detector is heuristic, say so in README (false-positive honesty).

================================================================================
# IMMEDIATE START ORDER
================================================================================
1. Open IBM Bob IDE. Complete login (IBMid + email verification code).
2. Clone/open https://github.com/jamesparser/solguardian (already created) OR
   `git clone git@github.com:jamesparser/solguardian.git`
3. In Bob: `/init` for AGENTS.md describing SolGuardian.
4. Scaffold package + CLI + sample contracts with seeded bugs.
5. EVM detectors → report.md/json.
6. Solana detectors.
7. Skills packs.
8. End-to-end CLI run on samples. Save outputs.
9. Record demo path. Write STATEMENTS.md. Capture remaining bob_sessions PNGs.
10. Push everything public. Prepare lablab submission fields.

================================================================================
# SUCCESS DEFINITION
================================================================================
Done means: public repo runs
`solguardian analyze samples/...` and prints a credible multi-finding report;
Bob IDE visibly orchestrated the work; `bob_sessions/` has PNGs; statements and
video materials exist; nothing secret committed; project is original and
judged as a developer-workflow improvement (testing / code review) with Bob core.

# GO.
================================================================================
