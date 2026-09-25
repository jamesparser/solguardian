# BUILD PROMPT — hand this whole file to your coding agent
# Project: SolGuardian · IBM Bob 2.0 Hackathon · Jason Parser Research
# Coordination agent (MiMo) does NOT implement. You (coding agent) implement.

---

## 0. Mission
Build **SolGuardian**: a multi-agent smart-contract exploit hunter for **Solidity (EVM)** and **Solana (Rust/Anchor)** that runs as a real tool, developed and demonstrated **inside IBM Bob IDE** so Bob is clearly a core component (hackathon eligibility).

Team brand: **Jason Parser Research**  
Product name: **SolGuardian** (locked)  
Tagline: *Automated exploit hunting for Solidity & Solana*

One-sentence pitch: Point SolGuardian at contract source; parallel agents hunt real exploit classes and emit ranked findings with a minimal PoC stub and a patch sketch.

---

## 1. Context you need
- Event: IBM Bob 2.0 Hackathon (lablab.ai × IBM), **Sep 25–27, 2026**, submissions close **Sep 27 22:00 Bangkok (UTC+7)**
- Working repo: https://github.com/jamesparser/clear-to-ship (RENAME this repo to `solguardian` OR create `jamesparser/solguardian` — preferred name **jamesparser/solguardian**)
- Team page: https://lablab.ai/ai-hackathons/ibm-bob-2-hackathon/jason-parser-research
- Official guide: `bob-hackathon/docs/bob2-hackathon-guide.html` (workspace copy)
- **Bob IDE is required.** Solution must **showcase IBM Bob IDE as a core component**. Optional: Bob Shell, watsonx.

### What Bob is / is not
- IBM Bob = IBM's AI coding IDE (chat, Agent mode, subagents, skills, MCP) — like Cursor/Claude Code, **not** OpenAI Codex
- We are **not** building a Bob plugin as the product
- We **are** building a real tool **with** Bob as the development + demo engine
- Portable core (CLI/library) must still run outside Bob so the tool is useful after the hackathon

### Hard eligibility rules
1. IBM Bob IDE must be **visibly core** (Agent mode, parallel subagents, document understanding, code reviews)
2. `bob_sessions/` folder in the final public repo — PNG screenshots of **Bob task session consumption summaries**, named e.g. `solguardian_task01_reentrancy_scan_summary.png`. Capture **during the build**, not at the last minute
3. Clean data only: sample/synthetic contracts + public docs. **No** client data, PI, social scrapes. Keep `DATA_SOURCES.md`
4. **40 Bobcoins** on the hackathon account — spend carefully; no top-up
5. Public GitHub repo, MIT, **no secrets** (use `.gitignore` / `.bobignore`)
6. Original work — **do not** reuse or rebrand BGI `a2a-omega` (different event)
7. Video ≤3 min with ≥90s live demo + narration showing Bob usage
8. Two statements ≤500 words: Problem & Solution + IBM Bob Usage

---

## 2. Product spec (what you build)

### 2.1 In scope (MVP that demos well)
A pipeline that takes a **target contract** (Solidity `.sol` and/or Anchor/Rust `.rs`) and produces a **findings report**.

**Detectors (implement as separate analyzers / Bob subagent roles):**

Solidity / EVM:
1. Reentrancy (state change after external call)
2. Access control / missing modifiers / `tx.origin`
3. Unchecked external call / return value
4. Delegatecall / proxy misconfig
5. Oracle / price assumption (spot vs TWAP notes)
6. Signature / replay / nonce gaps
7. Dangerous `selfdestruct`, `suicide`, arbitrary send

Solana / Anchor:
1. Missing signer / owner checks
2. Account confusion / type cosplay (`Account` vs unchecked)
3. CPI privilege / missing `has_one` / seeds validation
4. Integer overflow / precision (if no checked math)
5. Freeze authority / upgrade authority footguns (static notes)
6. Unchecked account data deserialization

**Each finding must include:**
- id, severity (critical/high/medium/low), confidence
- title + 2–5 sentence explanation **a human can understand**
- file:line or function name
- exploit sketch (step-by-step, not a weapon — educational repro)
- **PoC stub** (Foundry test skeleton or Anchor test skeleton)
- patch sketch (1–6 lines of guidance)

**Outputs:**
- `report.json` (machine)
- `report.md` (human / demo)
- `pocs/` stubs
- optional simple static HTML page that renders the report (nice for video)

### 2.2 Out of scope (do NOT build)
- Full symbolic execution / custom bytecode VM
- On-chain live scanning of mainnet (unless trivial and optional)
- Agent payment (x402) features
- Hyperledger / Hyperliquid consensus integrations
- BGI A2A messaging protocols
- A “Bob plugin marketplace”
- Anything that requires API keys you don’t have

### 2.3 Hyperledger / audit trail (optional, simplified)
**Why one might want it:** timestamped proof you found X before someone else (bounty priority).  
**How (simple):** local append-only signed hash log of findings (`audit/receipts.jsonl` with SHA-256 + timestamp). **Skip blockchain.** Only mention “immutable-style receipt log” in the writeup. Do not spend hours on chains.

### 2.4 ClawHub / skills pack (do this)
Include `skills/` (or `.bob/skills/` + `rules/`) as **verified smart-contract security skill packs** the agents use:
- `skills/reentrancy/SKILL.md`
- `skills/access-control/SKILL.md`
- `skills/solana-account-validation/SKILL.md`
- `skills/severity-grading/SKILL.md`
- `skills/poc-stubs/SKILL.md`
Each skill: when to use, checklist, false-positive notes, output format. These make the product explainable and reusable (“we ship verified check packs”).

---

## 3. Architecture (keep it boring and shippable)

```
solguardian/
  README.md                 # product story + demo
  STATEMENTS.md             # two ≤500w submissions drafts
  DATA_SOURCES.md
  bob_sessions/             # REQUIRED screenshots (PNG)
  skills/                   # smart-contract skill packs
  samples/
    solidity/Vault.sol      # seeded bugs (synthetic)
    solana/vault/           # seeded Anchor bugs (synthetic)
  src/ or solguardian/
    cli.py | cli.ts         # `solguardian analyze path/to/contract`
    detectors/              # one module per detector class
    report/                 # json/md/html renderers
    pocs/                   # stub templates
  tests/
  audit/receipts.jsonl      # optional hash log
  .gitignore
  .bobignore
```

**Stack preference (pick one and stick to it):**
- **Python** (fast to ship detectors + report) **or**
- **TypeScript/Node** if Bob demo feels smoother
- Foundry only as **PoC stub text**, not a full suite requirement
- No heavy ML. Pattern/AST/regex + structured LLM roles via Bob is fine.

**Runtime story:**
1. **Primary demo:** IBM Bob IDE Agent mode runs the pipeline with **parallel subagents**
2. **Portable CLI:** `solguardian analyze samples/solidity/Vault.sol` so the tool works outside Bob later

---

## 4. IBM Bob IDE usage plan (eligibility — do not skip)

Use Bob IDE for **every major workstream** and **screenshot task summaries as you go**.

Required Bob showcase (make visible in video):
1. `/init` / AGENTS.md on the repo (persistent context)
2. **Agent mode** to implement detectors
3. **Parallel subagents** for detector families (security, Solana, reporting)
4. Document understanding on sample contracts + skill packs
5. Code review / commit / PR flow via Bob where natural
6. Custom rules or skills that encode SolGuardian severity policy

Suggested task list for `bob_sessions/` (name files like this):
- `solguardian_task01_agents_md_init_summary.png`
- `solguardian_task02_evm_detectors_summary.png`
- `solguardian_task03_solana_detectors_summary.png`
- `solguardian_task04_report_pipeline_summary.png`
- `solguardian_task05_skills_pack_summary.png`
- `solguardian_task06_demo_end_to_end_summary.png`

**Bobcoin budget (~40):** scaffold 4 · detectors 14 · report 8 · skills 6 · demo re-runs 4 · reserve 4.

**Account switch (critical):** After the hackathon invite email, in Bob IDE → Settings → General → select **`ibm-coding-challenge-uat` (region: us-east)**. Do not burn personal coins.

---

## 5. Demo contracts (synthetic, seeded)
Create 6–10 intentional issues total across two targets, e.g.:

`Vault.sol`:
- reentrancy in `withdraw`
- missing access control on `adminDrain`
- `tx.origin` auth
- unchecked `call` return
- centralized oracle spot price

`vault` (Anchor):
- missing signer check
- account type confusion
- unchecked CPI
- precision loss on token math

**Label them clearly as synthetic teaching samples.** No live mainnet “victims.”

---

## 6. Demo metrics (tape these on screen)
| Metric | Target |
|--------|--------|
| Seeded critical/high findings caught | e.g. 7/8 or better |
| Time to first report | &lt; 5 minutes end-to-end |
| Human explanation quality | every finding readable in 15s |
| PoC stub generated | 1 per confirmed finding |

---

## 7. Video plan (≤3 minutes)
1. **0:00–0:25** Pain: audits take days; juniors miss classes; bounty work is grind
2. **0:25–1:00** What SolGuardian is (one slide or README)
3. **1:00–2:20** **Live in Bob IDE:** open sample → run SolGuardian → show **parallel subagents** → findings + PoC stub
4. **2:20–2:45** Metrics + `bob_sessions/` evidence
5. **2:45–3:00** Jason Parser Research + “built with IBM Bob”

Narration required. Show Bob UI, not only terminal.

---

## 8. Submission checklist (lablab)
- [ ] Public repo `jamesparser/solguardian` (or renamed clear-to-ship)
- [ ] `bob_sessions/` complete PNGs
- [ ] `report.md` from a real run on samples
- [ ] `DATA_SOURCES.md`
- [ ] `STATEMENTS.md` (Problem & Solution + IBM Bob Usage, each ≤500w)
- [ ] Video MP4 ≤3 min
- [ ] Cover image + short slides
- [ ] Demo app URL (GitHub Pages of `report.html` is enough)
- [ ] MIT LICENSE
- [ ] Submit on lablab before **Sep 27 22:00 Bangkok**
- [ ] Later: post-hackathon feedback form (for $100 participant reward)

---

## 9. Naming / brand
- Product: **SolGuardian**
- Org/author line: Jason Parser Research · @jasonparsersec · github.com/jamesparser
- Do **not** call it ExploitSmith / SecureShip Gate / Clear to Ship (dead names)
- Optional footer: “Skills packs derived from verified smart-contract checklists”

---

## 10. Working agreements
1. **You implement.** MiMo (this coordinator) only orchestrates, writes prompts, tracks, and submits copy.
2. Prefer **small PRs** with screenshots of Bob sessions attached to the PR body or `bob_sessions/`.
3. If Bobcoins are tight, implement detectors as pure code and use Bob for orchestration/review/skills — still show Agent mode + subagents.
4. If time is tight, cut Solana depth first **only if** Solidity path is fully demoable; but try to keep **at least 2 Solana detectors** because the name and pitch promise both.
5. When stuck: ship the demo path before polish.

---

## 11. Immediate next steps for you (coding agent)
1. Confirm Bob IDE installed (v2.2.0) and login works
2. When invite arrives: switch to `ibm-coding-challenge-uat` / us-east
3. Create/rename GitHub repo to **jamesparser/solguardian**
4. `/init` in Bob + AGENTS.md
5. Seed `samples/` + skeleton CLI
6. Implement EVM detectors → report
7. Add Solana detectors
8. Write skills packs
9. End-to-end demo + screenshots + statements + video

---

## 12. References
- Event: https://lablab.ai/ai-hackathons/ibm-bob-2-hackathon
- Guide: https://lablab-ibm-bob-2-hackathon-guide.s3.us.cloud-object-storage.appdomain.cloud/index.html
- Bob docs: https://bob.ibm.com/docs/ide
- Bob download: https://bob.ibm.com/download
- Repo template: https://github.com/watsonxhackathon/ibm-hackathon-template

**Go build. Capture Bob session summaries as you go. Ship a demoable report by Sunday 12:00 Bangkok.**
