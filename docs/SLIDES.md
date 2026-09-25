# Slide outline — 5 slides, text ready to paste

Keep each slide to one idea. All numbers below come from `demo/report.json`, so they are
verifiable, not aspirational. Build these in any tool; a text file in the repo beats a binary
deck nobody can diff.

---

### 1 — Title / pain

> **SolGuardian**
> Automated exploit hunting for Solidity & Solana
> Jason Parser Research · built with IBM Bob 2.0

- Audits: days, five figures, still miss classes
- Same mistake, three ecosystems, re-derived by eye every time
- Attackers automate; defenders do not

---

### 2 — What it is

> Point it at source. Get ranked findings with PoC stubs and patch sketches.

```
target source ──> EVM/HyperEVM hunter ─┐
                   Solana/Anchor hunter ├─> ranked report.json / .md / .html
                                        │      + pocs/*  + skill citations
                                        ┘
```

One finding = severity · confidence · `file:line` · plain-English reason · exploit sketch ·
PoC stub · patch sketch · checklist citation.

---

### 3 — How it works (the two design choices that matter)

1. **Deterministic detectors** — AST-lite + pattern rules, no LLM in the scan path.
   Reproducible, free, works offline, survives an empty AI budget.
2. **Skill packs** — 14 human-written checklists in `skills/`. Every finding quotes the items it
   satisfied. You can argue with the rule.

Plus: matching runs on **comment- and string-masked** source, so prose cannot create findings,
and **one root cause = one finding**, so packs do not pile up on the same line.

---

### 4 — Results

| metric | value |
| --- | --- |
| seeded issues caught | **17 / 17** |
| time to a full report | **0.9 s** (935 lines, 5 files; rule pass ~0.2 s) |
| detectors | 13 (7 EVM/HyperEVM · 6 Solana) |
| skill packs | 14 |
| findings emitted | 49 (16 critical · 18 high · 12 medium · 3 low) |
| findings on the clean negative control | **0** |
| PoC stubs | one per finding (Foundry / Anchor skeletons) |
| tests | 55 passing, stdlib only |
| network calls / API keys | **0** |

**Honesty slide, in the deck:** heuristics. False positives on unusual-but-correct code; false
negatives on anything the patterns do not describe — no symbolic execution, no cross-contract
data flow, no bytecode, no deployed state. **A clean report is not an audit.** Recall is measured
on a seed set we wrote: it is a floor, not a benchmark.

---

### 5 — IBM Bob + close

- Bob IDE used for: `/init` + `AGENTS.md` · Agent-mode multi-file work · **parallel subagents**
  (EVM hunter / Solana hunter / report writer) · document understanding over `skills/` ·
  review + commit flow
- 6 captured task sessions in `bob_sessions/`, budgeted against ~40 Bobcoins
- Same agent split ships in the product: `solguardian/agents/`
- The report reproduces with **zero** Bobcoins left — that was the point

> `github.com/jamesparser/solguardian` · live report: `jamesparser.github.io/solguardian`
> **SolGuardian — Jason Parser Research · built with IBM Bob**

---

## Speaker notes for the 20-second Q&A answers

- *"Why not just use Slither?"* — Deterministic rule engines like Slither are the right baseline
  and we do not claim to replace them. SolGuardian's contribution is the **explainable layer**:
  versioned checklists that each finding cites, ranked severity×confidence, an instant PoC stub
  and patch sketch per finding, and one tool spanning EVM, HyperEVM and Anchor — built entirely
  inside Bob in a hackathon window.
- *"Where is the AI?"* — In the workflow that built it (Bob Agent mode, parallel subagents,
  document understanding, review/commit), which is exactly what this hackathon asks for. Keeping
  the model out of the scan path is a deliberate product decision: a security report must be
  reproducible and cheap enough to run on every commit.
- *"Isn't 17/17 suspicious?"* — Yes, and the README says so out loud: we planted those bugs and we
  wrote the seed file. It proves the rules fire where the class is present. It is a floor, not a
  benchmark, and every finding still carries a confidence score because we expect false positives
  on real code.
