# AGENTS.md — SolGuardian

Instructions for coding agents (IBM Bob IDE Agent mode, subagents, or any other) working on
this repository. Read this first.

## What this is

**SolGuardian** is an automated exploit hunter for smart-contract **source code**:

- **EVM / Solidity** — Ethereum, Arbitrum, Base, **HyperEVM (Hyperliquid)**
- **Solana / Anchor (Rust)**

Point it at a file or a directory; specialized detectors hunt real exploit classes and emit
ranked findings with a PoC stub and a patch sketch. Hackathon: IBM Bob 2.0 (lablab.ai × IBM),
team **Jason Parser Research**.

## Non-negotiable rules

1. **Bob IDE is a core component.** Develop and demo the tool inside IBM Bob IDE
   (Agent mode, parallel subagents, document understanding, review/commit flow). The *product*
   is not a Bob plugin — it is a real tool built with Bob.
2. **Detectors are deterministic code.** No ML, no model calls inside the scan path. A full
   report must reproduce with zero Bobcoins remaining.
3. **Offline only.** No RPC endpoints, no explorers, no paid APIs, no network calls at all in
   the analyzer. Stdlib Python.
4. **Synthetic data only.** Sample contracts are our own teaching code with deliberately seeded
   bugs. Never add client data, company-confidential code, personal info, real audited
   vulnerabilities, or social scrapes. Every source belongs in `DATA_SOURCES.md`.
5. **Never commit secrets.** No API keys, mnemonics, keypairs, RPC URLs. `.gitignore` and
   `.bobignore` both exclude them; check the diff before committing.
6. **Original work.** Do not reuse or rebrand any other hackathon project (especially
   agent-to-agent messaging hubs).
7. **Honesty about limits.** If a rule is a heuristic, say so in the README and in the finding
   (`confidence`). A false positive labelled 0.9 is worse than no finding.

## Layout

```
solguardian/
  core/        source model, parsers (solidity.py, rust.py), finding model, skills loader,
               scanner, scorecard, text utilities (comment/string masking)
  detectors/   one module per exploit class; registered via @register
  report/      report.json / report.md / report.html + PoC stub templates
  agents/      EvmHunter, SolanaHunter, ReportWriter + the parallel orchestrator
skills/        one SKILL.md per exploit class - the verified checklists
samples/       synthetic seeded targets + EXPECT_FINDINGS.json (ground truth)
tests/         stdlib unittest suite: contract, ground truth, CLI, performance
bob_sessions/  required: PNG task summaries + the exact prompts to reproduce them
demo/          committed report for GitHub Pages
```

## The finding contract (every detector must satisfy it)

`id`, `severity` (critical/high/medium/low/info), `confidence` (0–1), title, 2–5 sentence
plain-English description, `file:line` + function, evidence line, exploit sketch (educational),
**PoC stub** (Foundry `*.t.sol` or Anchor `*.rs` skeleton), patch sketch (1–6 lines), skill pack
reference, CWE. Build findings with `self.make(...)` in `core/detector.py` — it fills the
contract in one place, so no detector can forget a field.

Grading and ranking rules are authoritative in `skills/severity-grading/SKILL.md`.

## Coding conventions that matter here

- **Match against `SourceIndex.masked`, never raw text.** Comments and string literals are
  blanked to spaces at equal length, so prose can't create findings and line numbers stay
  exact.
- Use the shared helpers in `core/evmutil.py` and `core/rsutil.py` rather than new ad-hoc
  regexes, so packs agree with each other.
- **One root cause, one finding.** If `evm_access` and `evm_delegatecall` both fit, the more
  specific pack owns it (see the skip conditions in `evm_access.py`).
- A detector raising must never abort the run: `agents/base.py` catches and logs.
- Python 3.8+ compatible, standard library only. No build step, no Docker.

## Commands

```bash
python3 -m solguardian analyze samples/solidity/Vault.sol      # single file
python3 -m solguardian analyze samples/solana/vault            # directory
python3 -m solguardian analyze samples --out out/samples --html
python3 -m solguardian demo                                    # one-command demo
python3 -m solguardian list                                    # detectors + skill packs
python3 -m solguardian analyze samples --fail-on critical; echo $?   # CI gate -> 1

python3 -m unittest discover -s tests -v                       # full suite
pip install -e .                                               # gives you `solguardian`
```

## Adding a detector

1. Write `skills/<slug>/SKILL.md` first: when to use, checklist (each line testable), severity
   guidance, false positives, required output fields.
2. Add `solguardian/detectors/<name>.py`, subclass `Detector`, set `id`, `label`, `language`,
   `skill`, `cwe`, decorate with `@register`, import it in `detectors/__init__.py`.
3. Seed a matching bug in `samples/` and add its key to `samples/EXPECTED_FINDINGS.json`.
4. Add a negative case to `TestGroundTruth.test_negative_cases_not_flagged`.
5. Run the suite; a new detector that lowers recall or trips a negative case is not done.

## Before any commit

```bash
python3 -m unittest discover -s tests        # green
python3 -m solguardian analyze samples --quiet
git diff --cached | grep -inE "key|secret|token|mnemonic|rpc|\.solana" # must be empty
```

Do not push to `main` without the tests passing; do not edit `bob_sessions/*.png` (evidence).
