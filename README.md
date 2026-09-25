# SolGuardian

**Automated exploit hunting for Solidity & Solana — built with IBM Bob 2.0.**
IBM Bob 2.0 Hackathon · [Jason Parser Research](https://lablab.ai/ai-hackathons/ibm-bob-2-hackathon/jason-parser-research)

> Point SolGuardian at contract source. Specialised agents hunt real exploit classes across
> **EVM/HyperEVM (Solidity)** and **Solana/Anchor (Rust)** and emit ranked findings — each with a
> plain-English reason, a minimal PoC stub and a patch sketch.

[![live demo report](https://img.shields.io/badge/demo-report.html-2ea44f)](https://jamesparser.github.io/solguardian/)
[![tests](https://img.shields.io/badge/tests-42%20passing-brightgreen)](tests/)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/dependencies-none%20(stdlib)-informational)](pyproject.toml)

---

## 60-second start

```bash
git clone https://github.com/jamesparser/solguardian.git
cd solguardian
python3 -m solguardian analyze samples        # needs only Python 3.8+; no network, no keys
```

Output on a synthetic, deliberately bug-seeded sample set:

```
SolGuardian 0.1.0 - 5 file(s), 935 lines, 13 detector(s) in 0.94s
findings: 49  (16 critical, 18 high, 12 medium, 3 low)
  ...
ground truth: caught 17/17 seeded issues (100% recall), 32 extra unseeded findings
wrote: out/samples/report.json, out/samples/report.md, 53 PoC stub(s)
```

`out/samples/report.md` is the deliverable. `--html` adds a self-contained page.

(0.9 s includes rendering 49 PoC stubs; the rule pass itself is ~0.2 s.)

## What a finding looks like

Every finding is one JSON object with the same contract, and the same fields in the markdown
report:

| field | example (`SG-EVM-CEI001-004`) |
| --- | --- |
| severity / confidence | `high` / `0.75` |
| location | `samples/solidity/Vault.sol:74 (withdraw)` |
| rule / detector / CWE | `CEI-001` / `evm_reentrancy` / `CWE-841` |
| description | *"withdraw() performs an external interaction (`msg.sender.call`) at line 74 and only updates contract state afterwards (`balanceOf[msg.sender]`, `totalDeposits`)…"* |
| evidence | the exact source line that triggered it |
| exploit sketch | 4 ordered, educational steps (no live weapon) |
| patch sketch | *"move `balanceOf[msg.sender] -= amount` above the call, or add `nonReentrant`"* |
| PoC stub | `pocs/sg-evm-cei001-004_...t.sol` — Foundry skeleton + `forge test` command |
| skill pack | `skills/reentrancy/SKILL.md` + the checklist items it satisfied |

The **skill pack citation is what makes it explainable**: the report quotes the human-written
checklist that the detector enforced, so a reviewer can disagree with the rule instead of the
mood of a model.

## Why it is built this way

- **Deterministic, not generative.** Detectors are AST-lite parsers plus pattern rules. No LLM
  sits in the scan path, so the same input always produces the same report — and the tool still
  works with zero AI budget left. (There is a test asserting byte-level reproducibility.)
- **Comments cannot create findings.** Every detector matches against a *masked* copy of the
  source where comments, strings and char literals are blanked to spaces at identical length, so
  line numbers stay exact. That single design choice removed more false positives than any rule
  tuning.
- **One root cause, one finding.** Packs hand off deliberately: a `delegatecall` bug belongs to
  the proxy pack, not to access control; `payable(x).transfer(v)` reverts by design, so it is not
  an "unchecked return value". Each of those exclusions has a regression test.
- **Portable CLI core.** `solguardian analyze <path> --fail-on high` is a real CI gate: exit 1 on
  a finding at or above a severity. Sample workflow in
  [`.github/workflows/solguardian.yml`](.github/workflows/solguardian.yml).
- **Offline by principle.** No RPC endpoints, no explorers, no paid APIs. Proof-of-storage,
  symbolic execution and SMT solving are out of scope by choice — see below.

## Coverage

13 detectors, each tied to a skill pack:

| chain | detector | rules |
| --- | --- | --- |
| EVM / HyperEVM | `evm_reentrancy` | state after external call, multi-call ordering |
| | `evm_access` | missing guard, `tx.origin` auth, writable critical params |
| | `evm_external_calls` | discarded call results, silenced `ok;`, 2300-gas stipend |
| | `evm_delegatecall` | caller-controlled target, unguarded logic pointer, layout notes |
| | `evm_oracle` | AMM spot price, unchecked rounds, single source, timestamp windows |
| | `evm_sig_replay` | unbound digest, no spend-once tracking, no deadline, malleability |
| | `evm_selfdestruct` | reachable destruct, arbitrary send destination, stranded funds |
| Solana / Anchor | `solana_signer` | missing `Signer`, permissionless mutation |
| | `solana_accounts` | `UncheckedAccount` type confusion, token-owner gaps, seeds/bump |
| | `solana_cpi` | unchecked CPI, spoofable program id, `remaining_accounts` |
| | `solana_math` | divide-before-multiply precision loss, overflow, divide-by-zero |
| | `solana_authority` | mint/freeze/upgrade authority footguns (static notes) |
| | `solana_deser` | raw casts over foreign account data, unchecked deserialization |

Hyperliquid gets a **notes pack**
([`skills/hyperliquid-hyperevm-notes/SKILL.md`](skills/hyperliquid-hyperevm-notes/SKILL.md)):
HyperEVM is treated as EVM bytecode with different trust assumptions — bridged canonical value,
HyperCore price reads as consensus inputs, distinct fee/finality model — not as a new chain
client. Findings against HyperEVM-shaped code are tagged `chain: "hyperevm"`.

## Multi-agent by construction

The pipeline is a set of named agents the orchestrator dispatches, not one big loop:

| agent | role |
| --- | --- |
| `evm-hunter#1..N` | Solidity/HyperEVM shards — 7 detectors each |
| `solana-hunter#1..N` | Anchor/Rust shards — 6 detectors each |
| `adjudicator` | cross-checks where independent detectors agree |
| `report-writer` | gates the output contract before anything is written |

Files are partitioned by source size (largest-first bin packing) so shards finish together; a
40-contract repo gets 40-way fan-out rather than a fixed pair of agents. `--workers N` controls
it, and `--backend processes` removes the GIL ceiling on large trees:

```bash
python3 tools/scale_check.py --files 24      # serial vs threads vs processes
```

Measured (%s).
Only processes genuinely beat serial — scanning is CPU-bound regex work, so threads pay GIL
contention and land within noise of serial. And all three return **byte-identical** findings,
because
ranking uses a total order rather than arrival order. That equivalence is asserted by
[`tests/test_multi_agent.py`](tests/test_multi_agent.py), so parallelism cannot quietly change a
report. Threads stay the default because on macOS/Windows `spawn` re-imports the caller's
`__main__` in every child — an unguarded script would recursively spawn processes — so `auto`
upgrades only for the guarded CLI entry point.

The adjudicator is deliberately weaker than it sounds: it **annotates** corroboration and cannot
raise a severity or a confidence. Agreement is a triage signal, not evidence, and
`test_adjudicator_cannot_promote_its_own_guesses` fails if that ever stops being true.

The same three-role split is what Bob's subagents do at build time
([`bob_sessions/bob_tasks/task03_solana_detectors.md`](bob_sessions/bob_tasks/task03_solana_detectors.md)
spawns three concurrent agents) — `solguardian/agents/` is that workflow, shipped as code.

## Ground truth, and how honest it is

`samples/EXPECTED_FINDINGS.json` lists **17 issues deliberately planted** in three synthetic
contracts (5 Solidity/EVM, 5 HyperEVM-shaped, 7 Anchor/Rust). The CLI scores itself against that
file automatically and prints recall plus any missed key.

- **caught 17/17** on the seed set, 0.9 s over 935 lines (5 files incl. the negative control),
  one PoC stub per finding.
- **32 additional findings** are reported as *unseeded*: real gaps in the same samples that we did
  not count in the denominator (e.g. unguarded `setPriceFeed`, `realloc::payer` economics).
- Recall is measured against a seed set **we wrote**, which is an easy target and we say so: it
  proves the rules fire where the bug class is present, not that SolGuardian finds every bug in
  someone else's protocol. Treat it as a floor, not a benchmark.

### The negative control

`samples/clean/` is the other half of the metric: a Solidity vault and an Anchor program with
the **same shapes** as the seeded samples (deposit / withdraw / rewards / SPL CPI / settle /
admin knob) but written with the validation actually present — checks-effects-interactions,
typed `Signer` and `Account` slots, seeds-derived PDAs, `checked_*` math, spend-tracked
signatures. SolGuardian reports **0 findings** on it, and
[`tests/test_false_positives.py`](tests/test_false_positives.py) fails the build if any change
makes it report a critical or high there. That guard is what caught five real false positives
during this build (private `ecrecover` helpers flagged as replay vectors, seeds-verified PDAs
flagged as missing signers, client-supplied-bump logic fired on derived bumps, admin-only
treasury sweeps flagged as drains, and a reverted-by-design `payable(x).transfer()` flagged as
an unchecked return). Precision claims without a negative control are just optimism.

### Known limitations (read before trusting a clean report)

- These are **heuristics**. Expect false positives on unusual-but-correct code and **false
  negatives on anything the patterns do not describe.** A clean SolGuardian report is not an audit
  and is not proof of safety.
- No symbolic execution, no SMT solving, no bytecode analysis, no reachability proof — so
  cross-function and cross-contract data flow is invisible to it.
- Inherited and constructor-executed bugs are missed. A proxy's implementation file is analysed
  without its storage layout.
- Only source is read: no deployed bytecode, storage, balances or transaction history, so
  "reachable in practice on this deployment" cannot be answered.
- Confidence is deliberately capped: nothing reaches 1.0. **Anything below 0.6 is a review
  prompt, not a verdict.** Grading rules:
  [`skills/severity-grading/SKILL.md`](skills/severity-grading/SKILL.md).

## Out of scope (by choice)

Full symbolic execution / custom bytecode VM / SMT solvers · live mainnet scanners requiring paid
keys · Hyperledger or hash-receipt chains · on-chain notary systems · agent payments (x402/x401)
and A2A messaging · Bob plugin marketplaces, UI polish wars, login systems · anything requiring
credentials we do not have.

## Repository map

```
solguardian/            the package: core (parsers, finding model, skills, scoring),
                        detectors/, report/, agents/ (EvmHunter, SolanaHunter, ReportWriter)
skills/                 14 SKILL.md packs - the verified checklists agents and rules enforce
samples/                synthetic seeded targets + EXPECTED_FINDINGS.json (ground truth)
tests/                  <!-- solguardian-tests: 78 -->78 tests: contract, ground-truth recall,
                        false positives, multi-agent, CLI, docs, secrets
demo/                   committed report for GitHub Pages
bob_sessions/           required Bob evidence: PNG task summaries + the exact prompts used
docs/                   submission runbook, video script, slide outline, cover generator
AGENTS.md               instructions for coding agents working on this repo
BUILD.md                how to run it, and how IBM Bob built it
STATEMENTS.md           the two <=500-word submission statements
DATA_SOURCES.md         provenance of every input (synthetic code + public docs only)
```

## Testing

```bash
python3 -m unittest discover -s tests -v        # stdlib only
python3 tests/run_tests.py                      # same, plus the demo metric
pip install -e . && pytest -q                   # if you prefer pytest
```

The suite asserts four things a security tool should never let regress: every finding satisfies
the output contract; all 16 seeds are caught; the specific false positives we removed stay
removed; and nothing secret is committed.

## Built with IBM Bob 2.0

Bob IDE is the development environment, not a badge on the side. Workstreams, verbatim prompts,
parallel-subagent briefs, the Bobcoin budget and the screenshot procedure are all in
[`bob_sessions/`](bob_sessions/) — start with
[`bob_sessions/README.md`](bob_sessions/README.md). The agent split survives in the shipped
product: `python3 -m solguardian analyze` runs `EvmHunter` and `SolanaHunter` concurrently, then
`ReportWriter` enforces the finding contract. Full narrative: [`BUILD.md`](BUILD.md).

## Data & licence

Synthetic teaching contracts and public documentation only — no client data, no personal
information, no real protocol code. Every input is itemised in [`DATA_SOURCES.md`](DATA_SOURCES.md).
MIT © Jason Parser Research.

Do not use this against systems you are not authorised to test. It reads source files and has no
network or transaction capability at all; the PoC files it emits are commented skeletons, not
exploits.
