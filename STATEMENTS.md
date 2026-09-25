# STATEMENTS.md — lablab submission text

Two required written statements, each under 500 words. Paste the body of each section into the
matching lablab field. (Word counts are checked by `tests/test_docs.py`.)

---

## 1. Problem & Solution

**Problem.** Smart-contract audits are the bottleneck between shipping and being solvent. A
human review of a mid-size vault takes days, costs five figures, and still misses things — not
because auditors are careless, but because the same handful of exploit classes (reentrancy,
missing access control, unvalidated Solana accounts, manipulable price reads, replayable
signatures) have to be re-derived by eye in every new codebase, across three ecosystems that
each speak a different language about the same mistake. Meanwhile the attacker's side is
automated: a newly deployed contract is probed within minutes.

Small teams get it worst. They cannot afford an audit before launch, so they launch un-audited,
or they run a linter that prints four hundred style warnings and no idea which of them can
actually lose money.

**Solution.** SolGuardian is an exploit hunter you point at source code. Give it a Solidity file,
an Anchor program, or a whole directory; specialised agents cover EVM/HyperEVM and Solana in
parallel and return a ranked report. Every finding ships with the five things a reviewer needs
to act in under a minute:

- a severity and an explicit confidence score, so a heuristic never masquerades as a verdict;
- a two-to-five-sentence plain-English explanation of *why* it is exploitable here;
- the exact `file:line` and function, with the triggering source quoted;
- an educational exploit sketch and a **PoC stub** (a Foundry or Anchor test skeleton);
- a patch sketch, plus a citation of the checklist that justified the call.

Those checklists live in `skills/` — twelve versioned, human-written packs (reentrancy,
access-control, oracle-price, Solana account validation, CPI safety, HyperEVM notes, severity
grading). They are what make the system explainable, teachable and extensible: adding a detector
means writing its skill first.

The design constraint we held to: **deterministic code, not a model guessing.** Detectors are
AST-lite parsers plus pattern rules that only ever match against comment- and string-masked
source. The report reproduces byte-for-byte with zero tokens spent, runs fully offline with no
RPC keys, and works in CI as a gate (`--fail-on high`).

**Proof.** On our own synthetic seed set (`samples/EXPECTED_FINDINGS.json`, 17 deliberately
planted issues across Solidity, HyperEVM-style Solidity and Anchor), SolGuardian catches 17/17
with no regressions, in 0.9 seconds over 935 lines, emitting 49 findings with a PoC stub for
each. The other half of the number is precision: `samples/clean/` holds a Solidity vault and an
Anchor program of the same shapes written *correctly*, and SolGuardian reports zero findings
there — a claim the test suite enforces, alongside the specific false positives we removed (a
caller-scoped `withdraw()` is not an access-control bug; a `token_program` slot needs no
signature).

Out of scope by choice: symbolic execution, SMT solvers, live mainnet scanning, and anything
needing credentials we do not have.

*(≈470 words)*

---

## 2. IBM Bob usage

**Bob is the workshop, not a badge on the finished product.** SolGuardian was designed, written,
tested and demoed inside IBM Bob 2.0 IDE, and the repository is organised so a judge can verify
that claim rather than take it on trust.

**Agent mode for the structural work.** The AST-lite parsers (`solguardian/core/solidity.py`,
`rust.py`), the text-masking layer that stops comments from ever producing a finding, the
finding contract in `core/detector.py`, and the three report emitters were built through Bob's
Agent mode across multi-file edit sessions. Each session landed with a verification command in
the prompt — `python3 -m unittest discover -s tests -v` — because an agent that cannot check its
own work is a liability in a security tool.

**Parallel subagents for the two ecosystems.** `bob_sessions/bob_tasks/task03_solana_detectors.md`
is the exact prompt that spawned three concurrent subagents over six Solana detectors, sharing a
brief (match masked text only; never demand `Signer<'info>` from a program slot; cite the skill
pack). The same split survives in the shipped product: `solguardian/agents/` contains
`EvmHunter`, `SolanaHunter` and `ReportWriter`, and the orchestrator runs them concurrently in a
thread pool, so `solguardian analyze samples` demonstrates the agent pipeline on camera instead
of describing it. `ReportWriter` is also a real quality gate: it rejects any finding missing an
exploit sketch, PoC stub or skill citation.

**Document understanding as the knowledge layer.** `skills/*/SKILL.md` are prose checklists with
YAML frontmatter. Bob read the pack as a set, normalised every file to the same five sections,
and wired the loader in `core/skills.py` so `solguardian list` prints detectors and packs side by
side. The result: each finding quotes the checklist items it satisfied, which is what turns a
regex hit into a defensible review item.

**Review and commit flow.** Detector work landed as small commits per workstream, with Bob's diff
review used to catch anything that must not be committed — secrets, RPC URLs, real protocol
names. `.gitignore` and `.bobignore` both exclude credentials, and `.bobignore` additionally
keeps binary bulk out of the model's context.

**Bobcoin discipline (~40, no top-up).** Planned spend is in `bob_sessions/README.md`
(4/10/8/6/6/4, 2 reserved). The architectural consequence is the part worth stating: because
detectors are deterministic Python, the full 17/17 report reproduces with **zero** Bobcoins left.
A judge who clones the repo gets the same output on their own machine, offline, for free.

The concurrency is measured, including where it disappoints: on a 24-contract corpus (median of
five runs) one agent took 5.1 s, threaded shards 4.5 s, process shards 2.0 s — threads barely beat
serial under the GIL, so only processes earn their keep. All three return byte-identical findings,
because ranking uses a total order rather than arrival order, asserted in CI. Sharding per file is
what carries the claim past this demo: a 40-contract monorepo gets forty hunters, not a fixed pair.

*(≈500 words)*
