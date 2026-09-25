# BUILD.md — how to run SolGuardian, and how Bob built it

Two halves: **(A)** the portable CLI, which needs nothing but Python; **(B)** how IBM Bob IDE
was used to build and demonstrate it, which is the eligibility requirement.

---

## A. Running the CLI

Requirements: **Python 3.8+**, standard library only. No network, no RPC, no API keys, no
Docker, no compile step.

```bash
git clone https://github.com/jamesparser/solguardian.git
cd solguardian

# option 1: run from the checkout, no install
python3 -m solguardian analyze samples

# option 2: install the console script
pip install -e .
solguardian analyze samples/solidity/Vault.sol
```

### Commands

| command | what it does |
| --- | --- |
| `solguardian analyze <path>` | scan a `.sol`/`.rs` file or a project directory |
| `--out <dir>` | output directory (default `out/<target>`) |
| `--html` | also write a self-contained `report.html` |
| `--serial` | run the detectors through the serial path instead of the agent pipeline |
| `--workers N` | how many agent instances to fan the files out over (default: auto) |
| `--backend auto/threads/processes` | how shards run concurrently (see below) |
| `--quiet` | no console table |
| `--expect <file>` | ground-truth file for recall/precision |
| `--no-expect` | disable ground-truth scoring |
| `--fail-on <severity>` | exit 1 if any finding is at/above that severity (CI gate) |
| `solguardian demo` | end-to-end run over the shipped samples |
| `solguardian list` | list every detector and skill pack |

### Outputs

```
out/samples/
  report.json      machine-readable: every field of the finding contract
  report.md        human/demo report: metrics, ranked table, per-finding detail
  report.html      single file, zero external requests (github pages / video)
  pocs/*.t.sol     Foundry test skeletons for EVM/HyperEVM findings
  pocs/*.rs        Anchor/Rust test skeletons for Solana findings
```

### Using it as a CI gate

```yaml
# .github/workflows/solguardian.yml
- run: pip install -e .
- run: solguardian analyze src/ --fail-on high --quiet
```

Exit code 1 means "a finding at or above that severity exists", so it fails the build. Sample
workflow shipped at `.github/workflows/solguardian.yml`.

---

### The multi-agent pipeline

`solguardian/agents/` is a real orchestrator, not a metaphor:

- `evm-hunter` and `solana-hunter` are fanned out **one worker per file shard**. Shards are built
  by largest-first bin packing over line counts, so a 40-contract repo runs 40-way concurrently
  instead of "two agents forever".
- `adjudicator` cross-checks the merged set and records, per finding, which *other* detectors
  independently flagged the same code. Annotation-only: it cannot change a severity or a
  confidence, and `test_adjudicator_cannot_promote_its_own_guesses` enforces that.
- `report-writer` gates the output contract and refuses incomplete findings.

`threads` is the default and always safe. `processes` removes the GIL ceiling and auto-applies
only to large corpora reached through the guarded CLI entry point — on macOS/Windows `spawn`
re-imports the caller's `__main__` in every child, so an unguarded script would recursively spawn
processes (that happened during development, which is why library callers must ask for it).

Measured, median of 5 runs on a 24-contract / 3,216-line corpus (Python 3.9.6, 8 cores): serial
**5.1 s**, threads **4.5 s**, processes **2.0 s**, all returning byte-identical findings. The
unflattering half is reported deliberately: threads barely beat serial because scanning is
CPU-bound regex work under the GIL, so processes are the only real speedup.

```bash
python3 tools/scale_check.py --files 24 --repeats 5   # proves equality of output, not just speed
python3 -m solguardian analyze ./contracts --workers 8 --backend processes
python3 tools/recall_gate.py                          # CI: recall + precision + perf budget
python3 tools/secret_scan.py                          # credential-shape sweep
```

## B. How IBM Bob IDE was used

Bob is the development environment for this project, not an optional extra. The workstream
split, the exact prompts, the planned Bobcoin budget and the screenshot procedure are all in
[`bob_sessions/`](bob_sessions/) (start with `bob_sessions/README.md`).

| Bob task | workstream | deliverable |
| --- | --- | --- |
| 01 | `/init` → `AGENTS.md` | repo contract for agents |
| 02 | EVM detectors | 7 detectors against `samples/solidity` |
| 03 | Solana detectors (**parallel subagents**) | 6 detectors against `samples/solana` |
| 04 | Skills pack | `skills/*/SKILL.md` made machine-readable |
| 05 | Report layer + CLI | `report.json/md/html`, PoC templates, `--fail-on` |
| 06 | End-to-end run + review/commit | `demo/` outputs, diff review |
| 07 | (optional) code review pass | Bob reviewing its own diff |

What Bob must be seen doing on camera: **Agent mode**, **parallel subagents**, **document
understanding** (over `skills/` and `samples/`), and the **code review / commit** flow.

### Account / instance (do this before heavy use)

1. Finish IBMid login (the email verification code is required to complete signup).
2. When the hackathon invite arrives ("added to `ibm-hackathon-xxxx`"): Bob IDE →
   **Settings → General → instance `ibm-coding-challenge-uat`, region `us-east`**.
3. Never burn a personal Bob account on hackathon work.

### Bobcoin discipline (~40 total, no top-up)

Spend on orchestration, review and skills work — not on generating detector code over and
over. The deliberate design choice that makes this safe: **every detector is deterministic
Python**, so `solguardian analyze samples` produces the identical report with zero Bobcoins
left. If the budget runs out the day before the deadline, the demo still works.

### If you continue development inside Bob

Use the prompt in `bob_sessions/bob_tasks/task02_evm_detectors.md` as the template: name the
files, name the constraints (mask first, one root cause per finding, `self.make(...)`), and end
with the exact verification command. Bob's Agent mode lands far more reliably on a prompt that
finishes with "then run `python3 -m unittest discover -s tests -v`".
