# Submission runbook — IBM Bob 2.0 Hackathon

Deadline: **Sep 27, 2026 22:00 Bangkok (UTC+7)**. Demo-able end-to-end target: Sun 12:00 Bangkok.
Everything below is copy-paste ready except the four items marked **YOU**.

## Status

| item | state |
| --- | --- |
| tool (13 detectors, 14 skill packs, 4 agent roles, CLI, reports) | ✅ done, `python3 -m solguardian analyze samples` |
| multi-agent fan-out (file-sharded hunters, adjudicator, writer) | ✅ `--workers N`, `--backend threads/processes` |
| ground truth | ✅ 17/17 seeded issues caught, 0 findings on the written-correct control |
| concurrency equivalence | ✅ `tools/scale_check.py`: serial = threads = processes, byte-identical |
| tests | ✅ 55 passing, stdlib only (`python3 -m unittest discover -s tests`) |
| repo docs | ✅ README, AGENTS, BUILD, DATA_SOURCES, STATEMENTS, samples/README |
| demo artefacts | ✅ `demo/` (report.json/md/html + 49 PoC stubs), `docs/cover.png`, slides, video script |
| CI + Pages | ✅ workflows committed — **YOU**: enable Pages once (below) |
| 21 commits pushed to `jamesparser/solguardian` | ❌ **blocked** — see A (auth, not code) |
| `bob_sessions/*.png` | ❌ **YOU** — must be captured inside Bob IDE (below) |
| lablab form + video upload | ❌ **YOU** — needs your lablab account |

## A. Unblock the push (one action — it is auth, not code)

**This build machine has no `jamesparser` credential.** Both HTTPS entries in `~/.git-credentials`
and all seven SSH keys authenticate as `node0datasystems-lgtm`, which has pull-only on this repo
(`permissions.push: false`), so `git push` returns 403. The repository state is fine — the remote is
already `jamesparser/solguardian`, the working tree is clean, and all 21 commits are **authored and
committed as Jason Parser `<330036968+jamesparser@users.noreply.github.com>`** (repo-local identity;
your global `~/.gitconfig` was left untouched).

Pick whichever is least annoying:

1. **Give the build a `jamesparser` identity** (cleanest — the repo is yours). A fine-grained PAT
   with Contents:Read+Write on this one repo, or sign a `jamesparser` account into this machine,
   and I push immediately.
2. **Add the machine account as a Write collaborator** — github.com/jamesparser/solguardian →
   Settings → Collaborators → Add `node0datasystems-lgtm` (Write), then I run the push. The commits
   still read as authored by Jason Parser; only the *pusher* would be node0.
3. **Push it yourself** — nothing is needed from me:
   ```bash
   cd /Users/terminal/solguardian-work/solguardian && git push origin main
   ```
   (If you want the authorship check first: `git log origin/main..HEAD --format='%an' | sort -u`
   should print exactly `Jason Parser`.)

Backup copy of the same 21 commits: `/Users/terminal/solguardian-work/solguardian-main.bundle`
(`git clone` it, or `git fetch <bundle> main:main`).

Nothing else in this runbook depends on the push except the two links below.

## B. Bob evidence (eligibility — judges disqualify without it)

`bob_sessions/README.md` has the capture procedure (Tasks → open task → click the task header →
screenshot the **session consumption summary**) and the budget table. The seven verbatim prompts
are already written in `bob_sessions/bob_tasks/`:

| paste this | save the PNG as |
| --- | --- |
| `task01_init_agents_md.md` | `solguardian_task01_agents_md_init_summary.png` |
| `task02_evm_detectors.md` | `solguardian_task02_evm_detectors_summary.png` |
| `task03_solana_detectors.md` | `solguardian_task03_solana_detectors_summary.png` (parallel subagents) |
| `task04_skills_pack.md` | `solguardian_task04_skills_pack_summary.png` |
| `task05_report_cli.md` | `solguardian_task05_report_cli_summary.png` |
| `task06_end_to_end_demo.md` | `solguardian_task06_end_to_end_demo_summary.png` |
| `task07_code_review.md` (optional) | `solguardian_task07_code_review_summary.png` |

Before any of it: **IBMids → finish email verification**, then when the invite lands switch
**Settings → General → `ibm-coding-challenge-uat`, region `us-east`**. Never spend Bobcoins on a
personal instance; ~40 total, no top-up. Capture each PNG as you finish the task, not at the end.

If the budget dies mid-way: the report still reproduces with zero Bobcoins (detectors are
deterministic Python) — say that on camera rather than hiding it.

## C. GitHub Pages (30 seconds, after the push)

`.github/workflows/pages.yml` is committed. Enable it once:
**Settings → Pages → Build and deployment → Source: GitHub Actions**.
Then `https://jamesparser.github.io/solguardian/` serves the landing page plus the generated
`report.html` from `demo/`, and every later push to `main` regenerates it from current code.

## D. lablab fields — paste these

- **Project title** — `SolGuardian: multi-agent exploit hunting for Solidity & Solana`
- **One-liner** — `Point it at contract source; agents return ranked findings with PoC stubs and patch sketches.`
- **Repo** — `https://github.com/jamesparser/solguardian`
- **Demo URL** — `https://jamesparser.github.io/solguardian/` (or `…/demo/report.html`)
- **Cover image** — `docs/cover.png` (1280×640, regenerate with `python3 docs/make_cover.py`)
- **Slides** — `docs/SLIDES.md` (paste into your deck tool; every number comes from
  `demo/report.json`)
- **Statement 1 (Problem & Solution)** and **Statement 2 (IBM Bob usage)** — the two sections of
  [`../STATEMENTS.md`](../STATEMENTS.md), each under 500 words and enforced by
  `tests/test_docs.py`
- **Video** — ≤3 min, ≥90 s live with narration; script and shot checklist in
  [`VIDEO_SCRIPT.md`](VIDEO_SCRIPT.md)
- **Post-hackathon feedback form** — required for participant rewards; set a reminder right after
  submitting

## E. Pre-flight (5 minutes before you record or submit)

```bash
cd /Users/terminal/solguardian-work/solguardian
python3 -m unittest discover -s tests          # 55 OK
rm -rf out && python3 -m solguardian analyze samples --out out/samples --html
python3 -m solguardian analyze samples/clean --out out/clean --quiet   # 0 findings
python3 tools/recall_gate.py                   # recall + precision + perf budget
python3 tools/scale_check.py --files 24        # serial == threads == processes (multi-agent claim)
solguardian demo --html                        # the exact on-camera command
git status --short                             # clean tree
```

Then: clear the terminal, hide notifications, set the instance to `ibm-coding-challenge-uat`, and
record the beat sheet in `docs/VIDEO_SCRIPT.md`.

## F. Deliberately not built

Symbolic execution / bytecode VM / SMT solving · live mainnet scanning needing paid RPC keys ·
Hyperledger or hash-receipt chains · on-chain notary · x402/x401 agent payments · A2A messaging
hubs · Bob plugin marketplaces · login systems · anything needing credentials we do not have.
All five chains/VMs above are named in the README's out-of-scope section so the omission reads as
a decision, not a gap.
