# `bob_sessions/` - proof that SolGuardian was built in IBM Bob IDE

This folder is a **required deliverable** of the IBM Bob 2.0 Hackathon: PNG screenshots of
Bob task-session consumption summaries, one per workstream.

## Screenshot procedure (repeat for every task)

1. IBM Bob IDE → make sure the instance is the hackathon one:
   **Settings → General → instance `ibm-coding-challenge-uat`, region `us-east`**.
2. Open the chat sidebar → **Tasks**.
3. Open the finished task.
4. Click the **task header** → the **session consumption summary** panel opens
   (tokens / Bobcoins / subagents / duration).
5. Screenshot that panel and save it into this folder with the exact name below.
6. Commit immediately - capture as you complete each workstream, never at the end.

## Task prompts

The verbatim prompts to paste into Bob are in [`bob_tasks/`](bob_tasks/), one file per
workstream. Each also lists what to verify before screenshotting, so the evidence and the
work always arrive together.

| screenshot | Bob task prompt | what it must show |
| --- | --- | --- |
| `solguardian_task01_agents_md_init_summary.png` | `bob_tasks/task01_init_agents_md.md` | `/init` → `AGENTS.md`, repo orientation |
| `solguardian_task02_evm_detectors_summary.png` | `bob_tasks/task02_evm_detectors.md` | Agent mode writing the 7 EVM detectors, tests green |
| `solguardian_task03_solana_detectors_summary.png` | `bob_tasks/task03_solana_detectors.md` | parallel subagents on the 6 Solana detectors |
| `solguardian_task04_skills_pack_summary.png` | `bob_tasks/task04_skills_pack.md` | document understanding over `skills/` + samples |
| `solguardian_task05_report_cli_summary.png` | `bob_tasks/task05_report_cli.md` | report writers, PoC templates, CLI |
| `solguardian_task06_end_to_end_demo_summary.png` | `bob_tasks/task06_end_to_end_demo.md` | full `solguardian analyze samples` run + code review |

Optional (if Bobcoins remain): `solguardian_task07_code_review_summary.png` from
`bob_tasks/task07_code_review.md` - a Bob review pass over the diff, which is the
"developer-workflow improvement" angle the judges score.

## Bobcoin budget (≈40, no top-up)

| workstream | planned |
| --- | ---: |
| task01 init + AGENTS.md | 4 |
| task02 EVM detectors | 10 |
| task03 Solana detectors | 8 |
| task04 skills pack | 6 |
| task05 report + CLI | 6 |
| task06 end-to-end demo | 4 |
| reserve | 2 |

Detectors are **real deterministic code**, so a full report still reproduces with zero
Bobcoins left - which is exactly what `bob_tasks/task06_end_to_end_demo.md` demonstrates on
camera.

## Data rules

Screenshots must not contain API keys, mnemonics, RPC credentials or personal data. Crop or
redact before committing. See `../DATA_SOURCES.md`.
