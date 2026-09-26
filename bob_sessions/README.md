# Bob session evidence (IBM Bob 2.0 hackathon)

Captured on **ibm-hackathon-lablab** (enterprise, us-east API `api.us-east.bob.ibm.com`), account `node0datasystems@gmail.com`.

## Eligibility PNGs (session consumption summaries)

| File | Status | Evidence |
|------|--------|----------|
| `solguardian_task01_agents_md_init_summary.png` | **GOOD** | Task `/init`, Context 68.2k/270k (25%), Task Id `fd3873f5…`, Bobcoins 1.97 |
| `solguardian_task02_evm_detectors_summary.png` | **GOOD** | Task EVM detectors **completed 6/6**, Context 82.2k/270k (30%), Task Id `19eff27d…`, Bobcoins 2.14 |
| `solguardian_task03_solana_detectors_summary.png` | incomplete | mid-run only; no clean Task Id block |
| `solguardian_task04_skills_pack_summary.png` | not clean | captured the wrong task thread |
| `solguardian_task05_report_cli_summary.png` | incomplete | shows task02 numbers |
| `solguardian_task06_end_to_end_demo_summary.png` | not clean | captured the wrong task thread |

Do **not** treat the incomplete/wrong files as clean session summaries.

## Supporting evidence
- `evidence_01_settings_account_budget_40coins.png` — Bobcoins 40.00 at start
- `evidence_02_bob_settings_window.png` — Settings window
- `evidence_03_init_task_running.png` — `/init` running
- `evidence_04_init_approvals.png` — tool approvals
- `evidence_05_init_workstream.png` — workstream
- `solguardian_task02_evm_detectors_summary_full.png` — full UI around the good summary

## Live demo video
See the repo release / submission: `solguardian-demo.mp4` (~2:37, ≥90s live IBM Bob UI + `python3 -m solguardian analyze`).
