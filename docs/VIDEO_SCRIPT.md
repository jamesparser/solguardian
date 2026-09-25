# Demo video script — 3:00 max, ≥90s live

Hackathon rules: **≤3 minutes**, **≥90 seconds of live demo with narration**, and Bob must be
visibly in use (show the Bob UI, not only a terminal). Narration is required.

Read-aloud pace ≈150 wpm. Word counts per segment are budgeted so the narration fits the window
with room to breathe.

## Run sheet (timed)

| time | section | what is on screen | narration (say this) |
| --- | --- | --- | --- |
| 0:00–0:25 | **Pain** | slide 1 (title) | "Smart contract audits take days and cost five figures, and the same handful of exploit classes still get missed — because every new codebase makes a human re-derive them by eye, in three different ecosystems. Meanwhile attackers automate, and scan a fresh deployment in minutes." |
| 0:25–0:55 | **What it is** | slide 2 (one-line pitch + report screenshot) | "SolGuardian is an exploit hunter you point at source code. Give it a Solidity file, an Anchor program, or a whole directory. Specialised agents cover EVM, HyperEVM and Solana in parallel, and every finding ships with a severity, a confidence score, a plain-English reason, the exact line, an educational exploit sketch, a proof-of-concept stub, and a patch sketch." |
| 0:55–2:25 | **LIVE in IBM Bob** (90s, the core) | Bob IDE: repo open → chat/Agent mode → run → report | beat 1 opens with "Everything here was built inside IBM Bob two point zero. This is the repo as Bob has it open." — then the rest of the live beat sheet below |
| 2:25–2:45 | **Metrics + evidence** | `out/samples/report.md` metrics table, then `bob_sessions/` folder with PNGs | "On our seeded sample set: seventeen planted issues across three chains, seventeen caught, in under a second, with a proof-of-concept stub for each — and the correctly-written twin of those contracts gets zero findings. And these are the Bob task summaries from the build — deterministic code, so the report still reproduces with zero AI budget left." |
| 2:45–3:00 | **Close** | slide 5 (repo URL, team) | "SolGuardian. Built with IBM Bob. Jason Parser Research. Repo link and live demo report are in the description." |

Totals: 3:00 exactly, of which **LIVE = 1:30 (90 s)** inside IBM Bob — meeting the ≥90 s live
requirement without relying on how a judge counts the boundary.

## Live beat sheet (0:55 → 2:25)

Rehearse this path until it is muscle memory. Every step is ≤15 seconds.

1. **0:55–1:05** — In Bob IDE, show `samples/solidity/Vault.sol`. Scroll to `withdraw()`.
   *"Everything here was built inside IBM Bob two point zero — this is the repo as Bob has it open."*
   *"Here is a vault with a deliberately planted bug — can you see it? The balance is subtracted after the ETH is sent."*
2. **1:05–1:20** — Bob chat, Agent mode. Paste the prompt from
   [`bob_sessions/bob_tasks/task06_end_to_end_demo.md`](../bob_sessions/bob_tasks/task06_end_to_end_demo.md):
   *"Run SolGuardian on samples/solidity/Vault.sol and explain the top three findings in plain English, citing the skill checklist each one satisfied."*
   Let Bob's plan/agent panel be visible while it works.
3. **1:20–1:35** — Bob runs the CLI in its terminal. The ranked table appears. Point at row one.
   *"Reentrancy, critical, confidence zero point nine — and note it names the line and the state it writes late."*
4. **1:35–1:50** — Open `out/vault/report.md` next to the source. Show one finding's section:
   description, exploit sketch, patch sketch, PoC path, skill checklist.
   *"This part is the point: the finding quotes the human-written checklist it enforced, so you can argue with the rule instead of guessing why a model said no."*
5. **1:50–2:05** — Show the **parallel subagents**: run `solguardian analyze samples --out out/samples --html`
   and point at the `[evm-hunter]` / `[solana-hunter]` interleaved log lines, then the Agent pipeline
   table in `report.md`.
   *"Two hunters ran concurrently: seven detectors on the EVM side, six on the Solana side."*
6. **2:05–2:15** — Open `out/samples/report.html` (single file, no network). Scroll the KPI row.
   *"This page is self-contained — it is also what is hosted from the repo."*
7. **2:15–2:25** — Show a PoC stub file, then the CI gate:
   `solguardian analyze samples --fail-on critical; echo $?` → `1`.
   *"Every finding gets a test skeleton, and the exit code turns this into a CI gate."*

## Shot checklist (tick before recording)

- [ ] Bob IDE is the front window for the middle two minutes; the instance shows
      `ibm-coding-challenge-uat` (region `us-east`) in Settings → General.
- [ ] Bob's chat panel, the Agent/subagent panel and the terminal are all visible at some point.
- [ ] Editor font ≥16px; zoom the OS to 125–150% so the report text is legible after compression.
- [ ] Terminal cleared (`clear`), no private tabs, notifications silenced, dark theme.
- [ ] Nothing sensitive on screen: no RPC URLs, no keys, no wallet, no email, no personal files.
- [ ] `out/` deleted before recording so timings are honest (first run, cold).
- [ ] Narration recorded separately and overlaid — easier to re-take than screen+mic at once.
- [ ] Length ≤3:00 after export; play it back at 1× once before uploading.
- [ ] Subtitles/captions added if lablab supports them.

## Recording & upload

```bash
# macOS, screen + audio
# QuickTime → New Screen Recording → Options → Microphone On. Or:
mkdir -p out && ffmpeg -f avfoundation -list_devices true -i ""   # find your screen/index
# export as 1080p H.264 MP4, then trim to <=3:00
```

Upload to YouTube (unlisted) or Vimeo, paste the link into the lablab submission field, and keep
the file in a local `video/` folder — do **not** commit MP4s to the repo (`.gitignore` excludes
them; `.bobignore` keeps them out of Bob's context).

## If a live step fails while recording

Do not restart from zero. Jump to the pre-baked fallback: `demo/report.md` and
`demo/report.html` are committed outputs of the exact same command, and
`python3 -m unittest discover -s tests -v` proves the pipeline end to end without Bob. Cut back
to the fallback, then re-record only the beat that broke.
