# Bob task 05 - Report layer + CLI

**Screenshot to save:** `bob_sessions/solguardian_task05_report_cli_summary.png`
**Planned cost:** ~6 Bobcoins
**Bob features to show:** Agent mode multi-file edit, template understanding

```
Implement the deliverable layer, keeping core portable (no Bob-only assumptions):

- solguardian/report/json_report.py   machine-readable report.json
- solguardian/report/md_report.md     demo-facing report.md: metrics, ranked table, then one
                                      section per finding (description, evidence, exploit
                                      sketch, patch sketch, PoC path, skill checklist)
- solguardian/report/html_report.py   single-file report.html, zero external requests
- solguardian/report/pocs.py          renders report/templates/*.t.sol and anchor_stub.rs,
                                      one stub per finding, and writes them under pocs/
- solguardian/cli.py                  `analyze <path> [--out] [--html] [--serial] [--quiet]
                                      [--expect FILE] [--fail-on <severity>]`, `list`, `demo`

Constraints:
- PoC ids in stub headers must be the final ranked ids, so regenerate stubs in
  core/scanner.finalize() after ranking - not inside the detector
- --fail-on gives a real CI gate: exit 1 when a finding at/above that severity exists
- ground truth auto-discovery: if the target is samples/ or below, load
  samples/EXPECTED_FINDINGS.json and print recall plus any missed seeded key
- keep python3.8+ compatible, stdlib only

Then run the gate to prove it trips:
  python3 -m solguardian analyze samples --fail-on critical ; echo "exit=$?"
```

Before screenshotting: show the terminal with the ranked table and `exit=1`.
