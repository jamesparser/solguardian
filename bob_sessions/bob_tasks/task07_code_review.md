# Bob task 07 (optional) — code review pass

**Screenshot to save:** `bob_sessions/solguardian_task07_code_review_summary.png`
**Only run this if Bobcoins remain after tasks 01–06** (budget shows 2 in reserve).
**Bob features to show:** the review UI on a real diff, then the commit flow.

```
Review the working diff of this repo as a security-tooling code reviewer would.

For each issue you find, say which file and line, why it matters for a static analyser,
and whether the fix is a rule change or a test change. Focus on:

1. rules that could produce a false positive on correct code - check them against
   samples/clean/ (that directory must produce zero critical/high findings)
2. rules that match raw text instead of index.masked (comments/strings must never create
   a finding)
3. detectors that grade severity without a reachability argument in the description
4. any place a finding could be emitted without an exploit sketch, patch sketch, PoC stub
   or skill citation
5. anything that would leak a credential into a committed artefact

Do not "fix" the synthetic samples - they are intentionally vulnerable. Propose commits,
then make the smallest change that satisfies each real finding, and finish with
`python3 -m unittest discover -s tests -v`.
```

## Why this is worth a screenshot

The hackathon is scored as a **developer-workflow improvement** (testing / code review) with Bob
core. A review pass where Bob critiques its own generated code — and the test suite then proves
the precision guard still holds — is the single clearest frame for that criterion.

If Bobcoins are gone, skip it: `docs/VIDEO_SCRIPT.md` step 7 (the `--fail-on critical` gate) and
the green test run cover the workflow story without spending anything.
