# Bob task 04 - Skills pack ("the ClawHub idea")

**Screenshot to save:** `bob_sessions/solguardian_task04_skills_pack_summary.png`
**Planned cost:** ~6 Bobcoins
**Bob features to show:** document understanding over markdown, then wiring it into code

```
Read every file under skills/ as a set, then make the pack machine-usable:

1. Each SKILL.md must have YAML frontmatter (id, applies_to, severities, cwe, detector) and
   exactly these sections: When to use, Checklist, Severity guidance, False positives,
   Required output fields.
2. Tighten the language so each checklist line is a single testable assertion - a detector
   quotes these strings verbatim in the report.
3. Add skills/hyperliquid-hyperevm-notes/SKILL.md if missing: HyperEVM is EVM bytecode with
   different trust assumptions (bridge-minted value, HyperCore spot reads, finality and fee
   model differences). Explicitly forbid applying Solana runtime rules (PDAs, CPI, lamports)
   to HyperCore-facing Rust.
4. Cross-link: solguardian/core/skills.py parses these files. Confirm every detector's
   `skill` attribute resolves to a real directory, and that skills items quoted in
   out/samples/report.md actually exist in the markdown.
5. Verify with: python3 -m unittest tests.test_solguardian.TestRegistry -v
```

Before screenshotting: open one SKILL.md in the editor next to a report section quoting it.
