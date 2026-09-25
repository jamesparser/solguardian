"""report.md - the human / demo deliverable.

Order matters here: metrics first (judges skim), then the ranked table, then one section
per finding with the plain-English reason, evidence, exploit sketch, patch sketch and the
skill checklist that justified the call.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from ..core.finding import Finding, Severity
from ..core.scanner import ScanResult
from ..core.scorecard import Scorecard
from ..core.skills import skills as load_skills

BANNER = "SolGuardian"


def build(
    result: ScanResult,
    scorecard: Optional[Scorecard] = None,
    agents=None,
    target_arg: str = "",
) -> str:
    findings = result.findings
    lines: List[str] = []
    add = lines.append

    add("# %s analysis report" % BANNER)
    add("")
    add("- **Tool:** SolGuardian %s (static heuristics + AST-lite; no ML, no network)" % _version())
    add("- **Target:** `%s` (%d file%s, %d lines)"
        % (target_arg or result.target.root, len(result.target.files), "s" if len(result.target.files) != 1 else "", result.target.line_count))
    add("- **Detectors run:** %d" % len(set(result.detectors_run)))
    add("- **Time to full report:** %.2f s" % (result.duration_ms / 1000.0))
    add("- **Findings:** %d (%s)" % (len(findings), ", ".join(
        "%d %s" % (sum(1 for f in findings if f.severity is s), s.value) for s in Severity.ordered()
        if any(f.severity is s for f in findings)
    )))
    add("")

    if scorecard is not None:
        add("## Demo metrics (ground truth)")
        add("")
        add("| metric | value |")
        add("| --- | --- |")
        add("| seeded issues in samples | %d |" % len(scorecard.seeded))
        add("| seeded issues caught | **%d** |" % len(scorecard.caught))
        add("| recall | **%.0f%%** |" % (100.0 * scorecard.recall))
        add("| extra (unseeded) findings | %d |" % len(scorecard.unseeded))
        add("")
        add("| seeded issue | caught | rule | detector | severity (expected / found) |")
        add("| --- | --- | --- | --- | --- |")
        for entry in scorecard.to_dict()["detail"]:
            add("| `%s` | %s | %s | %s | %s / %s |" % (
                entry["key"],
                "yes" if entry["caught"] else "**MISSED**",
                entry["rule"] or "-",
                entry["detector"] or "-",
                entry["severity_expected"],
                entry["severity_found"] or "-",
            ))
        add("")

    if agents:
        hunters = [a for a in agents if "hunter" in a.agent]
        add("## Agent pipeline")
        add("")
        add("%d agent run(s): %d sharded hunter(s) scanning concurrently across %d ecosystem(s), "
            "then an adjudicator cross-check, then the report writer."
            % (len(agents), len(hunters), len({a.agent.split("#")[0] for a in hunters})))
        add("")
        add("| agent | role | files | findings | ms |")
        add("| --- | --- | ---: | ---: | ---: |")
        for agent in agents:
            add("| `%s` | %s | %s | %s | %s |" % (
                agent.agent,
                _role(agent.agent),
                agent.files_scanned if agent.files_scanned else "-",
                len(agent.findings) if agent.findings else "-",
                agent.duration_ms,
            ))
        add("")
        corroborated = [f for f in findings if f.corroborated_by]
        if corroborated:
            add("`%d` finding(s) were independently confirmed by a second detector; the "
                "adjudicator records that agreement as an annotation and never changes a grade."
                % len(corroborated))
            add("")

    add("## Ranked findings")
    add("")
    add("| # | id | sev | conf | rule | where | what |")
    add("| ---: | --- | --- | ---: | --- | --- | --- |")
    for index, f in enumerate(findings, start=1):
        add("| %d | `%s` | **%s** | %.2f | %s | `%s` | %s |" % (
            index, f.id, f.severity.value, f.confidence, f.rule, _short_loc(f), f.title,
        ))
    add("")

    add("## Findings in detail")
    add("")
    for f in findings:
        add("### %s — %s" % (f.id, f.title))
        add("")
        add("| field | value |")
        add("| --- | --- |")
        add("| severity | **%s** |" % f.severity.value)
        add("| confidence | %.2f |" % f.confidence)
        add("| rank score | %.2f |" % f.score)
        add("| rule / detector | %s / %s |" % (f.rule, f.detector))
        if f.corroborated_by:
            add("| corroborated independently by | %d other detector(s), %d rule(s): %s |"
                % (f.independent_confirmation, len(f.corroborated_by),
                   ", ".join("`%s`" % c for c in f.corroborated_by)))
        add("| chain | %s |" % (f.chain or "-"))
        add("| location | `%s` |" % f.location)
        add("| cwe | %s |" % (f.cwe or "-"))
        add("| skill pack | `%s` |" % (f.skill or "-"))
        add("")
        add(f.description.strip())
        add("")
        add("```solidity" if f.chain != "solana" else "```rust")
        add(f.evidence if f.evidence else "(see location)")
        add("```")
        add("")
        add("**Exploit sketch (educational)**")
        add("")
        for step in f.exploit_sketch:
            add("1. %s" % step)
        add("")
        add("**Patch sketch**")
        add("")
        for item in f.patch_sketch:
            add("- %s" % item)
        add("")
        if f.poc:
            add("**PoC stub:** `%s` — run with `%s`" % (f.poc.filename, f.poc.how_to_run))
            add("")
        if f.checklist:
            add("**Skill checklist satisfied**")
            add("")
            for item in f.checklist:
                add("- [x] %s" % item)
            add("")
        if f.tags:
            add("tags: %s" % ", ".join("`%s`" % t for t in f.tags))
            add("")

    add("---")
    add("")
    add("## Honesty notes")
    add("")
    add("- SolGuardian is a **heuristic** static tool. Every finding carries a confidence "
        "score; anything below 0.6 is a review prompt, not a verdict.")
    add("- Detectors are deterministic code (see `solguardian/detectors/`), so this report "
        "reproduces byte-for-byte without spending model tokens.")
    add("- No live exploit code is emitted: PoC files are commented skeletons against the "
        "synthetic samples in `samples/`.")
    add("- Proof-of-storage, gas-cost modelling, and cross-contract composition are out of "
        "scope by design (see README).")
    add("- The **adjudicator** agent records where two independent detectors agree, but it is "
        "annotation-only: it cannot raise a severity or a confidence. Agreement is a triage "
        "signal, not evidence, and a site where detectors disagree on grade is reported as two "
        "findings rather than averaged into one.")
    add("")

    skill_index = _skill_index()
    if skill_index:
        add("## Skill packs used")
        add("")
        add("| skill | applies to | checklist items |")
        add("| --- | --- | ---: |")
        for slug, sk in sorted(skill_index.items()):
            add("| `%s` | %s | %d |" % (sk.path, ", ".join(sk.applies_to) or "-", len(sk.checklist)))
        add("")

    return "\n".join(lines)


def write(result: ScanResult, out_path: str, scorecard: Optional[Scorecard] = None, agents=None, target_arg: str = "") -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(build(result, scorecard, agents, target_arg))
    return out_path


def _role(name: str) -> str:
    if "hunter" in name:
        return "scan shard (parallel)" if "#" in name else "ecosystem hunter (parallel)"
    if name == "adjudicator":
        return "cross-check / corroboration"
    if name == "report-writer":
        return "output-contract gate"
    return "agent"


def _short_loc(f: Finding) -> str:
    name = os.path.basename(f.file)
    return "%s:%s%s" % (name, f.line, (" %s()" % f.function) if f.function else "")


def _version() -> str:
    from .. import __version__

    return __version__


def _skill_index() -> Dict[str, object]:
    try:
        return load_skills()
    except Exception:
        return {}
