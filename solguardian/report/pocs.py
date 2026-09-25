"""PoC stub generation.

Every confirmed finding ships a test skeleton so a reviewer can prove the claim in
minutes. Stubs are intentionally non-weaponised: they describe the shape of the attack
against synthetic samples and assert nothing until you wire the call.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from ..core.finding import Finding

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def _snake(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()
    return slug[:48] or "poc"


def _camel(text: str) -> str:
    return "".join(part.title() for part in re.split(r"[^A-Za-z0-9]+", text) if part)[:40] or "Harness"


def _load(name: str) -> str:
    with open(os.path.join(TEMPLATE_DIR, name), "r", encoding="utf-8") as fh:
        return fh.read()


def context_for(finding: Finding) -> Dict[str, str]:
    function = finding.function or "vulnerableFunction"
    contract = finding.contract or _camel(os.path.splitext(os.path.basename(finding.file))[0])
    steps = list(finding.exploit_sketch) + ["", "", ""]
    patches = list(finding.patch_sketch) + ["", ""]
    return {
        "FINDING_ID": finding.id,
        "TITLE": finding.title,
        "SEVERITY": finding.severity.value,
        "CONFIDENCE": "%.2f" % finding.confidence,
        "RULE": finding.rule,
        "SKILL": finding.skill or "-",
        "LOCATION": finding.location,
        "FUNCTION": function,
        "TARGET_CONTRACT": contract,
        "TARGET_CONTRACT_FILE": os.path.basename(finding.file) or "Target.sol",
        "ACCOUNTS_STRUCT": contract,
        "HARNESS": _camel(finding.id + "_" + finding.slug()) + "Harness",
        "TEST_NAME": _snake(finding.id + " " + finding.title),
        "EXPLOIT_STEP_1": steps[0],
        "EXPLOIT_STEP_2": steps[1],
        "EXPLOIT_STEP_3": steps[2],
        "PATCH_1": patches[0],
        "PATCH_2": patches[1],
    }


LEFTOVER = re.compile(r"\{\{[A-Z0-9_]+\}\}")


def render(template: str, ctx: Dict[str, str]) -> str:
    out = template
    for key, value in ctx.items():
        out = out.replace("{{%s}}" % key, str(value))
    return LEFTOVER.sub("(n/a)", out)


def build_poc(finding: Finding, override: Optional[str] = None) -> "PocStub":
    from ..core.finding import PocStub  # local import: avoids a cycle

    ctx = context_for(finding)
    if finding.chain == "solana":
        language, template, suffix = "rust", "anchor_stub.rs", ".rs"
        how = "cargo test --features test-suites %s" % ctx["TEST_NAME"]
    else:
        language, template, suffix = "solidity", "foundry_stub.t.sol", ".t.sol"
        how = "forge test --match-contract %s -vvvv" % ctx["HARNESS"]

    filename = "pocs/%s_%s%s" % (finding.id.lower(), ctx["TEST_NAME"][:32], suffix)
    if override is not None:
        code = override.rstrip() + "\n"
    else:
        code = render(_load(template), ctx)
    return PocStub(language=language, filename=filename, code=code, how_to_run=how)


def write_pocs(findings: List[Finding], out_dir: str) -> List[str]:
    """Write stub files under out_dir/pocs and return their relative paths."""
    pocs_dir = os.path.join(out_dir, "pocs")
    os.makedirs(pocs_dir, exist_ok=True)
    written: List[str] = []
    for finding in findings:
        if not finding.poc:
            continue
        rel = finding.poc.filename
        path = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(finding.poc.code)
        if rel not in written:
            written.append(rel)
    return sorted(written)
