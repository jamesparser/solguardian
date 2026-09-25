"""SolGuardian test suite - stdlib unittest, no third-party runner required.

    python3 -m unittest discover -s tests -v
    python3 tests/run_tests.py

The tests are the demo's evidence chain: they assert the detector suite catches every
seeded issue, emits the full output contract for each finding, and does not regress into
the false positives we explicitly trained out.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from solguardian.core.detector import all_detectors  # noqa: E402
from solguardian.core.finding import Severity  # noqa: E402
from solguardian.core.scanner import scan  # noqa: E402
from solguardian.core.scorecard import load_expectations, score  # noqa: E402
from solguardian.core.skills import load_skills  # noqa: E402
from solguardian.core.source import build_target  # noqa: E402
from solguardian.report import html_report, json_report, md_report  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")
EXPECT = os.path.join(SAMPLES, "EXPECTED_FINDINGS.json")


def _scan(path: str):
    return scan(build_target(path))


class TestRegistry(unittest.TestCase):
    def test_detectors_registered(self) -> None:
        ids = {d.id for d in all_detectors()}
        for expected in (
            "evm_reentrancy", "evm_access", "evm_external_calls", "evm_delegatecall",
            "evm_oracle", "evm_sig_replay", "evm_selfdestruct",
            "solana_signer", "solana_accounts", "solana_cpi", "solana_math",
            "solana_authority", "solana_deser",
        ):
            self.assertIn(expected, ids, "detector %s is not registered" % expected)

    def test_every_detector_declares_a_real_skill(self) -> None:
        skills = load_skills()
        self.assertTrue(skills, "skills/ did not load")
        for detector in all_detectors():
            self.assertIn(detector.skill, skills, "%s points at a missing skill pack" % detector.id)
            self.assertTrue(detector.cwe, "%s has no CWE" % detector.id)

    def test_required_skill_packs_exist(self) -> None:
        skills = load_skills()
        for slug in (
            "reentrancy", "access-control", "oracle-price", "solana-account-validation",
            "hyperliquid-hyperevm-notes", "severity-grading", "poc-stubs",
            "external-calls", "delegatecall-proxy", "signature-replay", "fund-recovery",
            "solana-cpi", "solana-math", "solana-signer",
        ):
            self.assertIn(slug, skills, "missing skills/%s/SKILL.md" % slug)
            skill = skills[slug]
            self.assertGreaterEqual(len(skill.checklist), 5, "%s checklist too thin" % slug)
            self.assertTrue(skill.when_to_use, "%s has no 'When to use'" % slug)
            self.assertTrue(skill.false_positives or slug == "poc-stubs", "%s has no FP notes" % slug)
            self.assertTrue(skill.cwe, "%s has no cwe in frontmatter" % slug)


class TestOutputContract(unittest.TestCase):
    """Every finding must be independently actionable - the report's core promise."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = _scan(SAMPLES)

    def test_scan_found_something(self) -> None:
        self.assertGreaterEqual(len(self.result.findings), 20)

    def test_fields_complete(self) -> None:
        for f in self.result.findings:
            with self.subTest(finding=f.id):
                self.assertTrue(f.id.startswith("SG-"))
                self.assertIsInstance(f.severity, Severity)
                self.assertTrue(0.0 < f.confidence <= 1.0)
                self.assertTrue(f.title and len(f.title) > 12)
                self.assertGreaterEqual(len(f.description.split()), 20, "description not 2-5 sentences")
                self.assertTrue(f.file and f.line > 0, "missing location")
                self.assertTrue(f.evidence, "missing evidence line")
                self.assertGreaterEqual(len(f.exploit_sketch), 1)
                self.assertGreaterEqual(len(f.patch_sketch), 1)
                self.assertTrue(f.skill.startswith("skills/"), "missing skill pack reference")
                self.assertTrue(f.rule and f.detector)
                self.assertIsNotNone(f.poc, "missing PoC stub")
                self.assertIn(f.chain, ("evm", "hyperevm", "solana"))

    def test_pocs_are_language_appropriate(self) -> None:
        for f in self.result.findings:
            if f.chain == "solana":
                self.assertTrue(f.poc.filename.endswith(".rs"), f.id)
                self.assertIn("cargo test", f.poc.how_to_run)
            else:
                self.assertTrue(f.poc.filename.endswith(".t.sol"), f.id)
                self.assertIn("forge test", f.poc.how_to_run)
            self.assertIn(f.id, f.poc.code, "PoC header missing its finding id")
            self.assertIn("Educational", f.poc.code)

    def test_no_secrets_or_live_targets_in_output(self) -> None:
        blob = "\n".join(f.poc.code for f in self.result.findings if f.poc)
        for needle in ("0x00000000000000000000000000000000000000", "PRIVATE_KEY", "mnemonic",
                       "https://rpc.", "infura", "alchemy"):
            self.assertNotIn(needle, blob.lower() if needle.islower() else blob, needle)

    def test_ranking_is_monotonic_by_score(self) -> None:
        scores = [f.score for f in self.result.findings]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_ids_unique(self) -> None:
        ids = [f.id for f in self.result.findings]
        self.assertEqual(len(ids), len(set(ids)))


class TestGroundTruth(unittest.TestCase):
    """The demo metric: seeded recall, plus the false positives we trained out."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = _scan(SAMPLES)
        cls.seeded = load_expectations(EXPECT)
        cls.card = score(cls.result.findings, cls.seeded)

    def test_all_seeded_issues_caught(self) -> None:
        missed = ["%s (%s)" % (m.key, m.note) for m in self.card.missed]
        self.assertFalse(missed, "missed seeded issues: %s" % "; ".join(missed))

    def test_recall_meets_demo_bar(self) -> None:
        # handover target was >=7/8; the seed set grew to 16 across three chains
        self.assertGreaterEqual(len(self.card.caught), 8)
        self.assertGreaterEqual(self.card.recall, 0.95)

    def test_per_chain_recall(self) -> None:
        per = {"solidity": 0, "rust": 0}
        for key, finding in self.card.caught.items():
            per["rust" if finding.file.endswith(".rs") else "solidity"] += 1
        self.assertGreaterEqual(per["solidity"], 8, "EVM/HyperEVM regression")
        self.assertGreaterEqual(per["rust"], 6, "Solana regression (spec floor: 2 detectors)")

    def test_critical_seeded_issues_graded_critical_or_high(self) -> None:
        for key, finding in self.card.caught.items():
            expected = next(s for s in self.seeded if s.key == key)
            if expected.severity == "critical":
                self.assertIn(finding.severity, (Severity.CRITICAL, Severity.HIGH),
                              "%s undergraded to %s" % (key, finding.severity.value))

    def test_negative_cases_not_flagged(self) -> None:
        """Guardrails against the false positives we removed:

        - a caller-scoped `withdraw()` is not "missing access control"
        - `payable(x).transfer(v)` is not an unchecked return value (it reverts by design)
        - a `Program<'info, T>` / token_program slot is not a missing-signer finding
        """
        access = [f for f in self.result.findings
                  if f.rule.startswith("AC-001") and f.function == "withdraw"]
        self.assertFalse(access, "caller-scoped withdraw() must not be an AC-001")

        unchecked_native = [f for f in self.result.findings
                            if f.rule == "EC-001" and "transfer" in f.evidence
                            and "payable(" in f.evidence]
        self.assertFalse(unchecked_native, "native push payment flagged as unchecked return")

        signer_noise = [f for f in self.result.findings
                        if f.rule == "SIGNER-001" and f.file.endswith(".rs")
                        and f.evidence.strip().startswith("pub token_program")]
        self.assertFalse(signer_noise, "token_program flagged as missing signer")

    def test_deterministic_output(self) -> None:
        again = _scan(SAMPLES)
        self.assertEqual(
            [(f.id, f.rule, f.file, f.line, f.severity.value) for f in self.result.findings],
            [(f.id, f.rule, f.file, f.line, f.severity.value) for f in again.findings],
        )


class TestReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = _scan(SAMPLES)
        cls.card = score(cls.result.findings, load_expectations(EXPECT))

    def test_json_shape(self) -> None:
        payload = json_report.build(self.result, self.card)
        self.assertEqual(payload["tool"]["name"], "SolGuardian")
        self.assertEqual(len(payload["findings"]), len(self.result.findings))
        self.assertIn("demo_metrics", payload)
        self.assertEqual(json.loads(json.dumps(payload))["summary"]["total"], len(self.result.findings))
        first = payload["findings"][0]
        for key in ("id", "severity", "confidence", "location", "description",
                    "exploit_sketch", "patch_sketch", "poc", "skill", "cwe"):
            self.assertIn(key, first)

    def test_markdown_sections(self) -> None:
        text = md_report.build(self.result, self.card, target_arg="samples")
        for heading in ("# SolGuardian analysis report", "## Demo metrics", "## Ranked findings",
                        "## Findings in detail", "## Honesty notes", "## Skill packs used"):
            self.assertIn(heading, text)
        self.assertIn("recall", text.lower())
        self.assertIn("skills/reentrancy/SKILL.md", text)

    def test_html_is_self_contained(self) -> None:
        html = html_report.build(self.result, self.card, target_arg="samples")
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", html)
        for banned in ("http://", "cdn.", "googleapis", "<script src"):
            self.assertNotIn(banned, html, "report.html must not fetch anything: %s" % banned)
        self.assertIn("SolGuardian", html)


class TestCli(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "solguardian"] + list(args),
            cwd=ROOT, capture_output=True, text=True,
        )

    def test_analyze_single_solidity_file(self) -> None:
        proc = self.run_cli("analyze", "samples/solidity/Vault.sol", "--out", "out/test-vault", "--quiet")
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        for name in ("report.json", "report.md"):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, "out", "test-vault", name)), name)

    def test_analyze_solana_directory(self) -> None:
        proc = self.run_cli("analyze", "samples/solana/vault", "--out", "out/test-solana", "--quiet")
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        with open(os.path.join(ROOT, "out", "test-solana", "report.json")) as fh:
            data = json.load(fh)
        chains = set(data["summary"]["by_chain"])
        self.assertIn("solana", chains)
        detectors = set(data["detectors_run"])
        self.assertGreaterEqual(len([d for d in detectors if d.startswith("solana_")]), 2)

    def test_fail_on_gate(self) -> None:
        proc = self.run_cli("analyze", "samples", "--out", "out/test-gate", "--quiet", "--fail-on", "critical")
        self.assertEqual(proc.returncode, 1, "gate must trip on critical findings")
        proc = self.run_cli("analyze", "samples", "--out", "out/test-gate", "--quiet", "--fail-on", "info")
        self.assertEqual(proc.returncode, 1)

    def test_html_flag(self) -> None:
        proc = self.run_cli("analyze", "samples", "--out", "out/test-html", "--html", "--quiet")
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "out", "test-html", "report.html")))

    def test_list_and_version(self) -> None:
        self.assertEqual(self.run_cli("list").returncode, 0)
        self.assertEqual(self.run_cli("--version").returncode, 0)
        out = self.run_cli("list").stdout
        self.assertIn("skills/", out)

    def test_missing_path_errors(self) -> None:
        proc = self.run_cli("analyze", "samples/nope-nothing-here")
        self.assertNotEqual(proc.returncode, 0)


class TestPerformance(unittest.TestCase):
    def test_time_to_report(self) -> None:
        """Demo metric: full report in well under the 5-minute bar."""
        result = _scan(SAMPLES)
        self.assertLess(result.duration_ms, 5000, "scan took %d ms" % result.duration_ms)

    def test_serial_matches_parallel(self) -> None:
        from solguardian.agents.orchestrator import run_pipeline

        target = build_target(SAMPLES)
        serial = sorted(f.rule + f.file + str(f.line) for f in scan(target).findings)
        par = sorted(f.rule + f.file + str(f.line) for f in run_pipeline(target, parallel=False, verbose=False).findings)
        self.assertEqual(serial, par, "the agent pipeline must not change results")


if __name__ == "__main__":
    unittest.main(verbosity=2)
