"""Documentation is part of the deliverable, so it is tested like code.

Enforces: submission word limits, the video script's timing budget, seed-tag/ground-truth
agreement, the hackathon's required file set, and a no-secrets sweep over tracked files.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _has_yaml() -> bool:
    import importlib.util

    return importlib.util.find_spec("yaml") is not None


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), "r", encoding="utf-8") as fh:
        return fh.read()


class TestSubmissionStatements(unittest.TestCase):
    """lablab requires two written statements of <=500 words each."""

    def setUp(self) -> None:
        text = read("STATEMENTS.md")
        self.parts = re.split(r"^## \d+\. ", text, flags=re.M)[1:]
        self.assertEqual(len(self.parts), 2, "STATEMENTS.md must hold exactly two statements")

    def test_word_limits(self) -> None:
        for block in self.parts:
            title = block.splitlines()[0].strip()
            body = re.sub(r"\*\(≈?\d+ words?\)\*", "", block)
            body = re.sub(r"[#*_>`|-]", " ", body)
            words = len(body.split())
            self.assertLessEqual(words, 500, "%s is %d words (limit 500)" % (title, words))
            self.assertGreaterEqual(words, 250, "%s is thin: %d words" % (title, words))

    def test_titles(self) -> None:
        titles = " ".join(p.splitlines()[0] for p in self.parts).lower()
        self.assertIn("problem", titles)
        self.assertIn("solution", titles)
        self.assertIn("bob", titles)

    def test_bob_statement_cites_real_artifacts(self) -> None:
        bob_block = [p for p in self.parts if "bob" in p.splitlines()[0].lower()][0]
        for artefact in ("bob_sessions", "EvmHunter", "SolanaHunter", "ReportWriter", "skills/"):
            self.assertIn(artefact, bob_block, "statement must reference %s" % artefact)
        # every path it name-checks must exist
        for path in re.findall(r"`(solguardian/[A-Za-z0-9_./]+|skills/\*|bob_sessions/[A-Za-z0-9_./]+)`", bob_block):
            if path.endswith("*") or path.endswith("/"):
                continue
            probe = os.path.join(ROOT, path.replace("skills/*", "skills"))
            self.assertTrue(os.path.exists(probe), "statement references a missing path: %s" % path)


class TestVideoScript(unittest.TestCase):
    def test_live_demo_is_at_least_90_seconds(self) -> None:
        script = read("docs", "VIDEO_SCRIPT.md")
        segments = re.findall(
            r"\|\s*(\d):(\d\d)[-–](\d):(\d\d)\s*\|\s*\*{0,2}([^|*\n]+)", script
        )
        self.assertGreaterEqual(len(segments), 5, "expected a timed run sheet")
        total = 0
        live = 0
        for s1, m1, s2, m2, label in segments:
            # stamps are M:SS (minutes:seconds) within a <=3 minute video
            span = (int(s2) * 60 + int(m2)) - (int(s1) * 60 + int(m1))
            total += span
            if "LIVE" in label.upper():
                live += span
        self.assertLessEqual(total, 180, "video must be <=3 minutes, script totals %ds" % total)
        self.assertEqual(total, 180, "run sheet should account for the full 3:00 (%ds)" % total)
        self.assertGreaterEqual(live, 90, "live demo section must be >=90s, is %ds" % live)

    def test_bob_appears_on_camera(self) -> None:
        script = read("docs", "VIDEO_SCRIPT.md").lower()
        self.assertIn("ibm bob", script)
        self.assertIn("subagent", script)


class TestSamplesAreHonest(unittest.TestCase):
    """Seed tags, ground truth and the README must agree - no untagged bugs, no phantom seeds."""

    def setUp(self) -> None:
        import json

        self.seeded = json.loads(read("samples", "EXPECTED_FINDINGS.json"))["seeded"]

    def test_ground_truth_shape(self) -> None:
        self.assertGreaterEqual(len(self.seeded), 8, "spec asks for ~8 seeded issues")
        for entry in self.seeded:
            for key in ("key", "file", "lines", "severity", "note"):
                self.assertIn(key, entry)
            self.assertEqual(len(entry["lines"]), 2)
            self.assertLessEqual(entry["lines"][0], entry["lines"][1])
            self.assertTrue(entry.get("rules") or entry.get("detectors"), entry["key"])

    SAMPLE_FILES = ("solidity/Vault.sol", "solidity/HyperVault.sol",
                    "solana/vault/programs/vault/src/lib.rs",
                    "clean/CleanVault.sol", "clean/clean_vault.rs")

    def _samples(self) -> str:
        return "\n".join(read("samples", *rel.split("/")) for rel in self.SAMPLE_FILES)

    def test_every_seed_is_tagged_in_source(self) -> None:
        """Each planted bug carries a @seeded tag, and each tag class is in ground truth."""
        classes = set(re.findall(r"(?:@custom:seeded|@seeded)\s+([A-Za-z0-9_-]+)", self._samples()))
        self.assertGreaterEqual(len(classes), 8, "expected >=8 seeded classes, got %s" % sorted(classes))

        known = set()
        for entry in self.seeded:
            known |= set(entry.get("classes", []))
            known.add(entry["key"].split("-", 1)[-1].split("-")[0])
        untagged = [c for c in sorted(classes) if not any(
            c.lower().replace("-", "") in k.lower().replace("-", "").replace("_", "")
            or k.lower().replace("-", "").replace("_", "") in c.lower().replace("-", "")
            for k in known)]
        self.assertFalse(untagged, "seeded tags with no ground-truth entry: %s" % untagged)

    def test_seeded_files_declare_themselves_synthetic(self) -> None:
        for rel in ("solidity/Vault.sol", "solidity/HyperVault.sol",
                    "solana/vault/programs/vault/src/lib.rs"):
            text = read("samples", *rel.split("/")).lower()
            self.assertTrue("synthetic" in text or "teaching" in text,
                            "%s must state it is synthetic/teaching-only" % rel)
            self.assertTrue("educational" in text or "do not deploy" in text or "intentionally" in text,
                            "%s must warn it is not deployable" % rel)

    def test_no_live_addresses_or_endpoints(self) -> None:
        blob = (self._samples() + read("samples", "README.md")
                + read("samples", "EXPECTED_FINDINGS.json"))
        # the secp256k1 half-order constant in the clean control is a mathematical constant
        # (and a documented allowlist entry in DATA_SOURCES.md), not an address
        blob = blob.replace("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
                            "<half-order-constant>")
        low = blob.lower()
        for needle in ("https://rpc", "infura", "alchemy", "quicknode", "https://api",
                       "wss://", "https://mainnet", "https://sepolia", "https://goerli"):
            self.assertNotIn(needle, low, needle)
        # no realistic 20-byte hex address (our samples only use short selector/magic constants)
        self.assertFalse(re.search(r"0x[0-9a-fA-F]{40}", blob),
                         "a real-looking 20-byte address appeared in the samples")
        self.assertFalse(re.search(r"0x[0-9a-fA-F]{64}", blob),
                         "a real-looking 32-byte hash appeared in the samples")

class TestRequiredFiles(unittest.TestCase):
    REQUIRED = [
        "README.md", "LICENSE", "AGENTS.md", "BUILD.md", "DATA_SOURCES.md", "STATEMENTS.md",
        ".gitignore", ".bobignore", "pyproject.toml",
        "samples/EXPECTED_FINDINGS.json",
        "skills/reentrancy/SKILL.md", "skills/access-control/SKILL.md",
        "skills/oracle-price/SKILL.md", "skills/solana-account-validation/SKILL.md",
        "skills/hyperliquid-hyperevm-notes/SKILL.md", "skills/severity-grading/SKILL.md",
        "skills/poc-stubs/SKILL.md",
        "bob_sessions/README.md", "bob_sessions/bob_tasks/task01_init_agents_md.md",
        "bob_sessions/bob_tasks/task06_end_to_end_demo.md",
        "solguardian/cli.py", "solguardian/detectors/evm_reentrancy.py",
        "solguardian/detectors/solana_signer.py",
        "solguardian/report/templates/foundry_stub.t.sol",
        "solguardian/report/templates/anchor_stub.rs",
        "docs/VIDEO_SCRIPT.md", "docs/SLIDES.md", "docs/index.html", "docs/cover.png",
        "docs/SUBMISSION.md", "docs/make_cover.py",
        "tools/recall_gate.py", "tools/secret_scan.py",
        "demo/report.html", "demo/report.json", "demo/index.html",
        "samples/clean/CleanVault.sol", "samples/clean/clean_vault.rs",
        "tests/test_false_positives.py", "tests/run_tests.py",
        ".github/workflows/ci.yml", ".github/workflows/pages.yml",
    ]

    def test_all_present(self) -> None:
        for rel in self.REQUIRED:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, rel)), "missing required file: %s" % rel)

    def test_license_is_mit(self) -> None:
        self.assertIn("MIT License", read("LICENSE"))

    def test_bobignore_and_gitignore_block_secrets(self) -> None:
        for name in (".gitignore", ".bobignore"):
            text = read(name)
            for needle in (".env", "*.key"):
                self.assertIn(needle, text, "%s does not ignore %s" % (name, needle))

    def test_bob_task_files_cover_every_workstream(self) -> None:
        tasks = sorted(f for f in os.listdir(os.path.join(ROOT, "bob_sessions", "bob_tasks"))
                       if f.endswith(".md"))
        self.assertGreaterEqual(len(tasks), 6, "expected >=6 Bob workstreams")
        for name in tasks:
            text = read("bob_sessions", "bob_tasks", name)
            self.assertIn("Screenshot to save", text, name)
            self.assertRegex(text, r"```[\s\S]*?```", "%s has no pasteable prompt" % name)

    def test_readme_states_heuristic_honesty(self) -> None:
        readme = read("README.md").lower()
        self.assertIn("heuristic", readme)
        self.assertIn("false positive", readme)
        self.assertIn("bob", readme)

    def test_static_artifacts_do_not_reach_the_network(self) -> None:
        """Landing page and generated report must work offline / on Pages."""
        for rel in ("demo/index.html", "docs/index.html", "demo/report.html"):
            html = read(*rel.split("/")).lower()
            for banned in ("<script src", "cdn.", "googleapis", "fonts."):
                self.assertNotIn(banned, html, "%s fetches %s" % (rel, banned))

    def test_negative_control_is_documented(self) -> None:
        readme = read("README.md").lower()
        self.assertIn("negative control", readme)
        self.assertIn("samples/clean", readme)

    def test_no_real_protocol_names_as_code_sources(self) -> None:
        """Naming a venue in a skill doc is fine; shipping its code is not."""
        for rel in ("solidity/Vault.sol", "solidity/HyperVault.sol",
                    "solana/vault/programs/vault/src/lib.rs"):
            text = read("samples", *rel.split("/"))
            self.assertNotIn("uniswap-v3-periphery", text)
            self.assertNotIn("Compiled with solc", text)


class TestToolingScripts(unittest.TestCase):
    """The helper scripts CI calls must exist, compile and pass on a healthy tree."""

    def test_recall_gate_passes(self) -> None:
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "recall_gate.py")],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, (proc.stdout + proc.stderr)[-900:])
        self.assertIn("PASS", proc.stdout)

    def test_secret_scan_is_clean(self) -> None:
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "secret_scan.py")],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, (proc.stdout + proc.stderr)[-900:])
        self.assertIn("clean", proc.stdout)

    @unittest.skipUnless(_has_yaml(), "PyYAML not installed")
    def test_github_workflows_parse(self) -> None:
        """A workflow that fails to parse is a silent CI failure (this really happened)."""
        import yaml

        for rel in (".github/workflows/ci.yml", ".github/workflows/pages.yml"):
            with self.subTest(workflow=rel):
                doc = yaml.safe_load(read(*rel.split("/")))
                self.assertTrue(doc.get("jobs"), "%s declares no jobs" % rel)

    def test_helper_scripts_compile(self) -> None:
        import py_compile

        for rel in ("tools/recall_gate.py", "tools/secret_scan.py", "docs/make_cover.py",
                    "tests/run_tests.py"):
            with self.subTest(script=rel):
                py_compile.compile(os.path.join(ROOT, *rel.split("/")), doraise=True)


class TestNoSecretsTracked(unittest.TestCase):
    # NOTE: the words below also appear legitimately in docs about what must never be
    # committed, and in the hackathon prompt files we were given. Those paths are
    # allowlisted; the credential *shapes* (tokens, keys, rpc urls) are never allowlisted.
    ALLOWLIST_PREFIXES = ("solguardian/detectors/", "solguardian/core/", "tests/", "skills/",
                          "HANDOVER_PROMPT.md", "bob_sessions/", "DATA_SOURCES.md",
                          "AGENTS.md", "README.md", "STATEMENTS.md", "BUILD.md", "docs/",
                          # this file *defines* the credential shapes it hunts for
                          "tools/secret_scan.py")

    SECRETISH = re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|seed phrase|password\s*=|"
        r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-|AKIA[0-9A-Z]{16}|"
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|https://[a-z0-9.-]+\.(infura|alchemy|quicknode)[^\"']*)"
    )
    SKIP = {".git", "__pycache__", "out", "build", "dist", ".pytest_cache", "node_modules"}

    def _files(self):
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP and not d.startswith(".g")]
            for name in filenames:
                if name.endswith((".png", ".jpg", ".gif", ".ico", ".pyc")):
                    continue
                yield os.path.join(dirpath, name)

    def test_no_credentials_in_the_tree(self) -> None:
        hits = []
        for path in self._files():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except (UnicodeDecodeError, OSError):
                continue
            for match in self.SECRETISH.finditer(text):
                # allow the detector rules that search for these words
                rel = os.path.relpath(path, ROOT)
                if rel.startswith(self.ALLOWLIST_PREFIXES) or rel.startswith("samples/README"):
                    continue
                hits.append("%s: %s" % (rel, match.group(0)[:40]))
        self.assertFalse(hits, "possible secrets committed:\n" + "\n".join(hits))


if __name__ == "__main__":
    unittest.main(verbosity=2)
