"""Multi-agent orchestration: the contract behind "several agents audit at once".

Three properties matter and are easy to break, so they are pinned here:

1. **Fan-out is real.** More files -> more concurrent workers, with disjoint shards whose union
   is exactly the target's file set (no file scanned twice, none skipped).
2. **Results are order-independent.** Findings arrive from N threads in arbitrary order, so the
   ranked ids must be identical no matter how the work was sharded. Otherwise PoC filenames and
   the report change between runs, which for a security tool is unacceptable.
3. **The adjudicator cannot flatter the report.** It annotates corroboration; it must never move
   a severity or a confidence.
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from solguardian.agents.orchestrator import (  # noqa: E402
    Adjudicator, build_specs, resolve_workers, run_pipeline, shard_files,
)
from solguardian.agents.evm_hunter import EvmHunter  # noqa: E402
from solguardian.agents.pool import (  # noqa: E402
    PROCESS_HINT_FILES, PROCESS_HINT_LINES, pick_backend, would_benefit_from_processes,
)
from solguardian.core.detector import all_detectors  # noqa: E402
from solguardian.core.source import build_target  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")


def _snapshot(findings):
    return [(f.id, f.rule, f.file, f.line, f.severity.value) for f in findings]


class TestSharding(unittest.TestCase):
    def test_bin_packing_is_disjoint_and_complete(self) -> None:
        files = build_target(SAMPLES).files
        shards = shard_files(files, 3)
        flat = [f.rel for shard in shards for f in shard]
        self.assertEqual(sorted(flat), sorted(f.rel for f in files), "a file was lost or doubled")
        self.assertEqual(len(flat), len(set(flat)), "a file landed in two shards")

    def test_balance_puts_the_biggest_file_first(self) -> None:
        files = build_target(SAMPLES).files
        shards = shard_files(files, 2)
        loads = [sum(len(f) for f in shard) for shard in shards]
        self.assertLessEqual(max(loads) - min(loads), max(loads) * 0.6,
                             "shards are badly balanced: %s" % loads)

    def test_single_file_is_not_sharded(self) -> None:
        files = build_target(SAMPLES).files[:1]
        self.assertEqual(len(shard_files(files, 4)), 1)

    def test_workers_are_clamped_to_useful_range(self) -> None:
        self.assertEqual(resolve_workers(50, 3), 3, "cannot usefully run 50 agents over 3 files")
        self.assertEqual(resolve_workers(0, 5), 1)
        self.assertEqual(resolve_workers(-3, 5), 1)
        self.assertGreaterEqual(resolve_workers(None, 5), 1)

    def test_specs_never_mix_languages(self) -> None:
        """A shard is one language, so an agent's detectors cannot be applied to the wrong one."""
        target = build_target(SAMPLES)
        for spec in build_specs(target, 4):
            langs = {f.language for f in spec.files}
            self.assertEqual(langs, {spec.language}, "%s got %s" % (spec.name, langs))


class TestFanOut(unittest.TestCase):
    def test_more_files_spawn_more_agents(self) -> None:
        target = build_target(SAMPLES)
        one = run_pipeline(target, workers=1, verbose=False)
        many = run_pipeline(target, workers=4, verbose=False)
        hunters_one = [a for a in one.agents if "hunter" in a.agent]
        hunters_many = [a for a in many.agents if "hunter" in a.agent]
        self.assertEqual(len(hunters_one), len({s.language for s in build_specs(target, 1)}))
        self.assertGreater(len(hunters_many), len(hunters_one),
                           "sharding produced no extra concurrency")
        self.assertTrue(any("#" in a.agent for a in hunters_many),
                        "expected sharded agent names like evm-hunter#2")

    def test_pipeline_reports_the_agent_roles(self) -> None:
        summary = run_pipeline(build_target(SAMPLES), workers=3, verbose=False)
        names = [a.agent for a in summary.agents]
        self.assertIn("adjudicator", names)
        self.assertIn("report-writer", names)
        self.assertGreaterEqual(summary.workers, 2)
        self.assertEqual(summary.to_dict()["parallel_workers"], summary.workers)

    def test_every_file_is_scanned_exactly_once(self) -> None:
        target = build_target(SAMPLES)
        summary = run_pipeline(target, workers=4, verbose=False)
        scanned = sum(a.files_scanned for a in summary.agents if "hunter" in a.agent)
        self.assertEqual(scanned, len(target.files),
                         "shards double-scanned or skipped a file")


class TestOrderIndependence(unittest.TestCase):
    """The property that makes concurrent scanning safe to ship."""

    def test_ids_are_identical_across_worker_counts(self) -> None:
        target = build_target(SAMPLES)
        base = _snapshot(run_pipeline(target, workers=1, verbose=False).findings)
        for workers in (2, 3, 5):
            with self.subTest(workers=workers):
                got = _snapshot(run_pipeline(target, workers=workers, verbose=False).findings)
                self.assertEqual(base, got)

    def test_serial_path_matches_parallel_path(self) -> None:
        from solguardian.core.scanner import scan

        target = build_target(SAMPLES)
        serial = sorted("%s|%s|%d" % (f.rule, f.file, f.line) for f in scan(target).findings)
        par = sorted("%s|%s|%d" % (f.rule, f.file, f.line)
                     for f in run_pipeline(target, parallel=False, verbose=False).findings)
        self.assertEqual(serial, par)

    def test_shard_order_does_not_change_ranking(self) -> None:
        target = build_target(SAMPLES)
        scores = [f.score for f in run_pipeline(target, workers=4, verbose=False).findings]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestAdjudicator(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary = run_pipeline(build_target(SAMPLES), workers=3, verbose=False)
        cls.findings = cls.summary.findings

    def test_adjudicator_cannot_promote_its_own_guesses(self) -> None:
        """Compare against the same scan run *without* the adjudicator: severities and
        confidences must be byte-identical. Corroboration is an annotation only - if the
        cross-check pass were allowed to raise a grade, the agents could inflate their own
        findings, which is exactly what this tool must not do."""
        from solguardian.core.scanner import scan

        before = {(f.rule, f.file, f.line): (f.severity, f.confidence)
                  for f in scan(build_target(SAMPLES)).findings}
        after = {(f.rule, f.file, f.line): (f.severity, f.confidence) for f in self.findings}
        self.assertEqual(set(before), set(after), "the adjudicator added or dropped findings")
        for key, value in after.items():
            self.assertEqual(before[key], value,
                             "adjudicator changed %s -> %s" % (key, value))

    def test_corroboration_only_counts_other_detectors(self) -> None:
        for f in self.findings:
            if f.corroborated_by:
                self.assertGreaterEqual(f.independent_confirmation, 1)
                for entry in f.corroborated_by:
                    rule = entry.split(" ")[0]
                    self.assertNotEqual(rule, f.rule,
                                        "%s corroborated by its own rule" % f.id)
                    self.assertNotEqual(entry.split(" (")[-1].rstrip(")"), f.id)

    def test_a_multi_rule_site_is_corroborated(self) -> None:
        """claimTreasuryGrant() is independently flagged by the signature, reentrancy and
        unchecked-call packs - that agreement should surface in the report."""
        grant = [f for f in self.findings if f.function == "claimTreasuryGrant"]
        self.assertGreaterEqual(len({f.detector for f in grant}), 2,
                                "expected several detectors on claimTreasuryGrant()")
        self.assertTrue(any(f.corroborated_by for f in grant),
                        "adjudicator found no corroboration at a genuinely multi-rule site")

    def test_idempotent_rerun(self) -> None:
        """Re-adjudicating must not accumulate duplicates and overstate agreement.

        Operates on its own fresh scan: mutating the shared class fixture here would leak
        into every other test in the class.
        """
        findings = run_pipeline(build_target(SAMPLES), workers=2, verbose=False).findings
        before = {f.id: list(f.corroborated_by) for f in findings}
        adjudicator = Adjudicator(all_detectors())
        adjudicator.run(findings)
        adjudicator.run(findings)
        after = {f.id: list(f.corroborated_by) for f in findings}
        self.assertEqual(before, after, "adjudicator is not idempotent")
        for f in findings:
            self.assertEqual(len(f.corroborated_by), len(set(f.corroborated_by)),
                             "duplicate corroborations on %s" % f.id)

    def test_report_surfaces_corroboration(self) -> None:
        from solguardian.report import html_report, json_report, md_report

        result = run_pipeline(build_target(SAMPLES), workers=3, verbose=False).scan_result()
        payload = json_report.build(result)
        first = payload["findings"][0]
        self.assertIn("corroborated_by", first)
        self.assertIn("independent_confirmation", first)
        self.assertTrue(any(f.corroborated_by for f in result.findings),
                        "no corroboration to render - is the adjudicator wired in?")
        text = md_report.build(result, target_arg="samples", agents=result.agents)
        self.assertIn("corroborated independently by", text.lower())
        self.assertIn("## Agent pipeline", text)
        self.assertIn("adjudicator", text)
        self.assertIn("cross-check", text)

        page = html_report.build(result, target_arg="samples")
        self.assertIn("Agent pipeline", page)
        self.assertIn("corroborated independently by", page)
        self.assertIn("annotation-only", page)
        for banned in ("<script src", "cdn.", "googleapis"):
            self.assertNotIn(banned, page.lower(), "report.html must stay offline")


class TestBackendSelection(unittest.TestCase):
    """`auto` must never silently fork: spawn re-imports the caller's __main__ in every child."""

    def test_auto_is_conservative_for_library_callers(self) -> None:
        self.assertEqual(pick_backend("auto", 100000, 500, 8), "threads")
        self.assertEqual(pick_backend(None, 100000, 500, 8), "threads")

    def test_auto_upgrades_only_for_a_guarded_caller(self) -> None:
        self.assertEqual(pick_backend("auto", 100000, 500, 8, allow_processes=True), "processes")
        # ... and not for a corpus too small to pay for child startup
        self.assertEqual(pick_backend("auto", 900, 3, 3, allow_processes=True), "threads")

    def test_explicit_choices_are_honoured(self) -> None:
        self.assertEqual(pick_backend("threads", 99999, 999, 8, allow_processes=True), "threads")
        self.assertEqual(pick_backend("processes", 10, 1, 4), "processes")
        self.assertEqual(pick_backend("processes", 10, 1, 1), "threads",
                         "one worker must not pay for a child process")

    def test_unknown_backend_is_loud(self) -> None:
        with self.assertRaises(ValueError):
            pick_backend("forkserver")

    def test_threshold_matches_the_measured_break_even(self) -> None:
        self.assertFalse(would_benefit_from_processes(PROCESS_HINT_LINES - 1, 99, 8))
        self.assertFalse(would_benefit_from_processes(99999, PROCESS_HINT_FILES - 1, 8))
        self.assertFalse(would_benefit_from_processes(99999, 99, 1), "1 worker cannot parallelise")
        self.assertTrue(would_benefit_from_processes(PROCESS_HINT_LINES, PROCESS_HINT_FILES, 2))

    def test_shard_worker_is_picklable(self) -> None:
        """The process backend dies if the worker callable or its args cannot be pickled."""
        import pickle

        from solguardian.agents.orchestrator import _scan_shard

        self.assertIn(b"_scan_shard", pickle.dumps(_scan_shard))
        files = build_target(SAMPLES).files
        payload = pickle.loads(pickle.dumps((EvmHunter, "evm-hunter#1", files[:1])))
        cls, name, unpickled = payload
        self.assertEqual(cls, EvmHunter)
        self.assertEqual(name, "evm-hunter#1")
        self.assertEqual([f.rel for f in unpickled], [f.rel for f in files[:1]])
        # and running the unpickled shard must reproduce the in-process result
        from solguardian.core.source import SourceFile  # noqa: F401  (pickle dependency)

        direct = EvmHunter(None, name="evm-hunter#1").run(files[:1])
        through_pickle = _scan_shard(*pickle.loads(pickle.dumps((EvmHunter, "evm-hunter#1",
                                                                files[:1]))))
        self.assertEqual([(f.rule, f.file, f.line) for f in direct.findings],
                         [(f.rule, f.file, f.line) for f in through_pickle.findings])


if __name__ == "__main__":
    unittest.main(verbosity=2)
