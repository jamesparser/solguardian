"""Run the hunters in parallel, adjudicate, then hand off to the report writer.

This mirrors the Bob IDE task shape: one orchestrator, several specialist subagents working at
the same time, a cross-check pass, and one writer that turns the result into the deliverable.

Two levels of concurrency:

* **across ecosystems** - `evm-hunter` and `solana-hunter` never share state, so they always
  run side by side;
* **within an ecosystem** - a Solidity repo's files are split into shards by source size
  (largest-first bin packing, so shards finish together) and one worker runs per shard.

A 40-contract monorepo therefore gets 40x more parallelism than a two-agent pipeline would,
and `--workers 1` gives you the exact serial path back for debugging.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..core.detector import all_detectors
from ..core.finding import Finding, Severity
from ..core.scanner import ScanResult, dedupe, finalize
from ..core.source import SourceFile, Target, detect_chain
from .adjudicator import Adjudicator
from .base import Agent, AgentResult
from .evm_hunter import EvmHunter
from .pool import describe, make_executor, pick_backend, would_benefit_from_processes
from .report_writer import ReportWriter
from .solana_hunter import SolanaHunter


def _scan_shard(cls: type, name: str, files: List[SourceFile]) -> AgentResult:
    """Module-level worker so a shard can run in a *process* as well as a thread.

    ProcessPoolExecutor has to pickle the callable, and a bound method or lambda cannot be
    pickled - this can. It rebuilds its own detector instances, which is why agents hold no
    shared mutable state.
    """
    return cls(None, name=name).run(files)


@dataclass
class AgentSpec:
    """A named worker: which specialist class, which files, under what label."""

    cls: type
    name: str
    files: List[SourceFile]

    @property
    def language(self) -> str:
        return self.cls.language  # type: ignore[attr-defined]

    def build(self, detectors) -> Agent:
        return self.cls(detectors, name=self.name)


@dataclass
class RunSummary:
    findings: List[Finding] = field(default_factory=list)
    agents: List[AgentResult] = field(default_factory=list)
    duration_ms: int = 0
    files: int = 0
    lines: int = 0
    detectors: int = 0
    workers: int = 1
    target: Optional[Target] = None

    def scan_result(self) -> ScanResult:
        """Return the same object `scan()` produces, so the reporters never need to know
        whether the work ran through one agent or forty."""
        if self.target is None:  # pragma: no cover - run_pipeline always sets it
            raise RuntimeError("RunSummary has no target; build it with run_pipeline()")
        return ScanResult(
            target=self.target,
            findings=self.findings,
            detectors_run=[d.id for d in all_detectors()],
            duration_ms=self.duration_ms,
            agents=self.agents,
            workers=self.workers,
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "files_scanned": self.files,
            "lines_scanned": self.lines,
            "detectors_available": self.detectors,
            "parallel_workers": self.workers,
            "duration_ms": self.duration_ms,
            "findings_total": len(self.findings),
            "by_severity": {s.value: sum(1 for f in self.findings if f.severity is s)
                            for s in Severity.ordered()},
            "by_chain": _by_chain(self.findings),
            "agents": [a.to_dict() for a in self.agents],
        }


def _by_chain(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        key = f.chain or "unknown"
        out[key] = out.get(key, 0) + 1
    return out


def resolve_workers(requested: Optional[int], relevant_files: int) -> int:
    """Clamp the user's ask to something useful: [1, files, CPU count]."""
    if requested is None:
        requested = (os.cpu_count() or 2)
    ceiling = max(1, min(relevant_files or 1, max(2, (os.cpu_count() or 2))))
    return max(1, min(int(requested), ceiling))


def shard_files(files: List[SourceFile], workers: int) -> List[List[SourceFile]]:
    """Largest-first bin packing so every shard ends with a similar amount of source.

    Naive round-robin over 40 files where one is a 6,000-line megasol means one worker runs
    long after the other three have gone idle; sorting by line count before distributing keeps
    the tail short, which is the whole point of running them concurrently.
    """
    if workers <= 1 or len(files) <= 1:
        return [list(files)] if files else []
    buckets: List[List[SourceFile]] = [[] for _ in range(min(workers, len(files)))]
    loads = [0] * len(buckets)
    for f in sorted(files, key=lambda x: -len(x)):
        idx = loads.index(min(loads))
        buckets[idx].append(f)
        loads[idx] += max(len(f), 1)
    return [b for b in buckets if b]


def build_specs(target: Target, workers: int) -> List[AgentSpec]:
    """Fan the two ecosystem hunters out into N file-shards."""
    specs: List[AgentSpec] = []
    for hunter_cls in (EvmHunter, SolanaHunter):
        files = [f for f in target.files if f.language == hunter_cls.language]
        if not files:
            continue
        usable = max(1, min(workers, len(files)))
        chunks = shard_files(files, usable)
        base = hunter_cls.name
        for index, chunk in enumerate(chunks, start=1):
            name = base if len(chunks) == 1 else "%s#%d" % (base, index)
            specs.append(AgentSpec(cls=hunter_cls, name=name, files=chunk))
    return specs


def run_pipeline(
    target: Target,
    parallel: bool = True,
    verbose: bool = True,
    workers: Optional[int] = None,
    backend: str = "auto",
    allow_processes: bool = False,
) -> RunSummary:
    started = time.time()
    detectors = all_detectors()
    log = lambda msg: print(msg) if verbose else None

    active_workers = resolve_workers(workers, len(target.files)) if parallel else 1
    specs = build_specs(target, active_workers)
    backend = pick_backend(backend, target.line_count, len(target.files), len(specs),
                           allow_processes=allow_processes)
    log("[orchestrator] target=%s kind=%s files=%d lines=%d"
        % (target.root, target.kind, len(target.files), target.line_count))
    log("[orchestrator] %d agent(s) over %d ecosystem(s): %s%s"
        % (len(specs), len({s.language for s in specs}),
           ", ".join("%s[%d file(s)]" % (s.name, len(s.files)) for s in specs),
           "" if parallel else "  (serial requested)"))
    worth_forking = would_benefit_from_processes(target.line_count, len(target.files), len(specs))
    if len(specs) > 1:
        log("[orchestrator] backend: %s" % describe(backend, len(specs), hint=worth_forking))
        if backend == "threads" and worth_forking:
            log("[orchestrator] hint: %d lines over %d files - GIL contention means threads may "
                "not beat serial here; try --backend processes"
                % (target.line_count, len(target.files)))

    results: List[AgentResult] = []
    if parallel and len(specs) > 1:
        with make_executor(backend, len(specs)) as pool:
            futures = {pool.submit(_scan_shard, spec.cls, spec.name, spec.files): spec
                       for spec in specs}
            for future in as_completed(futures):
                spec = futures[future]
                res = future.result()
                results.append(res)
                for line in res.log:
                    log("[%s] %s" % (spec.name, line))
    else:
        for spec in specs:
            res = spec.build(detectors).run(spec.files)
            results.append(res)
            for line in res.log:
                log("[%s] %s" % (spec.name, line))

    findings = [f for res in results for f in res.findings]
    for f in findings:
        if not f.chain:
            f.chain = detect_chain(f.file, "")
    findings = finalize(dedupe(findings))

    adj_result = Adjudicator(detectors).run(findings)
    results.append(adj_result)
    for line in adj_result.log:
        log("[adjudicator] %s" % line)

    writer = ReportWriter(detectors)
    write_result = writer.run(findings)
    results.append(write_result)
    for line in write_result.log:
        log("[report-writer] %s" % line)

    summary = RunSummary(
        findings=findings,
        agents=results,
        duration_ms=int((time.time() - started) * 1000),
        files=len(target.files),
        lines=target.line_count,
        detectors=len(detectors),
        workers=max(1, len(specs)),
        target=target,
    )
    log("[orchestrator] done: %d finding(s) from %d agent run(s) in %d ms"
        % (len(findings), len(results), summary.duration_ms))
    return summary
