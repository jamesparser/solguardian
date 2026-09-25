"""Backend selection for the agent pool.

Shards always run concurrently; this module decides *how*.

**threads** (the default) are cheap to start, share the parsed-source cache, and are safe no
matter how the caller's process is structured. Because scanning is CPU-bound regex work under
CPython's GIL, threads overlap waiting and parsing well but do not scale linearly on big repos.

**processes** do remove the GIL and are genuinely faster on a monorepo, but they are opt-in only,
for two reasons that bit us during development:

1. on macOS and Windows the default start method is `spawn`, which re-imports the caller's
   `__main__` module in every child. A script that calls `run_pipeline()` without an
   `if __name__ == "__main__":` guard would therefore recurse into process-spawning processes.
2. each child pays import + pickling cost, so on a 3-file repo processes are *slower* than
   threads.

`auto` therefore resolves to `threads`, and prints a hint when the corpus is large enough that
`--backend processes` would probably pay off.
"""

from __future__ import annotations

import os
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor

#: rough break-even: below this, child startup costs more than the GIL saves
PROCESS_HINT_LINES = 2400
PROCESS_HINT_FILES = 4

RESOLVED = "threads"


def pick_backend(backend: str, total_lines: int = 0, file_count: int = 0, workers: int = 1,
                 allow_processes: bool = False) -> str:
    """Resolve the requested backend.

    `auto` upgrades to processes only when `allow_processes` is set - which the CLI does, because
    `python -m solguardian` runs through a `__main__` guard and is therefore safe under `spawn`.
    A library caller that passes `allow_processes=False` keeps the conservative, always-safe
    thread backend.
    """
    if backend in (None, "", "auto"):
        if allow_processes and would_benefit_from_processes(total_lines, file_count, workers):
            return "processes"
        return "threads"
    if backend == "threads":
        return "threads"
    if backend == "processes":
        # a single worker gains nothing from a child process
        return "processes" if workers > 1 else "threads"
    raise ValueError("unknown backend %r (use auto|threads|processes)" % backend)


def would_benefit_from_processes(total_lines: int, file_count: int, workers: int) -> bool:
    return (workers > 1
            and total_lines >= PROCESS_HINT_LINES
            and file_count >= PROCESS_HINT_FILES)


def make_executor(backend: str, max_workers: int) -> Executor:
    if backend == "processes" and max_workers > 1:
        return ProcessPoolExecutor(max_workers=max_workers)
    return ThreadPoolExecutor(max_workers=max_workers)


def describe(backend: str, workers: int, hint: bool = False) -> str:
    cpus = os.cpu_count() or 1
    note = ""
    if backend == "threads" and hint:
        note = "  [GIL-bound: --backend processes would scale better]"
    return "%s x %d worker(s), host has %d cpu core(s)%s" % (backend, workers, cpus, note)
