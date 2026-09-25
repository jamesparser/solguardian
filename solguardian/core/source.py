"""Target discovery: what SolGuardian is allowed to look at.

Everything is read from the local filesystem only. No RPC, no explorer, no network.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .textutil import SourceIndex

SOLIDITY_EXT = {".sol"}
RUST_EXT = {".rs"}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    "out",
    ".bob",
    ".idea",
    "generated",
    "test/fuzz",
}


@dataclass
class SourceFile:
    path: str            # absolute path on disk
    rel: str             # path relative to the analysis root
    language: str        # "solidity" | "rust"
    index: SourceIndex
    notes: List[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.index.raw

    @property
    def masked(self) -> str:
        return self.index.masked

    def line_text(self, lineno: int) -> str:
        return self.index.line_text(lineno)

    def __len__(self) -> int:
        return self.index.line_count


@dataclass
class Target:
    root: str
    files: List[SourceFile] = field(default_factory=list)
    kind: str = "mixed"     # "evm" | "solana" | "mixed" | "empty"
    notes: List[str] = field(default_factory=list)

    def by_language(self, language: str) -> Iterable[SourceFile]:
        return [f for f in self.files if f.language == language]

    @property
    def line_count(self) -> int:
        return sum(len(f) for f in self.files)


def _classify(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in SOLIDITY_EXT:
        return "solidity"
    if ext in RUST_EXT:
        return "rust"
    return ""


def _collect(root: str) -> List[str]:
    found: List[str] = []
    if os.path.isfile(root):
        return [root]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
        )
        for name in sorted(filenames):
            if _classify(name):
                found.append(os.path.join(dirpath, name))
    return found


def build_target(path: str) -> Target:
    """Load every .sol / .rs under `path` (or the single file)."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise SystemExit("solguardian: path does not exist: %s" % path)

    root = path if os.path.isdir(path) else os.path.dirname(path)
    files: List[SourceFile] = []
    for abs_path in _collect(path):
        language = _classify(abs_path)
        if not language:
            continue
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(abs_path, root if os.path.isdir(path) else os.path.dirname(root))
        files.append(SourceFile(path=abs_path, rel=rel.replace(os.sep, "/"), language=language,
                                index=SourceIndex(text)))

    langs = {f.language for f in files}
    if langs == {"solidity"}:
        kind = "evm"
    elif langs == {"rust"}:
        kind = "solana"
    elif langs:
        kind = "mixed"
    else:
        kind = "empty"
    return Target(root=root, files=files, kind=kind)


def detect_chain(rel_path: str, text: str) -> str:
    """Best-effort chain tag so HyperEVM targets read differently in the report."""
    low = (rel_path + "\n" + text).lower()
    if "hyperevm" in low or "hyperliquid" in low or "hyper-core" in low or "hyperchain" in low:
        return "hyperevm"
    if rel_path.endswith(".rs"):
        return "solana"
    return "evm"
