#!/usr/bin/env python3
"""Fail the build if a credential-shaped string is committed.

Complements `tests/test_docs.py::TestNoSecretsTracked` (which knows the allowlist for prose that
*discusses* secrets). This script is deliberately dumber and stricter: it only matches shapes that
are never legitimate in this repository - provider tokens, private-key blocks, wallet mnemonics,
key-prefixed RPC URLs.

    python3 tools/secret_scan.py [root]
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "out", "demo", "node_modules", "__pycache__", ".pytest_cache",
             "build", "dist", "target", ".venv", "venv"}
BINARY_OK = (".png", ".jpg", ".gif", ".ico", ".pyc", ".woff", ".woff2")

PATTERNS = [
    ("github pat", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}")),
    ("github fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("openai key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("rpc provider url", re.compile(r"https?://[^\s\"']*\b(?:infura|alchemy|quicknode|moralis|ankr)\b[^\s\"']*", re.I)),
    ("solana keypair file", re.compile(r"id[_-]?json\b.*\[", re.I)),
    ("wallet mnemonic", re.compile(r"(?i)\b(?:mnemonic|seed\s+phrase|private[_ ]key)\b\s*[:=]\s*['\"]?[A-Za-z]")),
    ("bare 64-hex secret", re.compile(r"(?i)(?:secret|token|apikey|api_key)\s*[:=]\s*[\"']?[0-9a-f]{64}")),
    ("basic-auth url", re.compile(r"://[^\s/@:]+:[^\s/@]{8,}@")),
]


def scan(root: str) -> list:
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            if name.endswith(BINARY_OK):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except (UnicodeDecodeError, OSError):
                continue
            rel = os.path.relpath(path, root)
            # this file and the docs that describe what to avoid are self-referential
            if rel in ("tools/secret_scan.py", "tests/test_docs.py", "DATA_SOURCES.md"):
                continue
            for label, pattern in PATTERNS:
                for match in pattern.finditer(text):
                    line = text[: match.start()].count("\n") + 1
                    hits.append("%s:%d  %s  %s" % (rel, line, label, match.group(0)[:70]))
    return hits


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else ROOT
    hits = scan(root)
    if hits:
        for hit in hits:
            print("::error::credential-shaped string at " + hit)
        print("\n%d match(es). Remove them, rotate anything that was ever committed, and add the"
              " path to .gitignore/.bobignore if it is genuinely a local secrets file." % len(hits))
        return 1
    print("secret scan: clean (%d patterns over %s)" % (len(PATTERNS), root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
