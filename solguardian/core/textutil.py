"""Source text utilities.

Every detector works on a *masked* copy of the source: comments, string literals and
char literals are replaced by spaces of identical length. That way character offsets and
line numbers stay stable while regexes cannot match inside a comment or a log message
(which would be a classic false-positive generator).
"""

from __future__ import annotations

import bisect
import re
from typing import List, Tuple


def mask_noise(text: str) -> str:
    """Blank out comments, string literals and char literals, preserving length."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            _blank(out, i, j)
            i = j
            continue
        if c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            _blank(out, i, j)
            i = j
            continue
        if c == "#" and nxt == "!":  # rust inner attribute - keep
            i += 2
            continue
        if c in "\"'":
            j = _scan_string(text, i)
            _blank(out, i, j)
            i = j
            continue
        i += 1
    return "".join(out)


def _blank(buf: List[str], start: int, end: int) -> None:
    for k in range(start, min(end, len(buf))):
        if buf[k] not in "\n":
            buf[k] = " "


def _scan_string(text: str, i: int) -> int:
    """Return index just past the string/char literal starting at i."""
    quote = text[i]
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == quote:
            return j + 1
        if quote == "'":
            # Rust lifetimes ('a, 'info) look like unterminated char literals.
            if c.isalnum() or c == "_":
                k = j + 1
                while k < n and (text[k].isalnum() or text[k] == "_"):
                    k += 1
                if k >= n or text[k] != "'":
                    return i + 1
                return k + 1
            return i + 1
        if c == "\n":
            return j  # unterminated literal, stop at newline
        j += 1
    return n


def line_offsets(text: str) -> List[int]:
    offs = [0]
    for k, ch in enumerate(text):
        if ch == "\n":
            offs.append(k + 1)
    return offs


class SourceIndex:
    """Cheap offset <-> line mapping plus snippet helpers."""

    def __init__(self, text: str) -> None:
        self.raw = text
        self.masked = mask_noise(text)
        self._offs = line_offsets(self.masked)

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self._offs, max(0, pos))

    def line_text(self, lineno: int) -> str:
        """Original (unmasked) text of a 1-indexed line."""
        if lineno < 1 or lineno > len(self._offs):
            return ""
        start = self._offs[lineno - 1]
        end = self._offs[lineno] if lineno < len(self._offs) else len(self.masked)
        return self.raw[start:end].rstrip("\n")

    def snippet(self, start_line: int, end_line: int) -> str:
        return "\n".join(
            "%4d | %s" % (ln, self.line_text(ln)) for ln in range(start_line, end_line + 1)
        )

    def line_slice(self, start_line: int, end_line: int) -> str:
        if start_line < 1 or start_line > len(self._offs):
            return ""
        start = self._offs[start_line - 1]
        end = self._offs[end_line] if end_line < len(self._offs) else len(self.masked)
        return self.masked[start:end]

    def block(self, open_idx: int) -> Tuple[int, int]:
        """Balanced `{ ... }` span starting at a char offset of `{`."""
        depth = 0
        i = open_idx
        n = len(self.masked)
        while i < n:
            c = self.masked[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return open_idx, i + 1
            i += 1
        return open_idx, n

    @property
    def line_count(self) -> int:
        return len(self._offs)


def finditer(pattern: str, masked: str, flags: int = 0):
    return re.finditer(pattern, masked, flags)
