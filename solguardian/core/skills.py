"""Skill packs: the "ClawHub" idea.

Each `skills/<slug>/SKILL.md` is a verified checklist that the detector (and the human
reviewing the finding) is held to. The report quotes the skill and the checklist items
that were satisfied, which is what makes a heuristic finding defensible instead of
mysterious.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEFAULT_SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "skills")


@dataclass
class Skill:
    slug: str
    path: str          # repo-relative path used in reports
    abs_path: str
    title: str = ""
    applies_to: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    cwe: str = ""
    when_to_use: str = ""
    checklist: List[str] = field(default_factory=list)
    false_positives: str = ""
    body: str = ""

    def item(self, needle: str) -> Optional[str]:
        for entry in self.checklist:
            if needle.lower() in entry.lower():
                return entry
        return None

    def items(self, needles: List[str]) -> List[str]:
        out: List[str] = []
        for needle in needles:
            hit = self.item(needle)
            if hit and hit not in out:
                out.append(hit)
        return out


def _frontmatter(text: str) -> Dict[str, str]:
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n", text, re.S)
    if not m:
        return {}
    data: Dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data


def _section(text: str, header: str) -> str:
    m = re.search(r"^##\s*%s\s*\n(.*?)(?=^##\s|\Z)" % re.escape(header), text, re.M | re.S)
    return m.group(1).strip() if m else ""


def _checklist(text: str) -> List[str]:
    items: List[str] = []
    section = _section(text, "Checklist")
    for line in section.splitlines():
        m = re.match(r"\s*[-*\d.]+\s*(?:\[ ?x? ?\])?\s*(.+)", line)
        if m:
            items.append(re.sub(r"\s+", " ", m.group(1)).strip())
    return items


def load_skills(skills_dir: str = DEFAULT_SKILLS_DIR) -> Dict[str, Skill]:
    skills: Dict[str, Skill] = {}
    if not os.path.isdir(skills_dir):
        return skills
    for entry in sorted(os.listdir(skills_dir)):
        md = os.path.join(skills_dir, entry, "SKILL.md")
        if not os.path.isfile(md):
            continue
        with open(md, "r", encoding="utf-8") as fh:
            text = fh.read()
        fm = _frontmatter(text)
        title = ""
        m = re.search(r"^#\s+(.+)$", text, re.M)
        if m:
            title = m.group(1).strip()
        skills[entry] = Skill(
            slug=entry,
            path="skills/%s/SKILL.md" % entry,
            abs_path=md,
            title=title or entry,
            applies_to=[s.strip() for s in re.split(r"[,\[\]]", fm.get("applies_to", "")) if s.strip()],
            severities=[s.strip() for s in re.split(r"[,\[\]]", fm.get("severities", "")) if s.strip()],
            cwe=fm.get("cwe", ""),
            when_to_use=_section(text, "When to use"),
            checklist=_checklist(text),
            false_positives=_section(text, "False positives"),
            body=text,
        )
    return skills


_CACHE: Optional[Dict[str, Skill]] = None


def skills(skills_dir: str = DEFAULT_SKILLS_DIR) -> Dict[str, Skill]:
    global _CACHE
    if _CACHE is None or skills_dir != DEFAULT_SKILLS_DIR:
        _CACHE = load_skills(skills_dir)
    return _CACHE


def get(slug: str) -> Optional[Skill]:
    return skills().get(slug)


def skill_path(slug: str) -> str:
    sk = get(slug)
    return sk.path if sk else "skills/%s/SKILL.md" % slug
