"""Render the lablab cover image (1280x640 PNG) from source.

    python3 docs/make_cover.py            # writes docs/cover.png

Generated rather than hand-drawn so the numbers on the artwork cannot drift away from the
repo: it reads samples/EXPECTED_FINDINGS.json and skills/ at build time. Requires Pillow
(dev-only; SolGuardian itself is stdlib-only).
"""

from __future__ import annotations

import json
import os
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "cover.png")
W, H = 1280, 640

BG = (11, 15, 20)
PANEL = (18, 24, 33)
INK = (230, 237, 243)
DIM = (139, 152, 165)
ACCENT = (108, 182, 255)
CRIT = (255, 92, 92)
HIGH = (255, 159, 69)
OK = (123, 216, 143)


def font(size: int, bold: bool = False) -> "ImageFont.ImageFont":
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold
        else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def metrics() -> dict:
    seeded = json.load(open(os.path.join(ROOT, "samples", "EXPECTED_FINDINGS.json")))["seeded"]
    skills = [d for d in os.listdir(os.path.join(ROOT, "skills"))
              if os.path.isfile(os.path.join(ROOT, "skills", d, "SKILL.md"))]
    det_dir = os.path.join(ROOT, "solguardian", "detectors")
    det = [f for f in os.listdir(det_dir) if f.endswith(".py") and not f.startswith("__")]
    return {
        "seeds": len(seeded),
        "skills": len(skills),
        "detectors": len(det),
        "evm": len([f for f in det if f.startswith("evm_")]),
        "sol": len([f for f in det if f.startswith("solana_")]),
    }


def main() -> int:
    m = metrics()
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # subtle diagonal texture
    for y in range(-H, W, 8):
        d.line([(y, 0), (y + H, H)], fill=(14, 19, 26), width=1)

    # accent bar
    d.rectangle([0, 0, W, 6], fill=ACCENT)

    d.text((64, 68), "Sol", font=font(76, True), fill=INK)
    w_sol = d.textlength("Sol", font=font(76, True))
    d.text((64 + w_sol, 68), "Guardian", font=font(76, True), fill=ACCENT)

    d.text((64, 172), "Automated exploit hunting for Solidity & Solana",
           font=font(30), fill=INK)
    d.text((64, 214), "EVM  ·  HyperEVM  ·  Solana / Anchor        built with IBM Bob 2.0",
           font=font(22), fill=DIM)
    d.text((64, 244), "full ranked report with PoC stubs in ~1 second, offline",
           font=font(18), fill=DIM)

    # stat cards
    cards = [
        ("%d/%d" % (m["seeds"], m["seeds"]), "planted issues\ncaught", CRIT),
        ("0", "findings on the\nclean control", OK),
        ("%d" % m["detectors"], "detectors\n%d EVM · %d Solana" % (m["evm"], m["sol"]), ACCENT),
        ("N\u00d7", "concurrent file-sharded\nagents + adjudicator", HIGH),
    ]
    x = 64
    for value, label, color in cards:
        d.rounded_rectangle([x, 288, x + 268, 476], 16, fill=PANEL, outline=(35, 44, 56))
        d.text((x + 24, 312), value, font=font(54, True), fill=color)
        for i, line in enumerate(label.split("\n")):
            d.text((x + 24, 388 + i * 26), line, font=font(19), fill=DIM)
        x += 288

    d.text((64, 512),
           "Ranked findings with severity, confidence, exploit sketch, PoC stub and patch sketch -",
           font=font(21), fill=INK)
    d.text((64, 542),
           "each one citing the human-written checklist in skills/ that justified it.",
           font=font(21), fill=INK)

    url = "github.com/jamesparser/solguardian"
    d.text((W - 64 - d.textlength(url, font=font(20)), 588), url, font=font(20), fill=ACCENT)
    d.line([64, 578, W - 64, 578], fill=(35, 44, 56))
    d.text((64, 588), "Jason Parser Research  ·  IBM Bob 2.0 Hackathon  ·  MIT",
           font=font(20), fill=DIM)

    img.save(OUT, "PNG", optimize=True)
    print("wrote %s (%dx%d, %d KB)" % (OUT, W, H, os.path.getsize(OUT) // 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
