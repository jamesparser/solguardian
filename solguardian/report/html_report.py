"""report.html - a single-file static report for the video and for GitHub Pages.

No build step, no CDN, no network: one HTML file with the findings baked in, so
`solguardian analyze --html` is enough to have something to show on camera.
"""

from __future__ import annotations

import html
import os
from typing import List, Optional

from ..core.finding import Finding, Severity
from ..core.scanner import ScanResult
from ..core.scorecard import Scorecard

STYLE = """
:root{--bg:#0b0f14;--panel:#121821;--ink:#e6edf3;--dim:#8b98a5;--crit:#ff5c5c;--high:#ff9f45;
--med:#ffd166;--low:#7bd88f;--info:#6cb6ff;--line:#232c38}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
header{padding:28px 32px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#0e141c,#0b0f14)}
h1{margin:0 0 6px;font-size:22px;letter-spacing:.3px}h1 span{color:var(--info)}
.sub{color:var(--dim);font-size:13px}main{padding:24px 32px;max-width:1180px;margin:0 auto}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0 26px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 18px;min-width:150px}
.kpi b{display:block;font-size:26px;line-height:1.1}.kpi small{color:var(--dim)}
table{width:100%;border-collapse:collapse;margin:10px 0 28px;font-size:14px}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700;
text-transform:capitalize;border:1px solid}
.critical{color:var(--crit);border-color:var(--crit)}.high{color:var(--high);border-color:var(--high)}
.medium{color:var(--med);border-color:var(--med)}.low{color:var(--low);border-color:var(--low)}
.info{color:var(--info);border-color:var(--info)}
details{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:0 0 12px;padding:0 16px}
summary{cursor:pointer;padding:14px 0;font-weight:600;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.loc{color:var(--dim);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
pre{background:#0a0e13;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12.5px}
ol li,ul li{margin:3px 0}.note{color:var(--dim);font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:900px){.grid{grid-template-columns:1fr}}
footer{padding:22px 32px;border-top:1px solid var(--line);color:var(--dim);font-size:12.5px}
a{color:var(--info)}
"""


def build(result: ScanResult, scorecard: Optional[Scorecard] = None, target_arg: str = "") -> str:
    findings: List[Finding] = result.findings
    esc = html.escape
    out: List[str] = []
    out.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    out.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    out.append("<title>SolGuardian report &middot; %s</title>" % esc(os.path.basename(target_arg or result.target.root)))
    out.append("<style>%s</style></head><body>" % STYLE)
    out.append("<header><h1>Sol<span>Guardian</span> &mdash; exploit hunt report</h1>"
               "<div class='sub'>target <code>%s</code> &middot; %d file(s) &middot; %d lines &middot; "
               "%d detectors &middot; %.2fs &middot; static heuristics, offline</div></header>"
               % (esc(target_arg or result.target.root), len(result.target.files), result.target.line_count,
                  len(set(result.detectors_run)), result.duration_ms / 1000.0))
    out.append("<main>")

    counts = {s: sum(1 for f in findings if f.severity is s) for s in Severity.ordered()}
    out.append("<div class='kpis'>")
    out.append("<div class='kpi'><b>%d</b><small>findings</small></div>" % len(findings))
    for s in Severity.ordered():
        if counts[s]:
            out.append("<div class='kpi'><b class='%s'>%d</b><small>%s</small></div>" % (s.value, counts[s], s.value))
    if scorecard is not None:
        out.append("<div class='kpi'><b>%.0f%%</b><small>seeded recall (%d/%d)</small></div>"
                   % (100 * scorecard.recall, len(scorecard.caught), len(scorecard.seeded)))
    corroborated = sum(1 for f in findings if f.corroborated_by)
    if corroborated:
        out.append("<div class='kpi'><b>%d</b><small>corroborated by a 2nd detector</small></div>"
                   % corroborated)
    agents = getattr(result, "agents", []) or []
    if agents:
        out.append("<div class='kpi'><b>%d</b><small>agent runs (%d sharded hunters)</small></div>"
                   % (len(agents), len([a for a in agents if "hunter" in a.agent])))
    out.append("</div>")

    if agents:
        out.append("<h3>Agent pipeline</h3><table><tr><th>agent</th><th>role</th>"
                   "<th>files</th><th>findings</th><th>ms</th></tr>")
        for a in agents:
            role = ("scan shard (parallel)" if "hunter" in a.agent
                    else "cross-check / corroboration" if a.agent == "adjudicator"
                    else "output-contract gate")
            out.append("<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                       % (esc(a.agent), role, a.files_scanned or "-",
                          len(a.findings) if a.findings else "-", a.duration_ms))
        out.append("</table><p class='note'>The adjudicator records where independent detectors "
                   "agree; it is annotation-only and cannot change a severity or confidence.</p>")

    if scorecard is not None:
        out.append("<h3>Ground truth</h3><table><tr><th>seeded issue</th><th>caught</th><th>rule</th>"
                   "<th>detector</th><th>severity</th></tr>")
        for entry in scorecard.to_dict()["detail"]:
            out.append("<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s / %s</td></tr>" % (
                esc(entry["key"]),
                "yes" if entry["caught"] else "<b>MISSED</b>",
                esc(entry["rule"] or "-"),
                esc(entry["detector"] or "-"),
                esc(entry["severity_expected"]),
                esc(entry["severity_found"] or "-"),
            ))
        out.append("</table>")

    out.append("<h3>Ranked findings</h3><table><tr><th>#</th><th>id</th><th>sev</th><th>conf</th>"
               "<th>rule</th><th>location</th><th>title</th></tr>")
    for i, f in enumerate(findings, start=1):
        out.append("<tr><td>%d</td><td><code>%s</code></td><td><span class='badge %s'>%s</span></td>"
                   "<td>%.2f</td><td>%s</td><td class='loc'>%s</td><td><a href='#%s'>%s</a></td></tr>"
                   % (i, esc(f.id), f.severity.value, f.severity.value, f.confidence, esc(f.rule),
                      esc("%s:%d%s" % (os.path.basename(f.file), f.line, (" %s()" % f.function) if f.function else "")),
                      esc(f.id), esc(f.title)))
    out.append("</table><h3>Detail</h3>")

    for f in findings:
        out.append("<details id='%s'><summary><span class='badge %s'>%s</span> <span>%s</span> "
                   "<span class='loc'>%s</span> <span class='note'>conf %.2f &middot; %s &middot; %s</span></summary>"
                   % (esc(f.id), f.severity.value, f.severity.value, esc(f.title), esc(f.location),
                      f.confidence, esc(f.rule), esc(f.chain or "-")))
        out.append("<p>%s</p>" % esc(f.description).replace("\n", "<br>"))
        if f.corroborated_by:
            out.append("<p class='note'>corroborated independently by %d other detector(s), "
                       "%d rule(s): %s <span class='note'>(annotation only &mdash; does not "
                       "change this grade)</span></p>"
                       % (f.independent_confirmation, len(f.corroborated_by),
                          ", ".join("<code>%s</code>" % esc(c) for c in f.corroborated_by)))
        out.append("<pre>%s</pre>" % esc(f.evidence or "(see location)"))
        out.append("<div class='grid'>")
        out.append("<div><b>Exploit sketch (educational)</b><ol>%s</ol></div>"
                   % "".join("<li>%s</li>" % esc(s) for s in f.exploit_sketch))
        out.append("<div><b>Patch sketch</b><ul>%s</ul>%s</div>"
                   % ("".join("<li>%s</li>" % esc(p) for p in f.patch_sketch),
                      ("<p class='note'>PoC stub: <code>%s</code><br>run: <code>%s</code></p>"
                       % (esc(f.poc.filename), esc(f.poc.how_to_run))) if f.poc else ""))
        out.append("</div>")
        if f.checklist:
            out.append("<p class='note'>skill <code>%s</code> checklist satisfied:</p><ul>%s</ul>"
                       % (esc(f.skill), "".join("<li>%s</li>" % esc(c) for c in f.checklist)))
        out.append("</details>")

    out.append("<p class='note'>Heuristic static analysis: findings below 0.6 confidence are review "
               "prompts, not verdicts. PoC files are commented skeletons against synthetic samples; "
               "no live exploit code is emitted. The adjudicator records detector agreement but is "
               "annotation-only: it never raises a severity or a confidence, and sites where "
               "detectors disagree stay as separate findings rather than being averaged.</p>")
    out.append("</main><footer>SolGuardian &middot; Jason Parser Research &middot; built with IBM Bob 2.0 "
               "&middot; <a href='https://github.com/jamesparser/solguardian'>source</a></footer>")
    out.append("</body></html>")
    return "\n".join(out)


def write(result: ScanResult, out_path: str, scorecard: Optional[Scorecard] = None, target_arg: str = "") -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(build(result, scorecard, target_arg))
    return out_path
