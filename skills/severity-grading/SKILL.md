---
id: severity-grading
applies_to: evm, hyperevm, solana
severities: critical, high, medium, low, info
cwe: n/a
detector: solguardian/core/scanner.py (ranking) + every detector's default grade
---

# Severity & confidence grading

## When to use
Always. This pack is the contract that makes two findings comparable and the ranking honest.

## Checklist
1. Grade on **impact x reachability**: can an unprivileged caller reach it in one transaction,
   and does it move value or break the protocol's accounting?
2. **critical** = funds lost or permanently controllable by anyone (unauthenticated drain/mint,
   caller-controlled delegatecall, unsigned authority over value, unbounded signature replay,
   reachable selfdestruct).
3. **high** = the attacker needs one precondition (stale/unvalidated oracle, ignored return value
   that changes accounting, precision loss on the main deposit path, `tx.origin` auth).
4. **medium** = design-level gaps with a realistic but indirect path (no deadline, missing
   `has_one`, unvalidated `remaining_accounts`, no withdrawal path for accumulated value).
5. **low/info** = availability, lint-adjacent, or a manual-review pointer with no proof.
6. Confidence is separate from severity: it is the probability the pattern is genuinely wrong.
   Never inflate confidence because severity is high.
7. Anything below **0.6** confidence is a review prompt and must be labelled as such.
8. Rank score = `severity_weight * (0.6 + 0.4 * confidence)`; ties break on file/line so the
   report is reproducible run to run.
9. Deduplicate by (file, line, rule family), keeping the most severe - one line, one finding.
10. Every graded finding must cite a skill pack; un-citable findings are dropped.
11. Weights: critical 9.0, high 6.5, medium 4.0, low 2.0, info 0.5.

## Severity guidance
Report the distribution next to the count. "27 findings" means nothing; "3 critical, all
reachable by anyone" is a decision.

## False positives
- Guarded-by-design patterns a regex cannot see (a modifier implemented as an internal
  `_check*` call): lower confidence, do not silently drop the finding.
- Two rules firing on one root cause: keep the more specific rule.

## Required output fields
`severity` (enum), `confidence` (0..1), `score` (rank key) on every finding.
