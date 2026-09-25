"""EVM detector: price-oracle assumptions.

Rules:
  OR-001 AMM spot price (in-pool reserves) used as the valuation source
  OR-002 Chainlink-style round read without staleness / round-integrity checks
  OR-003 single-source oracle in a value-deciding path (no deviation / second source)
  OR-004 block.timestamp / block.number used as a price window

Skill: skills/oracle-price/SKILL.md
"""

from __future__ import annotations

import re
from typing import List, Optional

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.solidity import SolFunction
from ..core.source import SourceFile, detect_chain

RESERVES = re.compile(r"\.getReserves\s*\(|\bgetAmountsFor\s*\(|\bquote\s*\([^)]*\)\s*/")
ROUND_READ = re.compile(r"\.latestRoundData\s*\(|\.latestAnswer\s*\(|\.getLatestData\s*\(")
STALENESS = re.compile(r"\bupdatedAt\b|\bstartedAt\b|\bansweredInRound\b|\broundId\b|\bobservationTimestamp\b")
TIMESTAMP_WINDOW = re.compile(r"\bblock\.timestamp\b.*(/|\*|<=|>=|-)\s*\w+|(?<=[\w\)\s])\bblock\.number\b\s*[-/*]")
PRICE_FN_HINT = re.compile(r"(price|value|valuation|equivalent|worth|collateral|health|liquidat|buy|mint|redeem)", re.I)
SECOND_SOURCE = re.compile(r"(median| TWAP|twap|checkpoint|deviation|Chainlink|feed2|secondFeed|crossCheck|VWAP)", re.I)

CHAINLINK_SIG = re.compile(
    r"\(\s*(?:uint80|,)\s*\w*\s*,\s*int256\s*\w*\s*,[^;]*\)\s*=\s*[A-Za-z_$][\w$.]*\.latestRoundData\s*\(\s*\)"
)


@register
class EvmOracleDetector(Detector):
    id = "evm_oracle"
    label = "Oracle / price assumptions"
    language = "solidity"
    skill = "oracle-price"
    cwe = "CWE-1231"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import solidity

        src = solidity.parse(file.rel, file.index)
        chain = detect_chain(file.rel, file.text)
        findings: List[dict] = []
        feeds = len(set(re.findall(r"\b(?:priceFeed|oracle|aggregator|Feed)\w*\b", src.index.masked)))

        def owner_fn(pos: int) -> Optional[SolFunction]:
            for fn in src.functions:
                if fn.has_body and fn.body_start <= pos < fn.body_end:
                    return fn
            return None

        def valuer(fn: Optional[SolFunction]) -> bool:
            if fn is None:
                return False
            return bool(PRICE_FN_HINT.search(fn.name) or re.search(r"\breturn\b[^;]*price", fn.body))

        for fn in src.functions:
            if not fn.has_body:
                continue
            body = fn.body

            # --- OR-001: AMM spot reserves -----------------------------------
            m = RESERVES.search(body)
            if m:
                line = src.index.line_of(fn.body_start + m.start())
                severity = Severity.CRITICAL if valuer(fn) else Severity.HIGH
                findings.append(
                    self.make(
                        file,
                        rule="OR-001",
                        title="AMM spot price used as valuation in %s()" % fn.name,
                        severity=severity,
                        confidence=0.88,
                        line=line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() derives a price from in-pool reserves (`getReserves`), which is the pool's own "
                            "balance ratio rather than a traded price. Any caller with enough capital - typically a "
                            "flash loan - can skew that ratio in a single transaction, and the contract will read the "
                            "manipulated number in the same block. There is no time-weighting and no second source here."
                            % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Flash-loan a large amount of one side of the pool.",
                            "Swap it into the pool to move reserves (and therefore the printed price) in the same tx.",
                            "Call %s() - the inflated price is now the contract's truth - then mint/borrow/liquidate." % fn.name,
                            "Swap back and repay the loan; the profit is the difference in the contract's accounting.",
                        ],
                        patch=[
                            "Use a time-weighted price (Chainlink TWAP or a multi-block Uniswap V2 `cumulativePrice` window).",
                            "Never let an in-block reserve ratio set collateral or payout values.",
                            "Add a max-deviation guard against a second source and reject out-of-band prints.",
                        ],
                        checklist_needles=["spot", "twap", "flash", "deviation"],
                        tags=["oracle", "price-manipulation", "flash-loan"],
                    )
                )

            # --- OR-002: round read without integrity checks ------------------
            if ROUND_READ.search(body) and not STALENESS.search(body):
                m2 = ROUND_READ.search(body)
                line = src.index.line_of(fn.body_start + m2.start())
                findings.append(
                    self.make(
                        file,
                        rule="OR-002",
                        title="Oracle round read without staleness/round checks in %s()" % fn.name,
                        severity=Severity.HIGH,
                        confidence=0.82,
                        line=line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() takes the answer from `latestRoundData()` but never inspects `updatedAt`, "
                            "`startedAt`, `answeredInRound` or `roundId`. A stale round, a round still in progress, or "
                            "a negative/zero answer therefore passes straight through, and the contract keeps pricing "
                            "off a print that may be hours old. The `require(answer > 0)` guard alone is not a freshness check."
                            % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Wait for the feed to stop updating (heartbeat exceeded) during volatility, or during a "
                            "keeper outage.",
                            "Trade the underlying asset so the market moves while the contract still uses the old print.",
                            "Borrow/liquidate against the stale valuation.",
                        ],
                        patch=[
                            "Require `updatedAt != 0 && block.timestamp - updatedAt <= MAX_STALENESS_SECONDS`.",
                            "Require `answeredInRound >= roundId` and `answer > 0`.",
                            "Fall back to a second feed (or pause) when the check fails.",
                        ],
                        checklist_needles=["staleness", "updatedAt", "fallback"],
                        tags=["oracle", "staleness"],
                    )
                )

            # --- OR-003: single source in a value path ------------------------
            single = re.search(r"\b([A-Za-z_$][\w$]*)\s*\.\s*(spotPrice|getPrice|getPriceOfAsset|price)\s*\(", body)
            if single and valuer(fn) and not SECOND_SOURCE.search(body):
                line = src.index.line_of(fn.body_start + single.start())
                findings.append(
                    self.make(
                        file,
                        rule="OR-003",
                        title="Single-source price %s.%s() decides value in %s()"
                        % (single.group(1), single.group(2), fn.name),
                        severity=Severity.HIGH if chain != "hyperevm" else Severity.MEDIUM,
                        confidence=0.65,
                        line=line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() trusts one oracle call (%s.%s) for a value-deciding calculation, with no deviation "
                            "check, no second source and no circuit breaker.%s If that single print is wrong - manipulated, "
                            "stale, or a different asset's unit - every dependent decision is wrong in the same direction."
                            % (
                                fn.name,
                                single.group(1),
                                single.group(2),
                                "On HyperEVM the HyperCore spot read is itself a consensus input, so treat unit/exponent "
                                "mismatches and asset-alias confusion as the realistic failure mode."
                                if chain == "hyperevm"
                                else "",
                            )
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Identify the oracle's own trust path (a small set of attesters, a single pair, a low-liquidity venue).",
                            "Move or misreport that one input.",
                            "Call the value-deciding entry point while the whole system believes the bad number.",
                        ],
                        patch=[
                            "Cross-check a second independent source and revert if they differ by more than a threshold.",
                            "Validate the returned exponent/units before using the number.",
                            "Add a per-block max-move (circuit breaker) and an explicit pause role.",
                        ],
                        checklist_needles=["second source", "deviation", "units"],
                        tags=["oracle", "single-source"],
                    )
                )

            # --- OR-004: block.timestamp as a price window --------------------
            if TIMESTAMP_WINDOW.search(body) and valuer(fn):
                m3 = TIMESTAMP_WINDOW.search(body)
                line = src.index.line_of(fn.body_start + m3.start())
                findings.append(
                    self.make(
                        file,
                        rule="OR-004",
                        title="Block timestamp used as a pricing window in %s()" % fn.name,
                        severity=Severity.LOW,
                        confidence=0.45,
                        line=line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() uses block.timestamp/block.number arithmetic in a value path. Miners/validators and "
                            "searchers have limited but real control over inclusion timing, and on instant-finality chains "
                            "the same-block grouping still makes `timestamp` a coarse, manipulable boundary."
                            % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Time your transaction so the window boundary favours you (last block of the window).",
                            "Combine with a spot-price read for a same-block advantage.",
                        ],
                        patch=[
                            "Use an explicit oracle round/timestamp, not the block clock, for valuation boundaries.",
                            "If a clock is needed for time locks, document the acceptable skew (<= 15s is the usual bar).",
                        ],
                        checklist_needles=["timestamp", "window"],
                        tags=["oracle", "timestamp"],
                    )
                )

        return findings
