"""The three SolGuardian subagents.

Inside IBM Bob IDE these map 1:1 to Bob's parallel subagent roles (EVM hunter, Solana
hunter, report writer). The CLI runs the same split with a thread pool so the pipeline is
identical with or without Bob, and so the demo shows real concurrency.
"""

from .base import Agent, AgentResult
from .evm_hunter import EvmHunter
from .solana_hunter import SolanaHunter
from .report_writer import ReportWriter

__all__ = ["Agent", "AgentResult", "EvmHunter", "SolanaHunter", "ReportWriter"]
