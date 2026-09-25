"""EVM / Solidity hunter subagent."""

from __future__ import annotations

from .base import Agent


class EvmHunter(Agent):
    name = "evm-hunter"
    language = "solidity"
    detector_ids = [
        "evm_reentrancy",
        "evm_access",
        "evm_external_calls",
        "evm_delegatecall",
        "evm_oracle",
        "evm_sig_replay",
        "evm_selfdestruct",
    ]
