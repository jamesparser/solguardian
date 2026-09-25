"""Solana / Anchor hunter subagent."""

from __future__ import annotations

from .base import Agent


class SolanaHunter(Agent):
    name = "solana-hunter"
    language = "rust"
    detector_ids = [
        "solana_signer",
        "solana_accounts",
        "solana_cpi",
        "solana_math",
        "solana_authority",
        "solana_deser",
    ]
