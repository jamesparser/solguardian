"""Detector registry.

Importing this package registers every detector. `core.detector.all_detectors()` is the
single source of truth the CLI, the agents and the tests use.
"""

from __future__ import annotations

from . import (  # noqa: F401  (import order = registry order)
    evm_access,
    evm_delegatecall,
    evm_external_calls,
    evm_oracle,
    evm_reentrancy,
    evm_selfdestruct,
    evm_sig_replay,
    solana_accounts,
    solana_authority,
    solana_cpi,
    solana_deser,
    solana_math,
    solana_signer,
)
from ..core.detector import all_detectors, detectors_for  # noqa: F401

__all__ = ["all_detectors", "detectors_for"]
