"""Precision guardrails.

`samples/clean/` is a **negative control**: the same contract shapes as the seeded samples
(deposit / withdraw / rewards / admin knob / SPL CPI / settle), written with the validation
actually present. If a rule change starts calling that code critical or high, the rule got
worse - fix the rule, do not relax this test.

Two more guardrails live in test_solguardian.TestGroundTruth (specific historical false
positives). This file owns the whole-file precision claim and the pattern-level ones.
"""

from __future__ import annotations

import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys  # noqa: E402

sys.path.insert(0, ROOT)

from solguardian.core.finding import Severity  # noqa: E402
from solguardian.core.scanner import scan  # noqa: E402
from solguardian.core.source import build_target  # noqa: E402

CLEAN = os.path.join(ROOT, "samples", "clean")


def _scan(path: str):
    return scan(build_target(path))


def _write(tmpdir: str, name: str, body: str):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


class TestCleanControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = _scan(CLEAN)

    def test_no_critical_or_high_on_correct_code(self) -> None:
        bad = [
            "%s %s (%s:%d)" % (f.severity.value, f.rule, f.file, f.line)
            for f in self.result.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        self.assertFalse(bad, "correct code flagged critical/high: %s" % ", ".join(bad))

    def test_informational_notes_are_low_confidence(self) -> None:
        """Anything left on the clean control must be labelled as a prompt, not a verdict."""
        for f in self.result.findings:
            with self.subTest(finding="%s %s" % (f.rule, f.file)):
                self.assertLessEqual(
                    f.confidence, 0.7,
                    "clean-control finding %s (%s) carries confidence %.2f - too confident"
                    % (f.rule, f.title, f.confidence),
                )

    def test_recall_is_untouched_by_the_precision_fixes(self) -> None:
        """The guard must not be bought by muting detectors: the seeded set stays 100%."""
        import json

        from solguardian.core.scorecard import load_expectations, score

        seeded_set = _scan(os.path.join(ROOT, "samples"))
        # the clean files add 0 seeds, so recall over samples/ must still be perfect
        card = score(
            seeded_set.findings,
            load_expectations(os.path.join(ROOT, "samples", "EXPECTED_FINDINGS.json")),
        )
        self.assertEqual(len(card.missed), 0, "missed: %s" % [m.key for m in card.missed])
        self.assertEqual(card.recall, 1.0)
        self.assertLess(len(self.result.findings), len(seeded_set.findings) // 5)
        del json


class TestPatternGuardrails(unittest.TestCase):
    """Micro-regressions: each snippet is correct code that an early draft flagged."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="sg-fp-")

    def _rules(self, name: str, body: str):
        _write(self.tmp, name, body)
        result = _scan(self.tmp)
        return {"%s:%s" % (f.rule, f.line): f.title for f in result.findings}, result

    def test_pull_payment_withdraw_is_not_a_drain(self) -> None:
        rules, _ = self._rules("Pull.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Pull {
    mapping(address => uint256) public balanceOf;
    address public treasury;

    constructor(address treasury_) {
        treasury = treasury_;
    }

    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "zero");
        balanceOf[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function sweepFee() external {
        uint256 fee = address(this).balance - _principal();
        require(fee > 0, "nothing");
        (bool ok, ) = treasury.call{value: fee}("");
        require(ok, "sweep failed");
    }

    function _principal() private view returns (uint256) {
        return address(this).balance;
    }
}
""")
        ac = [k for k in rules if k.startswith("AC-001")]
        cei = [k for k in rules if k.startswith("CEI")]
        self.assertFalse(ac, "caller-scoped withdraw()/sweepFee() flagged as missing access control: %s" % ac)
        self.assertFalse(cei, "effects-before-interactions flagged as reentrancy: %s" % cei)

    def test_checked_cpi_and_typed_accounts_are_quiet(self) -> None:
        rules, _ = self._rules("quiet.rs", """use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[program]
pub mod quiet {
    use super::*;

    pub fn pay(ctx: Context<Pay>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault_config;
        vault.total = vault.total.checked_add(amount).ok_or(Err::Overflow)?;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_token_account.to_account_info(),
                    to: ctx.accounts.user_token_account.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
                &[&[b"vault", ctx.accounts.authority.key().as_ref(), &[vault.bump]]],
            ),
            amount,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Pay<'info> {
    #[account(mut, has_one = authority, seeds = [b"vault", authority.key().as_ref()], bump = vault_config.bump)]
    pub vault_config: Account<'info, VaultConfig>,
    #[account(mut, token::authority = vault_authority)]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut, token::authority = authority)]
    pub user_token_account: Account<'info, TokenAccount>,
    /// CHECK: PDA signer, derivation verified by the seeds constraint above
    #[account(seeds = [b"vault", authority.key().as_ref()], bump = vault_config.bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct VaultConfig { pub authority: Pubkey, pub bump: u8, pub total: u64 }

#[error_code]
pub enum Err { #[msg("overflow")] Overflow }
""")
        noisy = [k for k in rules if k.split(":")[0] in
                 ("SIGNER-001", "SIGNER-002", "ACCT-001", "ACCT-002", "CPI-001", "CPI-002", "AUTH-003")]
        self.assertFalse(noisy, "validated Anchor code flagged: %s" % noisy)

    def test_comment_and_string_prose_cannot_create_findings(self) -> None:
        """The masking layer is a product claim; this proves it."""
        rules, _ = self._rules("Prose.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Prose {
    // This contract has NO selfdestruct, no delegatecall and no tx.origin auth.
    /* reentrancy is impossible here; the oracle is a TWAP with a deviation check */
    string public note = "someone could replay this signature forever and drain the vault";
    address public owner;

    function ping() external {
        require(msg.sender == owner, "owner only");
    }
}
""")
        self.assertFalse(
            [k for k in rules if k.split(":")[0] in ("SD-001", "DC-001", "AC-002", "SR-002", "CEI-001")],
            "prose inside comments/strings produced findings: %s" % sorted(rules),
        )

    def test_nonreentrant_guard_silences_cei(self) -> None:
        rules, _ = self._rules("Guarded.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Guarded {
    uint256 private _status = 1;
    mapping(address => uint256) public balanceOf;

    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balanceOf[msg.sender] >= amount, "short");
        balanceOf[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
""")
        self.assertFalse([k for k in rules if k.startswith("CEI")],
                         "guarded + CEI-ordered function still flagged: %s" % sorted(rules))


if __name__ == "__main__":
    unittest.main(verbosity=2)
