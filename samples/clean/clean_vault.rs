//! CleanVault - SYNTHETIC negative control for the Solana/Anchor detectors.
//!
//! Same shape as `samples/solana/vault/programs/vault/src/lib.rs` (init / deposit /
//! withdraw / admin knob / settle CPI) but with the validation actually present: signers are
//! typed, PDAs are derived instead of trusted, accounts are typed, CPIs are checked, and math
//! multiplies before dividing with checked ops.
//!
//! Purpose: `tests/test_false_positives.py` asserts this file yields **zero critical and zero
//! high** findings. If a rule change starts flagging it, precision regressed - fix the rule.
//!
//! Teaching code. Not audited. Not for deployment.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("SGUARD1an1cSynth3t1cCleanVau1tPr0gr3mXXXXXXXXX");

#[program]
pub mod clean_vault {
    use super::*;

    pub const SCALE: u128 = 1_000_000_000;

    /// The bump is derived here, never accepted from the client.
    pub fn initialize(ctx: Context<InitializeClean>) -> Result<()> {
        let (expected_pda, bump) = Pubkey::find_program_address(
            &[b"vault", ctx.accounts.authority.key().as_ref()],
            ctx.program_id,
        );
        require!(
            ctx.accounts.vault_config.key() == expected_pda,
            CleanError::InvalidPda
        );
        let vault = &mut ctx.accounts.vault_config;
        vault.authority = ctx.accounts.authority.key();
        vault.bump = bump;
        vault.total_deposits = 0;
        vault.total_shares = 0;
        Ok(())
    }

    /// Multiply before divide, widen to u128, checked everywhere.
    pub fn deposit(ctx: Context<DepositClean>, amount: u64) -> Result<()> {
        require!(amount > 0, CleanError::ZeroAmount);
        let vault = &mut ctx.accounts.vault_config;

        let shares: u128 = if vault.total_shares == 0 {
            amount as u128
        } else {
            (amount as u128)
                .checked_mul(vault.total_shares as u128)
                .ok_or(CleanError::Overflow)?
                .checked_div(vault.total_deposits as u128)
                .ok_or(CleanError::DivideByZero)?
        };

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_token_account.to_account_info(),
                    to: ctx.accounts.vault_token_account.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;

        vault.total_deposits = vault.total_deposits.checked_add(amount).ok_or(CleanError::Overflow)?;
        vault.total_shares = vault.total_shares.checked_add(shares as u64).ok_or(CleanError::Overflow)?;
        let position = &mut ctx.accounts.user_position;
        position.shares = position.shares.checked_add(shares as u64).ok_or(CleanError::Overflow)?;
        Ok(())
    }

    /// Burns the receipt first, then moves tokens, and the CPI result is propagated.
    pub fn withdraw(ctx: Context<WithdrawClean>, shares: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault_config;
        require!(vault.total_shares > 0, CleanError::DivideByZero);
        let position = &mut ctx.accounts.user_position;
        require!(position.shares >= shares, CleanError::InsufficientShares);

        let amount: u64 = (shares as u128)
            .checked_mul(vault.total_deposits as u128)
            .ok_or(CleanError::Overflow)?
            .checked_div(vault.total_shares as u128)
            .ok_or(CleanError::DivideByZero)? as u64;

        position.shares = position.shares.checked_sub(shares).ok_or(CleanError::Overflow)?;
        vault.total_shares = vault.total_shares.checked_sub(shares).ok_or(CleanError::Overflow)?;
        vault.total_deposits = vault.total_deposits.checked_sub(amount).ok_or(CleanError::Overflow)?;

        let bump = vault.bump;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_token_account.to_account_info(),
                    to: ctx.accounts.user_token_account.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
                &[&[b"vault", ctx.accounts.authority.key().as_ref(), &[bump]]],
            ),
            amount,
        )?;
        Ok(())
    }

    /// Admin action: the authority is a typed Signer bound to the stored key.
    pub fn set_fee_bps(ctx: Context<AdminClean>, fee_bps: u16) -> Result<()> {
        require!(fee_bps <= 500, CleanError::FeeTooHigh);
        ctx.accounts.vault_config.fee_bps = fee_bps;
        Ok(())
    }

    /// Settle against a program Anchor has already validated, with the result checked.
    pub fn settle(ctx: Context<SettleClean>, payload: Vec<u8>) -> Result<()> {
        let instruction = Instruction {
            program_id: ctx.accounts.settlement_program.key(),
            accounts: vec![AccountMeta::new(ctx.accounts.vault_config.key(), false)],
            data: payload,
        };
        anchor_lang::solana_program::program::invoke(
            &instruction,
            &ctx.accounts.to_account_infos(),
        )?;
        Ok(())
    }

    /// remaining_accounts are length-checked and each one's owner is verified.
    pub fn settle_extra<'info>(
        ctx: Context<'_, '_, '_, 'info, SettleClean<'info>>,
    ) -> Result<()> {
        require!(ctx.remaining_accounts.len() >= 1, CleanError::NotEnoughAccounts);
        for account in ctx.remaining_accounts.iter() {
            require!(account.owner == &spl_token::ID, CleanError::InvalidOwner);
        }
        Ok(())
    }
}

/// The config PDA. `has_one` binds it to the signer on every use.
#[derive(Accounts)]
pub struct InitializeClean<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + VaultConfig::SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositClean<'info> {
    #[account(mut, has_one = authority, seeds = [b"vault", authority.key().as_ref()], bump = vault_config.bump)]
    pub vault_config: Account<'info, VaultConfig>,

    /// typed position PDA - Anchor deserialises and checks the owner for us
    #[account(mut, seeds = [b"position", vault_config.key().as_ref(), authority.key().as_ref()], bump)]
    pub user_position: Account<'info, UserPosition>,

    /// typed SPL accounts: owner == token program, and the mint is pinned
    #[account(mut, token::mint = mint, token::authority = authority)]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut, token::mint = mint, token::authority = vault_authority)]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    /// CHECK: derived PDA that owns the vault token account; seeds are verified above
    #[account(seeds = [b"vault", authority.key().as_ref()], bump = vault_config.bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct WithdrawClean<'info> {
    #[account(mut, has_one = authority, seeds = [b"vault", authority.key().as_ref()], bump = vault_config.bump)]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(mut, seeds = [b"position", vault_config.key().as_ref(), authority.key().as_ref()], bump)]
    pub user_position: Account<'info, UserPosition>,

    #[account(mut, token::mint = mint, token::authority = authority)]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(mut, token::mint = mint, token::authority = vault_authority)]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    /// CHECK: PDA signer for the payout CPI, seeds verified by the constraint above
    #[account(seeds = [b"vault", authority.key().as_ref()], bump = vault_config.bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct AdminClean<'info> {
    #[account(mut, has_one = authority)]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SettleClean<'info> {
    #[account(mut, has_one = authority)]
    pub vault_config: Account<'info, VaultConfig>,

    /// Anchor verifies this account is executable and has the expected program id
    pub settlement_program: Program<'info, System>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[account]
pub struct VaultConfig {
    pub authority: Pubkey,
    pub bump: u8,
    pub total_deposits: u64,
    pub total_shares: u64,
    pub fee_bps: u16,
}

impl VaultConfig {
    pub const SPACE: usize = 32 + 1 + 8 + 8 + 2;
}

#[account]
pub struct UserPosition {
    pub owner: Pubkey,
    pub shares: u64,
}

#[error_code]
pub enum CleanError {
    #[msg("invalid pda")]
    InvalidPda,
    #[msg("amount must be positive")]
    ZeroAmount,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("divide by zero")]
    DivideByZero,
    #[msg("insufficient shares")]
    InsufficientShares,
    #[msg("fee out of range")]
    FeeTooHigh,
    #[msg("not enough accounts")]
    NotEnoughAccounts,
    #[msg("invalid account owner")]
    InvalidOwner,
}
