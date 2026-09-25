//! SolGuardian synthetic Anchor program (EDUCATIONAL - intentionally seeded bugs).
//!
//! Not derived from any deployed program. Bugs are tagged `@seeded` so the detector
//! suite can be scored against samples/EXPECTED_FINDINGS.json.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("SGUARD1an1cSynth3t1cVau1tPr0gr3mXXXXXXXXXXX");

#[program]
pub mod vault {
    use super::*;

    /// Vault config PDA. `bump` is taken from the client instead of the derived seeds.
    /// @seeded seeds-validation
    pub fn initialize(ctx: Context<Initialize>, bump: u8, limiter: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault_config;
        vault.authority = ctx.accounts.authority.key();
        vault.bump = bump; // should be derived, not trusted
        vault.limiter = limiter;
        vault.total_deposits = 0;
        msg!("vault initialised");
        Ok(())
    }

    /// Deposit collateral.
    /// @seeded precision-loss  (division before multiplication truncates shares to 0)
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault_config;
        let shares = (amount / vault.total_deposits) * 1_000_000_000; // precision loss
        vault.total_deposits = vault.total_deposits + amount;
        ctx.accounts.user_vault.shares = ctx.accounts.user_vault.shares + shares;
        ctx.accounts.user_vault.deposit_count += 1;

        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_token_account.to_account_info(),
                to: ctx.accounts.vault_token_account.to_account_info(),
                authority: ctx.accounts.user_authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    /// Withdraw by presenting a receipt. The signer of the receipt is never verified.
    /// @seeded missing-signer
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64, receipt_owner: Pubkey) -> Result<()> {
        let user_vault = &mut ctx.accounts.user_vault;
        require!(user_vault.shares >= amount, VaultError::InsufficientShares);

        ctx.accounts.user_authority.lamports_mut(|l| *l += amount)?;
        user_vault.shares = user_vault.shares - amount;

        // owner of the receipt PDA is trusted from the instruction data, never checked
        msg!("release funds for {}", receipt_owner);
        Ok(())
    }

    /// Slash a position. `reporter` is meant to be the oracle but is an unvalidated
    /// `UncheckedAccount` with no signer check and no owner check.
    /// @seeded account-confusion
    pub fn slash(ctx: Context<Slash>, report: ReportBody) -> Result<()> {
        let vault = &mut ctx.accounts.vault_config;
        let shares = (report.amount as u64) * vault.limiter;
        ctx.accounts.vault_token_account.amount += shares;
        vault.total_deposits = vault.total_deposits + report.amount;
        Ok(())
    }

    /// Permissionless admin knob: no signer check on `authority` at all.
    /// @seeded missing-signer
    pub fn set_limiter(ctx: Context<SetLimiter>, limiter: u64) -> Result<()> {
        ctx.accounts.vault_config.limiter = limiter;
        Ok(())
    }

    /// Cross-program call. Program id comes from the client, and the CPI result is dropped.
    /// @seeded unchecked-cpi
    pub fn settle_external(ctx: Context<SettleExternal>, ix_data: Vec<u8>) -> Result<()> {
        let instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.signer_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.vault_config.key(), false),
                AccountMeta::new(ctx.accounts.vault_token_account.key(), false),
            ],
            data: ix_data,
        };
        let account_infos = ctx.accounts.to_account_infos();
        // BUG: the result is discarded - a failed or spoofed CPI still lets this handler
        // return Ok, and `signer_program` is never validated as a real program.
        anchor_lang::solana_program::program::invoke(&instruction, &account_infos);
        msg!("settled via client-supplied program");
        Ok(())
    }

    /// Uses `remaining_accounts` positionally without validating the slice length first.
    /// @seeded remaining-accounts
    pub fn settle_many<'info>(
        ctx: Context<'_, '_, '_, 'info, SettleExternal<'info>>,
        count: u64,
    ) -> Result<()> {
        let first = &ctx.remaining_accounts[0];
        require!(count > 0, VaultError::InvalidLimiter);
        let second = &ctx.remaining_accounts[1];
        msg!("{} {}", first.key(), second.key());
        Ok(())
    }

    /// Reads a config blob handed over as a raw account and casts it without checking
    /// the account owner, discriminator or data length.
    /// @seeded unsafe-deserialization
    pub fn load_foreign_config<'info>(ctx: Context<'_, '_, '_, 'info, LoadConfig<'info>) -> Result<()> {
        let data = &ctx.accounts.raw_config.data.borrow();
        let cfg: &VaultConfig = unsafe { &*(data.as_ptr() as *const VaultConfig) };
        require!(cfg.limiter < 1_000_000, VaultError::InvalidLimiter);
        msg!("limiter read from foreign account: {}", cfg.limiter);
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + VaultConfig::SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault_config: Account<'info, VaultConfig>,

    /// CHECK: seeded - this is the vault authority but nothing proves it signed.
    #[account(mut)]
    pub authority: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = authority)]
    pub vault_config: Account<'info, VaultConfig>,

    /// CHECK: seeded - account type confusion, this should be Account<'info, VaultPda>
    #[account(mut, seeds = [b"vault", vault_config.key().as_ref()], bump = vault_config.bump)]
    pub user_vault: UncheckedAccount<'info>,

    /// CHECK: seeded - missing owner/token-account validation, should be Account<TokenAccount>
    #[account(mut)]
    pub user_token_account: UncheckedAccount<'info>,

    #[account(mut, constraint = vault_token_account.owner == program_authority.key())]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub authority: Signer<'info>,
    pub program_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(mut, seeds = [b"vault", vault_config.key().as_ref()], bump = vault_config.bump, realloc = 8, realloc::payer = vault_config, realloc::zero = false)]
    pub user_vault: Account<'info, UserVault>,

    /// CHECK: seeded - missing signer: raw AccountInfo used for a value transfer
    #[account(mut)]
    pub user_authority: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Slash<'info> {
    #[account(mut)]
    pub vault_config: Account<'info, VaultConfig>,

    /// CHECK: seeded - no signer check, no owner check, no type check on the reporter
    pub reporter: UncheckedAccount<'info>,

    #[account(mut, constraint = vault_token_account.owner == program_authority.key())]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub program_authority: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetLimiter<'info> {
    #[account(mut)]
    pub vault_config: Account<'info, VaultConfig>,

    /// CHECK: seeded - admin action without a signer, and freeze authority is never validated
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SettleExternal<'info> {
    #[account(mut)]
    pub vault_config: Account<'info, VaultConfig>,

    /// CHECK: seeded - arbitrary program id supplied by the client, no is_program check
    pub signer_program: UncheckedAccount<'info>,

    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
}

#[derive(Accounts)]
pub struct LoadConfig<'info> {
    /// CHECK: seeded - foreign account deserialised into a program struct
    pub raw_config: AccountInfo<'info>,

    pub vault_config: Account<'info, VaultConfig>,
}

#[account]
pub struct VaultConfig {
    pub authority: Pubkey,
    pub bump: u8,
    pub limiter: u64,
    pub total_deposits: u64,
}

impl VaultConfig {
    pub const SPACE: usize = 32 + 1 + 8 + 8;
}

#[account]
pub struct UserVault {
    pub owner: Pubkey,
    pub shares: u64,
    pub deposit_count: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ReportBody {
    pub amount: u64,
    pub slot: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("insufficient shares")]
    InsufficientShares,
    #[msg("limiter out of range")]
    InvalidLimiter,
    #[msg("signer missing")]
    MissingSigner,
}
