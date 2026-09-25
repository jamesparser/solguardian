# SolGuardian analysis report

- **Tool:** SolGuardian 0.1.0 (static heuristics + AST-lite; no ML, no network)
- **Target:** `samples` (5 files, 935 lines)
- **Detectors run:** 13
- **Time to full report:** 1.45 s
- **Findings:** 49 (16 critical, 18 high, 12 medium, 3 low)

## Demo metrics (ground truth)

| metric | value |
| --- | --- |
| seeded issues in samples | 17 |
| seeded issues caught | **17** |
| recall | **100%** |
| extra (unseeded) findings | 32 |

| seeded issue | caught | rule | detector | severity (expected / found) |
| --- | --- | --- | --- | --- |
| `evm-reentrancy-withdraw` | yes | CEI-001 | evm_reentrancy | critical / critical |
| `evm-access-adminDrain` | yes | AC-001 | evm_access | critical / critical |
| `evm-tx-origin-setOperator` | yes | AC-002 | evm_access | high / high |
| `evm-unchecked-call-refundPending` | yes | EC-001 | evm_external_calls | high / high |
| `evm-spot-price-assetValue` | yes | OR-001 | evm_oracle | critical / critical |
| `hyperevm-delegatecall-migrate` | yes | DC-001 | evm_delegatecall | critical / critical |
| `hyperevm-sig-replay-claimTreasuryGrant` | yes | SR-002 | evm_sig_replay | critical / critical |
| `hyperevm-selfdestruct-decommission` | yes | SD-001 | evm_selfdestruct | critical / critical |
| `hyperevm-stuck-funds-recoverTokens` | yes | SF-001 | evm_selfdestruct | high / high |
| `hyperevm-unguarded-logic-pointer` | yes | DC-002 | evm_delegatecall | high / high |
| `solana-missing-signer-withdraw` | yes | SIGNER-002 | solana_signer | critical / critical |
| `solana-token-cpi-unvalidated-deposit` | yes | ACCT-002 | solana_accounts | critical / critical |
| `solana-account-confusion-deposit` | yes | ACCT-001 | solana_accounts | high / high |
| `solana-unchecked-cpi-settle_external` | yes | CPI-001 | solana_cpi | high / high |
| `solana-precision-loss-deposit` | yes | MATH-001 | solana_math | high / high |
| `solana-unsafe-deser-load_foreign_config` | yes | DESER-001 | solana_deser | critical / critical |
| `solana-remaining-accounts-settle_many` | yes | REMOT-001 | solana_cpi | medium / medium |

## Agent pipeline

| agent | files | findings | ms |
| --- | ---: | ---: | ---: |
| solana-hunter | 2 | 25 | 1286 |
| evm-hunter | 3 | 24 | 1316 |
| report-writer | - | 49 | 0 |

## Ranked findings

| # | id | sev | conf | rule | where | what |
| ---: | --- | --- | ---: | --- | --- | --- |
| 1 | `SG-EVM-001` | **critical** | 0.92 | DC-001 | `HyperVault.sol:54 migrate()` | delegatecall to unvalidated target in migrate() |
| 2 | `SG-SOL-001` | **critical** | 0.90 | DESER-001 | `lib.rs:117 load_foreign_config()` | Unsafe cast of account data into `VaultConfig` in load_foreign_config() |
| 3 | `SG-EVM-002` | **critical** | 0.90 | SR-002 | `HyperVault.sol:87 claimTreasuryGrant()` | No spend-once tracking: claimTreasuryGrant() can be replayed forever |
| 4 | `SG-EVM-003` | **critical** | 0.90 | CEI-001 | `HyperVault.sol:90 claimTreasuryGrant()` | Reentrancy: state updated after external call in claimTreasuryGrant() |
| 5 | `SG-EVM-004` | **critical** | 0.90 | SD-001 | `HyperVault.sol:102 decommission()` | Reachable `selfdestruct` with caller-chosen beneficiary in decommission() |
| 6 | `SG-EVM-005` | **critical** | 0.90 | CEI-001 | `Vault.sol:74 withdraw()` | Reentrancy: state updated after external call in withdraw() |
| 7 | `SG-EVM-006` | **critical** | 0.90 | AC-001 | `Vault.sol:83 adminDrain()` | Missing access control on adminDrain() |
| 8 | `SG-EVM-007` | **critical** | 0.90 | CEI-001 | `Vault.sol:85 adminDrain()` | Reentrancy: state updated after external call in adminDrain() |
| 9 | `SG-SOL-002` | **critical** | 0.88 | SIGNER-001 | `lib.rs:217 load_foreign_config()` | Missing signer check on `raw_config` in load_foreign_config() |
| 10 | `SG-EVM-008` | **critical** | 0.88 | OR-001 | `Vault.sol:120 assetValue()` | AMM spot price used as valuation in assetValue() |
| 11 | `SG-SOL-003` | **critical** | 0.85 | SIGNER-002 | `lib.rs:54 withdraw()` | withdraw() writes state / moves value with no `Signer` account at all |
| 12 | `SG-SOL-004` | **critical** | 0.85 | SIGNER-002 | `lib.rs:68 slash()` | slash() writes state / moves value with no `Signer` account at all |
| 13 | `SG-SOL-005` | **critical** | 0.85 | SIGNER-002 | `lib.rs:76 set_limiter()` | set_limiter() writes state / moves value with no `Signer` account at all |
| 14 | `SG-SOL-006` | **critical** | 0.80 | ACCT-002 | `lib.rs:39 deposit()` | Token CPI over unvalidated account `user_token_account` in deposit() |
| 15 | `SG-SOL-007` | **critical** | 0.80 | CPI-002 | `lib.rs:208 settle_external()` | CPI target `signer_program` is an unvalidated account, not a Program |
| 16 | `SG-EVM-009` | **critical** | 0.80 | SD-002 | `Vault.sol:85 adminDrain()` | Value sent to a caller-chosen address in adminDrain() |
| 17 | `SG-SOL-008` | **high** | 0.88 | SIGNER-001 | `lib.rs:185 slash()` | Missing signer check on `reporter` in slash() |
| 18 | `SG-SOL-009` | **high** | 0.88 | SIGNER-001 | `lib.rs:199 set_limiter()` | Missing signer check on `authority` in set_limiter() |
| 19 | `SG-SOL-010` | **high** | 0.85 | MATH-001 | `lib.rs:31 deposit()` | Precision loss: integer division before multiplication in deposit() |
| 20 | `SG-SOL-011` | **high** | 0.85 | CPI-001 | `lib.rs:94 settle_external()` | Unchecked CPI: result of `program::invoke` discarded in settle_external() |
| 21 | `SG-EVM-010` | **high** | 0.85 | EC-001 | `HyperVault.sol:89 claimTreasuryGrant()` | Unchecked value transfer result in claimTreasuryGrant() |
| 22 | `SG-EVM-011` | **high** | 0.85 | AC-002 | `Vault.sol:94 setOperator()` | tx.origin used for authorisation in setOperator() |
| 23 | `SG-EVM-012` | **high** | 0.85 | EC-001 | `Vault.sol:111 refundPending()` | Unchecked value transfer result in refundPending() |
| 24 | `SG-EVM-013` | **high** | 0.82 | AC-003 | `HyperVault.sol:94 setReserveFactor()` | Missing access control on setReserveFactor() (writable: reserveFactorBps) |
| 25 | `SG-EVM-014` | **high** | 0.82 | OR-002 | `Vault.sol:121 assetValue()` | Oracle round read without staleness/round checks in assetValue() |
| 26 | `SG-EVM-015` | **high** | 0.82 | AC-003 | `Vault.sol:130 setPriceFeed()` | Missing access control on setPriceFeed() (writable: priceFeed) |
| 27 | `SG-SOL-012` | **high** | 0.80 | ACCT-001 | `lib.rs:154 deposit()` | Unvalidated account type: `user_token_account` is UncheckedAccount in Deposit |
| 28 | `SG-SOL-013` | **high** | 0.80 | ACCT-001 | `lib.rs:208 settle_external()` | Unvalidated account type: `signer_program` is UncheckedAccount in SettleExternal |
| 29 | `SG-SOL-014` | **high** | 0.80 | ACCT-001 | `lib.rs:217 load_foreign_config()` | Unvalidated account type: `raw_config` is AccountInfo in LoadConfig |
| 30 | `SG-EVM-016` | **high** | 0.80 | DC-002 | `HyperVault.sol:61 setImplementation()` | Unguarded write to proxy logic pointer `implementation` |
| 31 | `SG-EVM-017` | **high** | 0.80 | SR-001 | `HyperVault.sol:88 claimTreasuryGrant()` | Unbound signature digest in claimTreasuryGrant() (cross-chain / cross-contract replay) |
| 32 | `SG-EVM-018` | **high** | 0.80 | SF-001 | `HyperVault.sol:109 recoverTokens()` | Stranded funds: recoverTokens() is gated on `pendingAdmin`, which is never assigned |
| 33 | `SG-EVM-019` | **high** | 0.75 | AC-001 | `Vault.sol:106 refundPending()` | Missing access control on refundPending() |
| 34 | `SG-SOL-015` | **high** | 0.70 | CPI-003 | `lib.rs:68 slash()` | SPL token balance edited directly on `vault_token_account` instead of via CPI |
| 35 | `SG-SOL-016` | **medium** | 0.80 | MATH-003 | `lib.rs:31 deposit()` | Division by `vault.total_deposits` with no zero guard in deposit() |
| 36 | `SG-SOL-017` | **medium** | 0.75 | REMOT-001 | `lib.rs:105 settle_many()` | `remaining_accounts` indexed at [0] without a length check |
| 37 | `SG-SOL-018` | **medium** | 0.75 | ACCT-003 | `lib.rs:149` | PDA seeds constraint trusts a client-supplied bump |
| 38 | `SG-SOL-019` | **medium** | 0.75 | ACCT-003 | `lib.rs:169` | PDA seeds constraint trusts a client-supplied bump |
| 39 | `SG-SOL-020` | **medium** | 0.70 | AUTH-001 | `lib.rs:17 initialize()` | PDA authority depends on a client-supplied `bump` in initialize() |
| 40 | `SG-EVM-020` | **medium** | 0.70 | SR-003 | `HyperVault.sol:87 claimTreasuryGrant()` | No signature expiry in claimTreasuryGrant() |
| 41 | `SG-EVM-021` | **medium** | 0.70 | SF-003 | `HyperVault.sol:110 recoverTokens()` | Token recovery result is never checked in recoverTokens() |
| 42 | `SG-SOL-021` | **medium** | 0.65 | AUTH-003 | `lib.rs:174 withdraw()` | Authority account `user_authority` is used by withdraw() with no signer and no binding |
| 43 | `SG-EVM-022` | **medium** | 0.65 | OR-003 | `HyperVault.sol:74 priceOf()` | Single-source price oracle.spotPrice() decides value in priceOf() |
| 44 | `SG-SOL-022` | **medium** | 0.60 | MATH-002 | `lib.rs:33 deposit()` | Unchecked arithmetic on `shares` in deposit() |
| 45 | `SG-SOL-023` | **medium** | 0.60 | MATH-002 | `lib.rs:55 withdraw()` | Unchecked arithmetic on `shares` in withdraw() |
| 46 | `SG-EVM-023` | **medium** | 0.60 | SR-004 | `HyperVault.sol:88 claimTreasuryGrant()` | Raw ecrecover without malleability checks in claimTreasuryGrant() |
| 47 | `SG-SOL-024` | **low** | 0.60 | AUTH-002 | `lib.rs:169` | `realloc::payer = vault_config` is not a funded signer in Withdraw |
| 48 | `SG-SOL-025` | **low** | 0.50 | MATH-004 | `lib.rs:67 slash()` | Narrowing cast `as u64` on an amount in slash() |
| 49 | `SG-EVM-024` | **low** | 0.50 | EC-003 | `HyperVault.sol:90 claimTreasuryGrant()` | Native `.transfer()` gas-stipend transfer in claimTreasuryGrant() |

## Findings in detail

### SG-EVM-001 — delegatecall to unvalidated target in migrate()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.92 |
| rank score | 8.71 |
| rule / detector | DC-001 / evm_delegatecall |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:54 (migrate)` |
| cwe | CWE-471 |
| skill pack | `skills/delegatecall-proxy/SKILL.md` |

migrate() executes `target.delegatecall(...)`. the delegatecall target `target` is an instruction argument, so any caller chooses the code that runs inside this contract's storage. delegatecall keeps this contract's storage and msg.sender, so the callee can rewrite owner/admin/implementation slots, mint, drain, or call selfdestruct. Authorisation on the wrapper (absent) does not help if the target itself is attacker-chosen.

```solidity
(bool ok, ) = target.delegatecall(data);
```

**Exploit sketch (educational)**

1. Deploy a malicious implementation contract.
1. Call migrate() with your contract as the target (or first move the pointer via the unguarded setter).
1. Inside the callee, write the admin/owner slot, then use the admin path to take the funds.

**Patch sketch**

- Only delegatecall to a constant, admin-upgraded-with-timelock implementation address.
- Add EIP-1967 slots + an `onlyProxyAdmin` + timelock upgrade path.
- Validate `target.code.length > 0` and that the target is in an allowlist.

**PoC stub:** `pocs/sg-evm-001_sg_evm_001_delegatecall_to_unval.t.sol` — run with `forge test --match-contract SgEvm001DelegatecallToUnvalidatedTargetIHarness -vvvv`

**Skill checklist satisfied**

- [x] The delegatecall target resolves to a constant or admin-upgraded implementation address -
- [x] Writes to logic pointers are guarded by an admin role **and** a timelock/delay, and emit an

tags: `delegatecall`, `upgradeability`, `DC-001`

### SG-SOL-001 — Unsafe cast of account data into `VaultConfig` in load_foreign_config()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.90 |
| rank score | 8.64 |
| rule / detector | DESER-001 / solana_deser |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:117 (load_foreign_config)` |
| cwe | CWE-125 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

load_foreign_config() reinterprets borrowed account bytes as `*const VaultConfig` and dereferences it. The layout of an account is entirely caller-supplied: there is no owner check and no length/discriminator check here, so the program reads memory it never validated. That is a type-conflict / out-of-bounds read on a chain where the runtime will not save you - and even when it only reads garbage, the value becomes trusted state.

```rust
let cfg: &VaultConfig = unsafe { &*(data.as_ptr() as *const VaultConfig) };
```

**Exploit sketch (educational)**

1. Create an account with the program's own PDA-looking address (or any short account) and pass it in.
1. The cast reads whatever bytes exist - attacker-chosen numbers become `limiter`, authority, etc.
1. Use the forged field to unlock the privileged branch of the handler.

**Patch sketch**

- Use Anchor's typed account (`Account<'info, VaultConfig>`), which verifies owner + discriminator.
- If raw access is unavoidable: check `account.owner == &id()`, then `VaultConfig::try_deserialize(&mut &data[8..])` and never dereference a cast.
- Add `require!(data.len() >= 8 + size_of::<VaultConfig>(), ...)` before reading.

**PoC stub:** `pocs/sg-sol-001_sg_sol_001_unsafe_cast_of_accoun.rs` — run with `cargo test --features test-suites sg_sol_001_unsafe_cast_of_account_data_into_vaul`

**Skill checklist satisfied**

- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority
- [x] `remaining_accounts` are length-checked **before** indexing and validated individually -

tags: `solana`, `unsafe`, `deserialization`, `DESER-001`

### SG-EVM-002 — No spend-once tracking: claimTreasuryGrant() can be replayed forever

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.90 |
| rank score | 8.64 |
| rule / detector | SR-002 / evm_sig_replay |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:87 (claimTreasuryGrant)` |
| cwe | CWE-294 |
| skill pack | `skills/signature-replay/SKILL.md` |

claimTreasuryGrant() pays out on a verified signature but no nonce, no mapping write and no already-used check exists anywhere in the contract. The signer's single authorisation is therefore an unlimited mint: the same (v, r, s) can be submitted in an unbounded number of transactions by anyone who has seen it once - including from public mempool history.

```solidity
function claimTreasuryGrant(bytes32 doc, uint8 v, bytes32 r, bytes32 s, uint256 amount) external {
```

**Exploit sketch (educational)**

1. Observe one legitimate use of claimTreasuryGrant() (mempool, front-end, an airdrop claim).
1. Call it again with the identical doc/v/r/s - the require() on the recovered address still passes.
1. Repeat until the contract is empty; gas is the only cost.

**Patch sketch**

- Track spend: `require(!used[hash]); used[hash] = true;` keyed on the full digest.
- Or carry a per-signer monotonic nonce inside the signed payload and compare it to storage.

**PoC stub:** `pocs/sg-evm-002_sg_evm_002_no_spend_once_trackin.t.sol` — run with `forge test --match-contract SgEvm002NoSpendOnceTrackingClaimtreasuryHarness -vvvv`

**Skill checklist satisfied**

- [x] A spend-once record exists (per-hash mapping or per-signer nonce) and is written in the same
- [x] Batch payloads bind the whole payload hash (no partial-subset replay).

tags: `signature`, `replay`, `missing-nonce`, `SR-002`

### SG-EVM-003 — Reentrancy: state updated after external call in claimTreasuryGrant()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.90 |
| rank score | 8.64 |
| rule / detector | CEI-001 / evm_reentrancy |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:90 (claimTreasuryGrant)` |
| cwe | CWE-841 |
| skill pack | `skills/reentrancy/SKILL.md` |

claimTreasuryGrant() performs an external interaction (payable(msg.sender).transfer) at line 90 and only updates contract state afterwards (borrowed). A callee can re-enter claimTreasuryGrant() during that callback and still see the pre-call balance, so the same funds can be withdrawn repeatedly. No reentrancy guard and no checks-effects-interactions ordering were found in this function.

```solidity
payable(msg.sender).transfer(amount);
```

**Exploit sketch (educational)**

1. Deploy a malicious callee whose fallback/receive() calls back into claimTreasuryGrant().
1. On the first call, pass an amount the contract still thinks you are owed.
1. Inside the callback, call claimTreasuryGrant() again before the balance subtraction at line 91 has executed - the old balance is still readable.
1. Repeat until the contract's native/ERC20 balance is drained.

**Patch sketch**

- Update all accounting before the external call (checks-effects-interactions).
- Or add OpenZeppelin ReentrancyGuard: `nonReentrant` on claimTreasuryGrant().
- Prefer push payments with an explicit withdraw-then-send ordering.

**PoC stub:** `pocs/sg-evm-003_sg_evm_003_reentrancy_state_upda.t.sol` — run with `forge test --match-contract SgEvm003ReentrancyStateUpdatedAfterExterHarness -vvvv`

**Skill checklist satisfied**

- [x] State writes (`balances[...]`, totals, flags, allowances, nonces) are ordered strictly
- [x] A reentrancy guard (`nonReentrant`, OZ `ReentrancyGuard`, ERC-7201 transient storage
- [x] before** the interaction - checks-effects-interactions holds.
- [x] Callbacks from the callee (`onERC721Received`, `tokensReceived`, `ERC4626` deposit hooks,

tags: `reentrancy`, `eth`, `value-transfer`, `CEI-001`

### SG-EVM-004 — Reachable `selfdestruct` with caller-chosen beneficiary in decommission()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.90 |
| rank score | 8.64 |
| rule / detector | SD-001 / evm_selfdestruct |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:102 (decommission)` |
| cwe | CWE-284 |
| skill pack | `skills/fund-recovery/SKILL.md` |

decommission() can destroy IHyperCorePriceOracle and force-send the whole native balance to an address the caller picks (`beneficiary`). There is no authorisation check at all on this path. Destructible state also kills any index that assumed code persists, and it makes an irreversible action available without a timelock or governance delay.

```solidity
selfdestruct(beneficiary);
```

**Exploit sketch (educational)**

1. Call decommission() (directly, or through the unguarded entry that reaches it).
1. The contract's storage is wiped and its ETH balance is pushed to the chosen beneficiary.
1. Every user balance recorded in the contract becomes unrecoverable.

**Patch sketch**

- Remove selfdestruct from application code; use a pause flag plus an explicit withdrawal route.
- If a migration really is needed, gate it behind a timelock + multi-sig governance role and a fixed beneficiary.
- Note that EIP-678 (Cancun and later) limits selfdestruct to same-transaction creation, but the storage/balance sweep still applies on pre-Pectra deployments and on HyperEVM.

**PoC stub:** `pocs/sg-evm-004_sg_evm_004_reachable_selfdestruc.t.sol` — run with `forge test --match-contract SgEvm004ReachableSelfdestructWithCallerCHarness -vvvv`

**Skill checklist satisfied**

- [x] `selfdestruct` does not exist in application code. If it does, it is reachable only behind a

tags: `selfdestruct`, `irreversible`, `SD-001`

### SG-EVM-005 — Reentrancy: state updated after external call in withdraw()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.90 |
| rank score | 8.64 |
| rule / detector | CEI-001 / evm_reentrancy |
| chain | evm |
| location | `solidity/Vault.sol:74 (withdraw)` |
| cwe | CWE-841 |
| skill pack | `skills/reentrancy/SKILL.md` |

withdraw() performs an external interaction (msg.sender.call) at line 74 and only updates contract state afterwards (balanceOf[msg.sender], totalDeposits). A callee can re-enter withdraw() during that callback and still see the pre-call balance, so the same funds can be withdrawn repeatedly. No reentrancy guard and no checks-effects-interactions ordering were found in this function.

```solidity
(bool ok, ) = msg.sender.call{value: amount}("");
```

**Exploit sketch (educational)**

1. Deploy a malicious callee whose fallback/receive() calls back into withdraw().
1. On the first call, pass an amount the contract still thinks you are owed.
1. Inside the callback, call withdraw() again before the balance subtraction at line 76 has executed - the old balance is still readable.
1. Repeat until the contract's native/ERC20 balance is drained.

**Patch sketch**

- Update all accounting before the external call (checks-effects-interactions).
- Or add OpenZeppelin ReentrancyGuard: `nonReentrant` on withdraw().
- Prefer push payments with an explicit withdraw-then-send ordering.

**PoC stub:** `pocs/sg-evm-005_sg_evm_005_reentrancy_state_upda.t.sol` — run with `forge test --match-contract SgEvm005ReentrancyStateUpdatedAfterExterHarness -vvvv`

**Skill checklist satisfied**

- [x] State writes (`balances[...]`, totals, flags, allowances, nonces) are ordered strictly
- [x] A reentrancy guard (`nonReentrant`, OZ `ReentrancyGuard`, ERC-7201 transient storage
- [x] before** the interaction - checks-effects-interactions holds.
- [x] Callbacks from the callee (`onERC721Received`, `tokensReceived`, `ERC4626` deposit hooks,

tags: `reentrancy`, `eth`, `value-transfer`, `CEI-001`

### SG-EVM-006 — Missing access control on adminDrain()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.90 |
| rank score | 8.64 |
| rule / detector | AC-001 / evm_access |
| chain | evm |
| location | `solidity/Vault.sol:83 (adminDrain)` |
| cwe | CWE-284 |
| skill pack | `skills/access-control/SKILL.md` |

adminDrain() is external, moves value to `to`, and writes payout, yet nothing in the function proves who the caller is: no `only*` modifier, no `require(msg.sender == ...)`, no role check, and no caller-scoped accounting. So the state it touches is not limited to the caller's own balance - any address can call it. This is a total-loss path: the destination is fully caller-chosen.

```solidity
function adminDrain(address to, uint256 amount) external {
```

**Exploit sketch (educational)**

1. Call adminDrain() from an EOA you control, with the arguments you want.
1. No key compromise or front-running is required - the entry point is permissionless.
1. Repeat until the shared balance is gone (or until every victim's claim has been consumed).

**Patch sketch**

- Add `onlyOwner` / AccessControl `onlyRole(GUARDIAN_ROLE)` to adminDrain().
- Or make the function self-service: derive the destination from `msg.sender` and let users pull their own funds.
- Emit an event and add a per-call cap so a wrong grant of authority is bounded.

**PoC stub:** `pocs/sg-evm-006_sg_evm_006_missing_access_contro.t.sol` — run with `forge test --match-contract SgEvm006MissingAccessControlOnAdmindrainHarness -vvvv`

**Skill checklist satisfied**

- [x] Each privileged function has either a modifier (`onlyOwner`, `onlyRole`, `onlyAdmin`)
- [x] Build the list of externally callable functions and mark which ones mutate privileged state.

tags: `access-control`, `value-flow`, `AC-001`

### SG-EVM-007 — Reentrancy: state updated after external call in adminDrain()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.90 |
| rank score | 8.64 |
| rule / detector | CEI-001 / evm_reentrancy |
| chain | evm |
| location | `solidity/Vault.sol:85 (adminDrain)` |
| cwe | CWE-841 |
| skill pack | `skills/reentrancy/SKILL.md` |

adminDrain() performs an external interaction (to.call) at line 85 and only updates contract state afterwards (totalDeposits). A callee can re-enter adminDrain() during that callback and still see the pre-call balance, so the same funds can be withdrawn repeatedly. No reentrancy guard and no checks-effects-interactions ordering were found in this function.

```solidity
(bool sent, ) = to.call{value: payout}("");
```

**Exploit sketch (educational)**

1. Deploy a malicious callee whose fallback/receive() calls back into adminDrain().
1. On the first call, pass an amount the contract still thinks you are owed.
1. Inside the callback, call adminDrain() again before the balance subtraction at line 87 has executed - the old balance is still readable.
1. Repeat until the contract's native/ERC20 balance is drained.

**Patch sketch**

- Update all accounting before the external call (checks-effects-interactions).
- Or add OpenZeppelin ReentrancyGuard: `nonReentrant` on adminDrain().
- Prefer push payments with an explicit withdraw-then-send ordering.

**PoC stub:** `pocs/sg-evm-007_sg_evm_007_reentrancy_state_upda.t.sol` — run with `forge test --match-contract SgEvm007ReentrancyStateUpdatedAfterExterHarness -vvvv`

**Skill checklist satisfied**

- [x] State writes (`balances[...]`, totals, flags, allowances, nonces) are ordered strictly
- [x] A reentrancy guard (`nonReentrant`, OZ `ReentrancyGuard`, ERC-7201 transient storage
- [x] before** the interaction - checks-effects-interactions holds.
- [x] Callbacks from the callee (`onERC721Received`, `tokensReceived`, `ERC4626` deposit hooks,

tags: `reentrancy`, `eth`, `value-transfer`, `CEI-001`

### SG-SOL-002 — Missing signer check on `raw_config` in load_foreign_config()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.88 |
| rank score | 8.57 |
| rule / detector | SIGNER-001 / solana_signer |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:217 (load_foreign_config)` |
| cwe | CWE-287 |
| skill pack | `skills/solana-signer/SKILL.md` |

`raw_config` is declared as AccountInfo<info> in the `LoadConfig` accounts struct, so Anchor cannot prove it was signed. load_foreign_config() still uses it to authorise a privileged state change. On Solana an unsigned account is just bytes anyone can craft: an attacker supplies their own account with the right key/shape and the program accepts the instruction. The handler contains no `is_signer` check either and no `Signer` account exists in the struct at all.

```rust
pub raw_config: AccountInfo<'info>,
```

**Exploit sketch (educational)**

1. Build the instruction with a self-created account in the `raw_config` slot (it does not need the real owner's key pair). 
1. Send the transaction - the program sees a well-formed account and no signature requirement fails.
1. Repeat for every victim's data the handler writes through that account.

**Patch sketch**

- Type it as `Signer<'info>`: `raw_config: Signer<'info>` (Anchor enforces the signature).
- Or add an explicit `require!(ctx.accounts.raw_config.is_signer, VaultError::MissingSigner);`.
- Better: bind it to state with `has_one = raw_config` plus a PDA `seeds` constraint.

**PoC stub:** `pocs/sg-sol-002_sg_sol_002_missing_signer_check_.rs` — run with `cargo test --features test-suites sg_sol_002_missing_signer_check_on_raw_config_in`

**Skill checklist satisfied**

- [x] Every account whose **signature** is required is typed `Signer<'info>`; the type system is
- [x] The key stored as the future authority (`vault.authority = authority.key()`) comes from a

tags: `solana`, `missing-signer`, `SIGNER-001`

### SG-EVM-008 — AMM spot price used as valuation in assetValue()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.88 |
| rank score | 8.57 |
| rule / detector | OR-001 / evm_oracle |
| chain | evm |
| location | `solidity/Vault.sol:120 (assetValue)` |
| cwe | CWE-1231 |
| skill pack | `skills/oracle-price/SKILL.md` |

assetValue() derives a price from in-pool reserves (`getReserves`), which is the pool's own balance ratio rather than a traded price. Any caller with enough capital - typically a flash loan - can skew that ratio in a single transaction, and the contract will read the manipulated number in the same block. There is no time-weighting and no second source here.

```solidity
(uint112 reserve0, uint112 reserve1, ) = pool.getReserves();
```

**Exploit sketch (educational)**

1. Flash-loan a large amount of one side of the pool.
1. Swap it into the pool to move reserves (and therefore the printed price) in the same tx.
1. Call assetValue() - the inflated price is now the contract's truth - then mint/borrow/liquidate.
1. Swap back and repay the loan; the profit is the difference in the contract's accounting.

**Patch sketch**

- Use a time-weighted price (Chainlink TWAP or a multi-block Uniswap V2 `cumulativePrice` window).
- Never let an in-block reserve ratio set collateral or payout values.
- Add a max-deviation guard against a second source and reject out-of-band prints.

**PoC stub:** `pocs/sg-evm-008_sg_evm_008_amm_spot_price_used_a.t.sol` — run with `forge test --match-contract SgEvm008AmmSpotPriceUsedAsValuationInAssHarness -vvvv`

**Skill checklist satisfied**

- [x] Identify the pricing source: in-pool reserves (spot), a single Chainlink round, a
- [x] The price cannot be moved inside the same transaction that consumes it (flash-loan
- [x] A second, independent source or a max-deviation circuit breaker exists for anything that

tags: `oracle`, `price-manipulation`, `flash-loan`, `OR-001`

### SG-SOL-003 — withdraw() writes state / moves value with no `Signer` account at all

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.85 |
| rank score | 8.46 |
| rule / detector | SIGNER-002 / solana_signer |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:54 (withdraw)` |
| cwe | CWE-287 |
| skill pack | `skills/solana-signer/SKILL.md` |

The `Withdraw` constraint list contains no `Signer`, yet withdraw() performs a privileged operation (`.lamports_mut(`). Permissionless mutation is exactly the class of bug that empties programs on Solana: there is no `msg.sender` equivalent to fall back on, so the account list is the only authorisation surface.

```rust
ctx.accounts.user_authority.lamports_mut(|l| *l += amount)?;
```

**Exploit sketch (educational)**

1. Call withdraw directly from any wallet - no signature from the configured authority is required.
1. Point the writable accounts at whatever you want changed.

**Patch sketch**

- Add `authority: Signer<'info>` and `#[account(constraint = authority.key() == vault_config.authority)]`.
- Or derive the writable account as a PDA and sign with `seeds` so only the program can author it.

**PoC stub:** `pocs/sg-sol-003_sg_sol_003_withdraw_writes_state.rs` — run with `cargo test --features test-suites sg_sol_003_withdraw_writes_state_moves_value_wit`

**Skill checklist satisfied**

- [x] Every account whose **signature** is required is typed `Signer<'info>`; the type system is

tags: `solana`, `missing-signer`, `privilege`, `SIGNER-002`

### SG-SOL-004 — slash() writes state / moves value with no `Signer` account at all

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.85 |
| rank score | 8.46 |
| rule / detector | SIGNER-002 / solana_signer |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:68 (slash)` |
| cwe | CWE-287 |
| skill pack | `skills/solana-signer/SKILL.md` |

The `Slash` constraint list contains no `Signer`, yet slash() performs a privileged operation (`+=`). Permissionless mutation is exactly the class of bug that empties programs on Solana: there is no `msg.sender` equivalent to fall back on, so the account list is the only authorisation surface.

```rust
ctx.accounts.vault_token_account.amount += shares;
```

**Exploit sketch (educational)**

1. Call slash directly from any wallet - no signature from the configured authority is required.
1. Point the writable accounts at whatever you want changed.

**Patch sketch**

- Add `authority: Signer<'info>` and `#[account(constraint = authority.key() == vault_config.authority)]`.
- Or derive the writable account as a PDA and sign with `seeds` so only the program can author it.

**PoC stub:** `pocs/sg-sol-004_sg_sol_004_slash_writes_state_mo.rs` — run with `cargo test --features test-suites sg_sol_004_slash_writes_state_moves_value_with_n`

**Skill checklist satisfied**

- [x] Every account whose **signature** is required is typed `Signer<'info>`; the type system is

tags: `solana`, `missing-signer`, `privilege`, `SIGNER-002`

### SG-SOL-005 — set_limiter() writes state / moves value with no `Signer` account at all

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.85 |
| rank score | 8.46 |
| rule / detector | SIGNER-002 / solana_signer |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:76 (set_limiter)` |
| cwe | CWE-287 |
| skill pack | `skills/solana-signer/SKILL.md` |

The `SetLimiter` constraint list contains no `Signer`, yet set_limiter() performs a privileged operation (`ctx.accounts.vault_config.limiter = `). Permissionless mutation is exactly the class of bug that empties programs on Solana: there is no `msg.sender` equivalent to fall back on, so the account list is the only authorisation surface.

```rust
ctx.accounts.vault_config.limiter = limiter;
```

**Exploit sketch (educational)**

1. Call set_limiter directly from any wallet - no signature from the configured authority is required.
1. Point the writable accounts at whatever you want changed.

**Patch sketch**

- Add `authority: Signer<'info>` and `#[account(constraint = authority.key() == vault_config.authority)]`.
- Or derive the writable account as a PDA and sign with `seeds` so only the program can author it.

**PoC stub:** `pocs/sg-sol-005_sg_sol_005_set_limiter_writes_st.rs` — run with `cargo test --features test-suites sg_sol_005_set_limiter_writes_state_moves_value_`

**Skill checklist satisfied**

- [x] Every account whose **signature** is required is typed `Signer<'info>`; the type system is

tags: `solana`, `missing-signer`, `privilege`, `SIGNER-002`

### SG-SOL-006 — Token CPI over unvalidated account `user_token_account` in deposit()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.80 |
| rank score | 8.28 |
| rule / detector | ACCT-002 / solana_accounts |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:39 (deposit)` |
| cwe | CWE-863 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

deposit() hands `ctx.accounts.user_token_account` to an SPL token CPI while the account is only an UncheckedAccount. Nothing proves its owner is the token program, that it is the vault's token account, or that its mint is the expected one. The CPI happily operates on whatever account the client supplied, which is the standard way vaults end up paying out of the wrong pot.

```rust
from: ctx.accounts.user_token_account.to_account_info(),
```

**Exploit sketch (educational)**

1. Point `user_token_account` at a token account you control (or at any account whose data you can shape).
1. The vault debits/credits the wrong account; your own balance is the source of truth for it.

**Patch sketch**

- `#[account(constraint = user_token_account.owner == program_authority.key() && user_token_account.mint == expected_mint)]`
- Type it `Account<'info, TokenAccount>` so Anchor deserialises and checks the owner.

**PoC stub:** `pocs/sg-sol-006_sg_sol_006_token_cpi_over_unvali.rs` — run with `cargo test --features test-suites sg_sol_006_token_cpi_over_unvalidated_account_us`

**Skill checklist satisfied**

- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority

tags: `solana`, `cpi`, `account-validation`, `ACCT-002`

### SG-SOL-007 — CPI target `signer_program` is an unvalidated account, not a Program

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.80 |
| rank score | 8.28 |
| rule / detector | CPI-002 / solana_cpi |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:208 (settle_external)` |
| cwe | CWE-252 |
| skill pack | `skills/solana-cpi/SKILL.md` |

`signer_program` is declared as UncheckedAccount in `SettleExternal` and is used as the program id for a cross-program call. Anchor only checks that an account is a *program* when it is typed `Program<'info, T>` (or when `is_program()` is called). Here the client picks the 'program', so the instruction is executed against code the program never vouched for - typically a spoofed token program that returns success without moving anything.

```rust
pub signer_program: UncheckedAccount<'info>,
```

**Exploit sketch (educational)**

1. Deploy a fake program whose address you pass as `signer_program`.
1. It deserialises the args, returns Ok, and moves nothing.
1. The vault credits your position anyway - mint-without-deposit.

**Patch sketch**

- Type the account `Program<'info, anchor_spl::token::Token>` (or `System`).
- Or `require!(ctx.accounts.signer_program.is_program(), VaultError::InvalidProgram);`.
- Even better, use the CPI helper (`token::transfer`) which resolves the program from `CpiContext` types instead of a client field.

**PoC stub:** `pocs/sg-sol-007_sg_sol_007_cpi_target_signer_pro.rs` — run with `cargo test --features test-suites sg_sol_007_cpi_target_signer_program_is_an_unval`

**Skill checklist satisfied**

- [x] The callee is a `Program<'info, T>` account (or `is_program()` verified), never a raw

tags: `solana`, `cpi`, `program-validation`, `CPI-002`

### SG-EVM-009 — Value sent to a caller-chosen address in adminDrain()

| field | value |
| --- | --- |
| severity | **critical** |
| confidence | 0.80 |
| rank score | 8.28 |
| rule / detector | SD-002 / evm_selfdestruct |
| chain | evm |
| location | `solidity/Vault.sol:85 (adminDrain)` |
| cwe | CWE-284 |
| skill pack | `skills/fund-recovery/SKILL.md` |

adminDrain() moves native value to `to`, which is supplied by the caller rather than derived from the contract's own accounting. It is unguarded. Any caller (or any caller that can reach this path) chooses the destination, so shared funds can be redirected at will.

```solidity
(bool sent, ) = to.call{value: payout}("");
```

**Exploit sketch (educational)**

1. Call adminDrain() with `to` set to an address you control.
1. Repeat for each victim's recorded balance if the function is parameterised by user.

**Patch sketch**

- Derive the recipient from the caller (`msg.sender`) or from a per-user withdrawal map.
- Use pull-payments: credit an internal balance, let users claim it themselves.

**PoC stub:** `pocs/sg-evm-009_sg_evm_009_value_sent_to_a_calle.t.sol` — run with `forge test --match-contract SgEvm009ValueSentToACallerChosenAddressIHarness -vvvv`

**Skill checklist satisfied**

- [x] No value-moving call takes its destination from instruction arguments without deriving it from

tags: `arbitrary-send`, `value-flow`, `SD-002`

### SG-SOL-008 — Missing signer check on `reporter` in slash()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.88 |
| rank score | 6.19 |
| rule / detector | SIGNER-001 / solana_signer |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:185 (slash)` |
| cwe | CWE-287 |
| skill pack | `skills/solana-signer/SKILL.md` |

`reporter` is declared as UncheckedAccount<info> in the `Slash` accounts struct, so Anchor cannot prove it was signed. slash() still uses it to authorise a privileged decision. On Solana an unsigned account is just bytes anyone can craft: an attacker supplies their own account with the right key/shape and the program accepts the instruction. The handler contains no `is_signer` check either and no `Signer` account exists in the struct at all.

```rust
pub reporter: UncheckedAccount<'info>,
```

**Exploit sketch (educational)**

1. Build the instruction with a self-created account in the `reporter` slot (it does not need the real owner's key pair). 
1. Send the transaction - the program sees a well-formed account and no signature requirement fails.
1. Repeat for every victim's data the handler writes through that account.

**Patch sketch**

- Type it as `Signer<'info>`: `reporter: Signer<'info>` (Anchor enforces the signature).
- Or add an explicit `require!(ctx.accounts.reporter.is_signer, VaultError::MissingSigner);`.
- Better: bind it to state with `has_one = reporter` plus a PDA `seeds` constraint.

**PoC stub:** `pocs/sg-sol-008_sg_sol_008_missing_signer_check_.rs` — run with `cargo test --features test-suites sg_sol_008_missing_signer_check_on_reporter_in_s`

**Skill checklist satisfied**

- [x] Every account whose **signature** is required is typed `Signer<'info>`; the type system is
- [x] The key stored as the future authority (`vault.authority = authority.key()`) comes from a

tags: `solana`, `missing-signer`, `SIGNER-001`

### SG-SOL-009 — Missing signer check on `authority` in set_limiter()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.88 |
| rank score | 6.19 |
| rule / detector | SIGNER-001 / solana_signer |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:199 (set_limiter)` |
| cwe | CWE-287 |
| skill pack | `skills/solana-signer/SKILL.md` |

`authority` is declared as AccountInfo<info> in the `SetLimiter` accounts struct, so Anchor cannot prove it was signed. set_limiter() still uses it to authorise a privileged decision. On Solana an unsigned account is just bytes anyone can craft: an attacker supplies their own account with the right key/shape and the program accepts the instruction. The handler contains no `is_signer` check either and no `Signer` account exists in the struct at all.

```rust
pub authority: AccountInfo<'info>,
```

**Exploit sketch (educational)**

1. Build the instruction with a self-created account in the `authority` slot (it does not need the real owner's key pair). 
1. Send the transaction - the program sees a well-formed account and no signature requirement fails.
1. Repeat for every victim's data the handler writes through that account.

**Patch sketch**

- Type it as `Signer<'info>`: `authority: Signer<'info>` (Anchor enforces the signature).
- Or add an explicit `require!(ctx.accounts.authority.is_signer, VaultError::MissingSigner);`.
- Better: bind it to state with `has_one = authority` plus a PDA `seeds` constraint.

**PoC stub:** `pocs/sg-sol-009_sg_sol_009_missing_signer_check_.rs` — run with `cargo test --features test-suites sg_sol_009_missing_signer_check_on_authority_in_`

**Skill checklist satisfied**

- [x] Every account whose **signature** is required is typed `Signer<'info>`; the type system is
- [x] The key stored as the future authority (`vault.authority = authority.key()`) comes from a

tags: `solana`, `missing-signer`, `SIGNER-001`

### SG-SOL-010 — Precision loss: integer division before multiplication in deposit()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.85 |
| rank score | 6.11 |
| rule / detector | MATH-001 / solana_math |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:31 (deposit)` |
| cwe | CWE-682 |
| skill pack | `skills/solana-math/SKILL.md` |

deposit() computes `(amount / vault.total_deposits) * 1_000_000_000`. Rust integers truncate, so dividing first throws away the remainder before the scaling factor is applied: for `amount < divisor` the result is exactly zero, and for larger amounts the user loses up to `divisor-1` units of precision per operation. This is the classic share-accounting bug - deposits silently credit 0 shares.

```rust
let shares = (amount / vault.total_deposits) * 1_000_000_000; // precision loss
```

**Exploit sketch (educational)**

1. Deposit an amount smaller than the divisor (`total_deposits` here) and receive 0 shares.
1. Do it repeatedly: the pool's recorded deposits grow while your share balance stays at zero - or, inverted, you can take shares that were never paid for.
1. Round the other way at withdrawal to extract the residual dust on every user.

**Patch sketch**

- Multiply first, divide last: `let shares = amount.checked_mul(SCALE)?.checked_div(total)?;`
- Use `u128` intermediates (`(amount as u128 * SCALE / total) as u64`).
- Track a virtual offset (ERC-4626 style inflation guard) so dust cannot be free-minted.

**PoC stub:** `pocs/sg-sol-010_sg_sol_010_precision_loss_intege.rs` — run with `cargo test --features test-suites sg_sol_010_precision_loss_integer_division_befor`

**Skill checklist satisfied**

- [x] Multiplication happens **before** division; division-first expressions are precision-loss
- [x] Rounding direction is deliberate and always favours the pool (virtual offset / ERC-4626-style

tags: `solana`, `precision`, `accounting`, `MATH-001`

### SG-SOL-011 — Unchecked CPI: result of `program::invoke` discarded in settle_external()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.85 |
| rank score | 6.11 |
| rule / detector | CPI-001 / solana_cpi |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:94 (settle_external)` |
| cwe | CWE-252 |
| skill pack | `skills/solana-cpi/SKILL.md` |

settle_external() performs a cross-program invocation and throws the `Result` away (no `?`, no `require!`). If the callee reverts, the CPI error is swallowed and this handler still returns `Ok(())`, so the program records the external operation as if it succeeded. Every downstream accounting decision then runs on a state that never happened.

```rust
anchor_lang::solana_program::program::invoke(&instruction, &account_infos);
```

**Exploit sketch (educational)**

1. Force the callee to fail (insufficient funds, wrong owner, frozen account).
1. The CPI error never propagates; settle_external() returns success.
1. The program's own bookkeeping now diverges from on-chain reality - withdraw against it.

**Patch sketch**

- Propagate: `program::invoke(&instruction, &account_infos)?;`
- Or `require!(result.is_ok(), VaultError::CpiFailed);` with a real error variant.
- Return the CPI error unchanged so clients see why the transaction failed.

**PoC stub:** `pocs/sg-sol-011_sg_sol_011_unchecked_cpi_result_.rs` — run with `cargo test --features test-suites sg_sol_011_unchecked_cpi_result_of_program_invok`

**Skill checklist satisfied**

- [x] Every CPI result is propagated (`?`) or explicitly handled; a dropped `Result` means the

tags: `solana`, `cpi`, `unchecked`, `CPI-001`

### SG-EVM-010 — Unchecked value transfer result in claimTreasuryGrant()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.85 |
| rank score | 6.11 |
| rule / detector | EC-001 / evm_external_calls |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:89 (claimTreasuryGrant)` |
| cwe | CWE-252 |
| skill pack | `skills/external-calls/SKILL.md` |

claimTreasuryGrant() calls out to e(msg.sender) and ignores the result. e(msg.sender).transfer() can fail silently: low-level `call` returns false instead of reverting, and `send`/`transfer` return false when the recipient cannot accept the value. State that was already updated before the call is not rolled back, so the contract's view of itself diverges from the chain - for accounting code that is a direct loss of user funds.

```solidity
require(signer == admin, "hyprivault: bad signature");
```

**Exploit sketch (educational)**

1. Make the callee fail on purpose: revert, run out of gas, or return false (non-standard ERC20).
1. Trigger claimTreasuryGrant() so the accounting step succeeds while the value move fails.
1. Withdraw/claim again with the state still advanced.

**Patch sketch**

- `(bool ok, ) = target.call{value: v}(""); require(ok, "transfer failed");`
- Or use OpenZeppelin Address.sendValue with an explicit revert.
- For non-standard ERC20s use `SafeERC20.safeTransfer` instead of `transfer`.

**PoC stub:** `pocs/sg-evm-010_sg_evm_010_unchecked_value_trans.t.sol` — run with `forge test --match-contract SgEvm010UncheckedValueTransferResultInClHarness -vvvv`

**Skill checklist satisfied**

- [x] Non-standard ERC20s (USDT-style no-return, fee-on-transfer, rebasing) are handled with

tags: `unchecked-call`, `error-handling`, `EC-001`

### SG-EVM-011 — tx.origin used for authorisation in setOperator()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.85 |
| rank score | 6.11 |
| rule / detector | AC-002 / evm_access |
| chain | evm |
| location | `solidity/Vault.sol:94 (setOperator)` |
| cwe | CWE-284 |
| skill pack | `skills/access-control/SKILL.md` |

setOperator() authorises the caller with `tx.origin` instead of `msg.sender`. tx.origin is the EOA that started the transaction and it keeps equaling the owner even when the owner is tricked into calling a malicious contract first. Any phishing-style interaction therefore hands over full authorisation of this function, which is exactly why Solidity deprecated the pattern.

```solidity
require(tx.origin == owner, "vault: not owner (tx.origin)");
```

**Exploit sketch (educational)**

1. Lure the authorised EOA into calling a contract you control (a small incentive is enough).
1. From that contract's fallback, call setOperator(): `tx.origin == owner` still holds.
1. Authorisation is granted while `msg.sender` is your contract.

**Patch sketch**

- Compare against `msg.sender`.
- If anti-contract phishing resistance is genuinely wanted, add `require(tx.origin == msg.sender)` *in addition to* the sender check, never instead of it.

**PoC stub:** `pocs/sg-evm-011_sg_evm_011_tx_origin_used_for_au.t.sol` — run with `forge test --match-contract SgEvm011TxOriginUsedForAuthorisationInSeHarness -vvvv`

**Skill checklist satisfied**

- [x] `tx.origin` is **never** the authorisation basis (`msg.sender` is the caller).

tags: `access-control`, `tx-origin`, `AC-002`

### SG-EVM-012 — Unchecked value transfer result in refundPending()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.85 |
| rank score | 6.11 |
| rule / detector | EC-001 / evm_external_calls |
| chain | evm |
| location | `solidity/Vault.sol:111 (refundPending)` |
| cwe | CWE-252 |
| skill pack | `skills/external-calls/SKILL.md` |

refundPending() calls out to n and ignores the result. n.transfer() can fail silently: low-level `call` returns false instead of reverting, and `send`/`transfer` return false when the recipient cannot accept the value. State that was already updated before the call is not rolled back, so the contract's view of itself diverges from the chain - for accounting code that is a direct loss of user funds.

```solidity
pendingRewards[user] = 0;
```

**Exploit sketch (educational)**

1. Make the callee fail on purpose: revert, run out of gas, or return false (non-standard ERC20).
1. Trigger refundPending() so the accounting step succeeds while the value move fails.
1. Withdraw/claim again with the state still advanced.

**Patch sketch**

- `(bool ok, ) = target.call{value: v}(""); require(ok, "transfer failed");`
- Or use OpenZeppelin Address.sendValue with an explicit revert.
- For non-standard ERC20s use `SafeERC20.safeTransfer` instead of `transfer`.

**PoC stub:** `pocs/sg-evm-012_sg_evm_012_unchecked_value_trans.t.sol` — run with `forge test --match-contract SgEvm012UncheckedValueTransferResultInReHarness -vvvv`

**Skill checklist satisfied**

- [x] Non-standard ERC20s (USDT-style no-return, fee-on-transfer, rebasing) are handled with

tags: `unchecked-call`, `error-handling`, `EC-001`

### SG-EVM-013 — Missing access control on setReserveFactor() (writable: reserveFactorBps)

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.82 |
| rank score | 6.03 |
| rule / detector | AC-003 / evm_access |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:94 (setReserveFactor)` |
| cwe | CWE-284 |
| skill pack | `skills/access-control/SKILL.md` |

setReserveFactor() rewrites security-critical storage (reserveFactorBps) with no authorisation check. An unguarded price feed, fee, cap or reserve parameter is the usual first step of a composed exploit: the attacker does not break the vault directly, they turn the vault's own inputs until a legitimate code path pays them. On HyperEVM treat HyperCore-style reads with the same caution.

```solidity
function setReserveFactor(uint256 bps) external {
```

**Exploit sketch (educational)**

1. Call setReserveFactor() to install a price/parameter you control.
1. Then trigger the normal accounting path (mint, redeem, liquidate) that reads it.

**Patch sketch**

- Guard with `onlyOwner`/role, plus an `Upgraded`/`ParamSet` event.
- Add a max-move bound and a timelock for security-critical values.
- Prefer AccessControl roles over a single `owner` address.

**PoC stub:** `pocs/sg-evm-013_sg_evm_013_missing_access_contro.t.sol` — run with `forge test --match-contract SgEvm013MissingAccessControlOnSetreserveHarness -vvvv`

**Skill checklist satisfied**

- [x] Each privileged function has either a modifier (`onlyOwner`, `onlyRole`, `onlyAdmin`)
- [x] Build the list of externally callable functions and mark which ones mutate privileged state.

tags: `access-control`, `config`, `AC-003`

### SG-EVM-014 — Oracle round read without staleness/round checks in assetValue()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.82 |
| rank score | 6.03 |
| rule / detector | OR-002 / evm_oracle |
| chain | evm |
| location | `solidity/Vault.sol:121 (assetValue)` |
| cwe | CWE-1231 |
| skill pack | `skills/oracle-price/SKILL.md` |

assetValue() takes the answer from `latestRoundData()` but never inspects `updatedAt`, `startedAt`, `answeredInRound` or `roundId`. A stale round, a round still in progress, or a negative/zero answer therefore passes straight through, and the contract keeps pricing off a print that may be hours old. The `require(answer > 0)` guard alone is not a freshness check.

```solidity
(, int256 answer, , , ) = priceFeed.latestRoundData();
```

**Exploit sketch (educational)**

1. Wait for the feed to stop updating (heartbeat exceeded) during volatility, or during a keeper outage.
1. Trade the underlying asset so the market moves while the contract still uses the old print.
1. Borrow/liquidate against the stale valuation.

**Patch sketch**

- Require `updatedAt != 0 && block.timestamp - updatedAt <= MAX_STALENESS_SECONDS`.
- Require `answeredInRound >= roundId` and `answer > 0`.
- Fall back to a second feed (or pause) when the check fails.

**PoC stub:** `pocs/sg-evm-014_sg_evm_014_oracle_round_read_wit.t.sol` — run with `forge test --match-contract SgEvm014OracleRoundReadWithoutStalenessRHarness -vvvv`

**Skill checklist satisfied**

- [x] Chainlink reads validate all four of: `updatedAt` freshness, `answeredInRound >= roundId`,

tags: `oracle`, `staleness`, `OR-002`

### SG-EVM-015 — Missing access control on setPriceFeed() (writable: priceFeed)

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.82 |
| rank score | 6.03 |
| rule / detector | AC-003 / evm_access |
| chain | evm |
| location | `solidity/Vault.sol:130 (setPriceFeed)` |
| cwe | CWE-284 |
| skill pack | `skills/access-control/SKILL.md` |

setPriceFeed() rewrites security-critical storage (priceFeed) with no authorisation check. An unguarded price feed, fee, cap or reserve parameter is the usual first step of a composed exploit: the attacker does not break the vault directly, they turn the vault's own inputs until a legitimate code path pays them. On this chain treat HyperCore-style reads with the same caution.

```solidity
function setPriceFeed(address feed) external {
```

**Exploit sketch (educational)**

1. Call setPriceFeed() to install a price/parameter you control.
1. Then trigger the normal accounting path (mint, redeem, liquidate) that reads it.

**Patch sketch**

- Guard with `onlyOwner`/role, plus an `Upgraded`/`ParamSet` event.
- Add a max-move bound and a timelock for security-critical values.
- Prefer AccessControl roles over a single `owner` address.

**PoC stub:** `pocs/sg-evm-015_sg_evm_015_missing_access_contro.t.sol` — run with `forge test --match-contract SgEvm015MissingAccessControlOnSetpricefeHarness -vvvv`

**Skill checklist satisfied**

- [x] Each privileged function has either a modifier (`onlyOwner`, `onlyRole`, `onlyAdmin`)
- [x] Build the list of externally callable functions and mark which ones mutate privileged state.

tags: `access-control`, `config`, `AC-003`

### SG-SOL-012 — Unvalidated account type: `user_token_account` is UncheckedAccount in Deposit

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.80 |
| rank score | 5.98 |
| rule / detector | ACCT-001 / solana_accounts |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:154 (deposit)` |
| cwe | CWE-863 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

`user_token_account` in the `Deposit` constraint list is typed as UncheckedAccount<info>, so Anchor performs no deserialisation, owner or discriminator check on it - yet deposit() passes it into program logic. That is account-confusion territory: an attacker can substitute a look-alike account (wrong owner, wrong mint, wrong program) and the handler has no way to notice. Typing it as `Account<'info, T>` / `Program<'info, T>` makes the runtime enforce it for free.

```rust
pub user_token_account: UncheckedAccount<'info>,
```

**Exploit sketch (educational)**

1. Create any account with a matching shape (or reuse one you own) and place it in the `user_token_account` slot.
1. Because ownership/discriminator are not verified, the handler treats it as trusted.
1. Combine with the missing signer path to redirect value.

**Patch sketch**

- Use a concrete type: `Account<'info, TokenAccount>` / `Program<'info, Token>` / `Account<'info, VaultPda>`.
- Or validate by hand: `require!(acc.owner == &anchor_spl::token::ID, ...)` and check the discriminator/length.
- Add `#[account(..., token::mint = expected_mint)]` style constraints for SPL accounts.

**PoC stub:** `pocs/sg-sol-012_sg_sol_012_unvalidated_account_t.rs` — run with `cargo test --features test-suites sg_sol_012_unvalidated_account_type_user_token_a`

**Skill checklist satisfied**

- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority
- [x] Every account that authorises a privileged action is typed `Signer<'info>` (or its

tags: `solana`, `account-validation`, `type-confusion`, `ACCT-001`

### SG-SOL-013 — Unvalidated account type: `signer_program` is UncheckedAccount in SettleExternal

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.80 |
| rank score | 5.98 |
| rule / detector | ACCT-001 / solana_accounts |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:208 (settle_external)` |
| cwe | CWE-863 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

`signer_program` in the `SettleExternal` constraint list is typed as UncheckedAccount<info>, so Anchor performs no deserialisation, owner or discriminator check on it - yet settle_external() passes it into program logic. That is account-confusion territory: an attacker can substitute a look-alike account (wrong owner, wrong mint, wrong program) and the handler has no way to notice. Typing it as `Account<'info, T>` / `Program<'info, T>` makes the runtime enforce it for free.

```rust
pub signer_program: UncheckedAccount<'info>,
```

**Exploit sketch (educational)**

1. Create any account with a matching shape (or reuse one you own) and place it in the `signer_program` slot.
1. Because ownership/discriminator are not verified, the handler treats it as trusted.
1. Combine with the missing signer path to redirect value.

**Patch sketch**

- Use a concrete type: `Account<'info, TokenAccount>` / `Program<'info, Token>` / `Account<'info, VaultPda>`.
- Or validate by hand: `require!(acc.owner == &anchor_spl::token::ID, ...)` and check the discriminator/length.
- Add `#[account(..., token::mint = expected_mint)]` style constraints for SPL accounts.

**PoC stub:** `pocs/sg-sol-013_sg_sol_013_unvalidated_account_t.rs` — run with `cargo test --features test-suites sg_sol_013_unvalidated_account_type_signer_progr`

**Skill checklist satisfied**

- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority
- [x] Every account that authorises a privileged action is typed `Signer<'info>` (or its

tags: `solana`, `account-validation`, `type-confusion`, `ACCT-001`

### SG-SOL-014 — Unvalidated account type: `raw_config` is AccountInfo in LoadConfig

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.80 |
| rank score | 5.98 |
| rule / detector | ACCT-001 / solana_accounts |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:217 (load_foreign_config)` |
| cwe | CWE-863 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

`raw_config` in the `LoadConfig` constraint list is typed as AccountInfo<info>, so Anchor performs no deserialisation, owner or discriminator check on it - yet load_foreign_config() passes it into program logic. That is account-confusion territory: an attacker can substitute a look-alike account (wrong owner, wrong mint, wrong program) and the handler has no way to notice. Typing it as `Account<'info, T>` / `Program<'info, T>` makes the runtime enforce it for free.

```rust
pub raw_config: AccountInfo<'info>,
```

**Exploit sketch (educational)**

1. Create any account with a matching shape (or reuse one you own) and place it in the `raw_config` slot.
1. Because ownership/discriminator are not verified, the handler treats it as trusted.
1. Combine with the missing signer path to redirect value.

**Patch sketch**

- Use a concrete type: `Account<'info, TokenAccount>` / `Program<'info, Token>` / `Account<'info, VaultPda>`.
- Or validate by hand: `require!(acc.owner == &anchor_spl::token::ID, ...)` and check the discriminator/length.
- Add `#[account(..., token::mint = expected_mint)]` style constraints for SPL accounts.

**PoC stub:** `pocs/sg-sol-014_sg_sol_014_unvalidated_account_t.rs` — run with `cargo test --features test-suites sg_sol_014_unvalidated_account_type_raw_config_i`

**Skill checklist satisfied**

- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority
- [x] Every account that authorises a privileged action is typed `Signer<'info>` (or its

tags: `solana`, `account-validation`, `type-confusion`, `ACCT-001`

### SG-EVM-016 — Unguarded write to proxy logic pointer `implementation`

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.80 |
| rank score | 5.98 |
| rule / detector | DC-002 / evm_delegatecall |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:61 (setImplementation)` |
| cwe | CWE-471 |
| skill pack | `skills/delegatecall-proxy/SKILL.md` |

setImplementation() assigns `implementation` with no authorisation check. Whoever controls that slot controls the logic every delegatecall in this proxy resolves to, which is equivalent to owning the contract and all of its storage. This is the storage-collision/upgrade footgun class: the slot is also shared with the implementation's own layout, so ordering matters.

```solidity
implementation = newImpl;
```

**Exploit sketch (educational)**

1. Point `implementation` at a contract you wrote.
1. Trigger the fallback/delegate path - all subsequent calls run your code in this storage.

**Patch sketch**

- Guard with `onlyProxyAdmin` + AccessControl role, and emit an Upgraded event.
- Use EIP-1967/ERC-1967 upgradeable proxies from OpenZeppelin rather than a hand-rolled slot.
- Keep implementation state in a namespaced storage gap to avoid collisions.

**PoC stub:** `pocs/sg-evm-016_sg_evm_016_unguarded_write_to_pr.t.sol` — run with `forge test --match-contract SgEvm016UnguardedWriteToProxyLogicPointeHarness -vvvv`

**Skill checklist satisfied**

- [x] Writes to logic pointers are guarded by an admin role **and** a timelock/delay, and emit an

tags: `delegatecall`, `proxy`, `storage-collision`, `DC-002`

### SG-EVM-017 — Unbound signature digest in claimTreasuryGrant() (cross-chain / cross-contract replay)

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.80 |
| rank score | 5.98 |
| rule / detector | SR-001 / evm_sig_replay |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:88 (claimTreasuryGrant)` |
| cwe | CWE-294 |
| skill pack | `skills/signature-replay/SKILL.md` |

claimTreasuryGrant() verifies a signature with raw `ecrecover` on a caller-supplied hash. The digest does not commit to the verifying contract address or the chain id (no EIP-712 domain separator), so one valid signature is valid everywhere the same bytecode is deployed - every fork, every testnet-to-mainnet copy, and every sibling contract that shares the signer.

```solidity
address signer = ecrecover(doc, v, r, s);
```

**Exploit sketch (educational)**

1. Capture a legitimate signed payload on chain A (or from any off-chain consumer of the signer).
1. Replay it verbatim against the same deployment on chain B / a sibling contract.
1. No forging is required: the signature is authentic, just in the wrong context.

**Patch sketch**

- Use OpenZeppelin EIP712 + `ECDSA.recover(typedDigest, v, r, s)` so the domain binds `address(this)` and `block.chainid`.
- If hand-rolled, hash `0x19 0x01 domainSeparator structHash` and cache the domain separator including chainid so forks invalidate it.

**PoC stub:** `pocs/sg-evm-017_sg_evm_017_unbound_signature_dig.t.sol` — run with `forge test --match-contract SgEvm017UnboundSignatureDigestInClaimtreHarness -vvvv`

**Skill checklist satisfied**

- [x] The digest commits to the verifying context: EIP-712 domain separator with `name`,

tags: `signature`, `replay`, `SR-001`

### SG-EVM-018 — Stranded funds: recoverTokens() is gated on `pendingAdmin`, which is never assigned

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.80 |
| rank score | 5.98 |
| rule / detector | SF-001 / evm_selfdestruct |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:109 (recoverTokens)` |
| cwe | CWE-284 |
| skill pack | `skills/fund-recovery/SKILL.md` |

`pendingAdmin` is declared as a storage address and used as the only authorisation for recoverTokens(), but nothing in this contract ever assigns it. It is therefore zero (`address(0)`), and no caller can ever satisfy the check. The function is dead code, which means value that only this path can move - ETH and tokens held by the contract - is permanently stranded.

```solidity
require(msg.sender == pendingAdmin, "hyprivault: not pending admin");
```

**Exploit sketch (educational)**

1. No attacker required: send value to the contract (or let it accumulate) and the recovery path can never be executed.
1. If the gate is `msg.sender == address(0)`, the check can even be satisfied by a crafted creation flow, turning dead code into an open door.

**Patch sketch**

- Assign the variable in the constructor or an initialiser, or delete the path.
- Add a test asserting the recovery function is callable by the intended role.
- Prefer AccessControl roles with `grantRole` at deploy time over bare address variables.

**PoC stub:** `pocs/sg-evm-018_sg_evm_018_stranded_funds_recove.t.sol` — run with `forge test --match-contract SgEvm018StrandedFundsRecovertokensIsGateHarness -vvvv`

**Skill checklist satisfied**

- [x] Token recovery uses `SafeERC20` and checks the return data - a rescue that silently fails is

tags: `stuck-funds`, `unreachable-guard`, `SF-001`

### SG-EVM-019 — Missing access control on refundPending()

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.75 |
| rank score | 5.85 |
| rule / detector | AC-001 / evm_access |
| chain | evm |
| location | `solidity/Vault.sol:106 (refundPending)` |
| cwe | CWE-284 |
| skill pack | `skills/access-control/SKILL.md` |

refundPending() is public, moves value to `user`, and writes owed, yet nothing in the function proves who the caller is: no `only*` modifier, no `require(msg.sender == ...)`, no role check, and no caller-scoped accounting. So the state it touches is not limited to the caller's own balance - any address can call it. The destination is a named user, so the direct risk is griefing/replay of that user's claim rather than an empty contract.

```solidity
function refundPending(address user) public returns (uint256 paid) {
```

**Exploit sketch (educational)**

1. Call refundPending() from an EOA you control, with the arguments you want.
1. No key compromise or front-running is required - the entry point is permissionless.
1. Repeat until the shared balance is gone (or until every victim's claim has been consumed).

**Patch sketch**

- Add `onlyOwner` / AccessControl `onlyRole(GUARDIAN_ROLE)` to refundPending().
- Or make the function self-service: derive the destination from `msg.sender` and let users pull their own funds.
- Emit an event and add a per-call cap so a wrong grant of authority is bounded.

**PoC stub:** `pocs/sg-evm-019_sg_evm_019_missing_access_contro.t.sol` — run with `forge test --match-contract SgEvm019MissingAccessControlOnRefundpendHarness -vvvv`

**Skill checklist satisfied**

- [x] Each privileged function has either a modifier (`onlyOwner`, `onlyRole`, `onlyAdmin`)
- [x] Build the list of externally callable functions and mark which ones mutate privileged state.

tags: `access-control`, `value-flow`, `AC-001`

### SG-SOL-015 — SPL token balance edited directly on `vault_token_account` instead of via CPI

| field | value |
| --- | --- |
| severity | **high** |
| confidence | 0.70 |
| rank score | 5.72 |
| rule / detector | CPI-003 / solana_cpi |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:68 (slash)` |
| cwe | CWE-252 |
| skill pack | `skills/solana-cpi/SKILL.md` |

slash() writes `ctx.accounts.vault_token_account.amount` directly. An SPL token account is owned by the token program, so a well-behaved runtime will reject the mutation; where the owner check is weak (or the account was passed as a raw/duplicated account) the balance can be forged inside the transaction, letting an attacker mint purchasing power without moving tokens.

```rust
ctx.accounts.vault_token_account.amount += shares;
```

**Exploit sketch (educational)**

1. Pass an account the handler treats as the vault token account.
1. Direct mutation path (or a CPI on an unvalidated program) inflates `amount`.
1. Withdraw/settle logic trusts `amount` and releases real tokens.

**Patch sketch**

- Move balances with `token::transfer` / `token::mint_to` CPIs signed by the vault PDA.
- Keep program-owned state in your own accounts, never in foreign-owned layouts.

**PoC stub:** `pocs/sg-sol-015_sg_sol_015_spl_token_balance_edi.rs` — run with `cargo test --features test-suites sg_sol_015_spl_token_balance_edited_directly_on_`

**Skill checklist satisfied**

- [x] Every CPI result is propagated (`?`) or explicitly handled; a dropped `Result` means the

tags: `solana`, `spl`, `account-ownership`, `CPI-003`

### SG-SOL-016 — Division by `vault.total_deposits` with no zero guard in deposit()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.80 |
| rank score | 3.68 |
| rule / detector | MATH-003 / solana_math |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:31 (deposit)` |
| cwe | CWE-682 |
| skill pack | `skills/solana-math/SKILL.md` |

deposit() divides by `vault.total_deposits`, which is program state that can legitimately be zero (a fresh vault). On Solana an integer division by zero panics the builtin, the transaction fails with an opaque error, and the first depositor can never complete the flow - an availability bug rather than a theft, but it blocks the account's own happy path.

```rust
let shares = (amount / vault.total_deposits) * 1_000_000_000; // precision loss
```

**Exploit sketch (educational)**

1. Call the handler while the divisor is zero (empty vault) to force the panic.
1. If the zero branch is also how shares are seeded, the whole feature is unusable.

**Patch sketch**

- Special-case the empty pool: `let shares = if total == 0 { amount } else { ... };`
- `checked_div(...).ok_or(VaultError::DivideByZero)?` so the failure is a typed error.

**PoC stub:** `pocs/sg-sol-016_sg_sol_016_division_by_vault_tot.rs` — run with `cargo test --features test-suites sg_sol_016_division_by_vault_total_deposits_with`

**Skill checklist satisfied**

- [x] Divisors can never be zero: the empty-vault case is special-cased or guarded with

tags: `solana`, `division-by-zero`, `availability`, `MATH-003`

### SG-SOL-017 — `remaining_accounts` indexed at [0] without a length check

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.75 |
| rank score | 3.60 |
| rule / detector | REMOT-001 / solana_cpi |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:105 (settle_many)` |
| cwe | CWE-252 |
| skill pack | `skills/solana-cpi/SKILL.md` |

settle_many() reads `remaining_accounts[0]` from `ctx.remaining_accounts` before checking how many accounts the client actually sent. A short account list panics on the slice index (an uncaught panic in the handler, not a clean program error), and any validation that *would* have happened afterwards is skipped - note the ordering here: the read precedes the `require!`.

```rust
let first = &ctx.remaining_accounts[0];
```

**Exploit sketch (educational)**

1. Send the instruction with fewer remaining accounts than expected.
1. The program panics on the index; clients see an opaque failure (DoS of that path).
1. Or rely on the missing validation to slip a wrong-role account into position.

**Patch sketch**

- `ensure!(ctx.remaining_accounts.len() >= 2, VaultError::NotEnoughAccounts);` before indexing.
- Iterate with `.iter().next().ok_or(...)` so absence becomes a typed error.
- Validate each remaining account's owner/mint - they are outside Anchor's checks.

**PoC stub:** `pocs/sg-sol-017_sg_sol_017_remaining_accounts_in.rs` — run with `cargo test --features test-suites sg_sol_017_remaining_accounts_indexed_at_0_witho`

**Skill checklist satisfied**

- [x] `remaining_accounts` lengths are validated before they are used as CPI accounts.

tags: `solana`, `remaining-accounts`, `panic`, `REMOT-001`

### SG-SOL-018 — PDA seeds constraint trusts a client-supplied bump

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.75 |
| rank score | 3.60 |
| rule / detector | ACCT-003 / solana_accounts |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:149` |
| cwe | CWE-863 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

The account constraint uses `bump = vault_config.bump`, and that stored bump was written from an instruction argument in `initialize`. Anchor will therefore accept *any* bump the client first persisted, so the seeds constraint stops pinning the address to a single canonical PDA. Bump values are part of the address derivation: letting the client choose them is a validation gap.

```rust
#[account(mut, seeds = [b"vault", vault_config.key().as_ref()], bump = vault_config.bump)]
```

**Exploit sketch (educational)**

1. Call `initialize` with a bump that still satisfies the (weak) derivation and store it.
1. Reuse that stored bump later to make a seeds check accept a non-canonical address.

**Patch sketch**

- Derive the bump: `bump` (Anchor verifies) or `let (,_ ,bump) = Pubkey::find_program_address(...)`.
- Store the *derived* bump, never the client's.

**PoC stub:** `pocs/sg-sol-018_sg_sol_018_pda_seeds_constraint_.rs` — run with `cargo test --features test-suites sg_sol_018_pda_seeds_constraint_trusts_a_client_`

**Skill checklist satisfied**

- [x] PDAs are derived, not trusted: `seeds` + `bump` verified by Anchor, or

tags: `solana`, `pda`, `seeds`, `ACCT-003`

### SG-SOL-019 — PDA seeds constraint trusts a client-supplied bump

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.75 |
| rank score | 3.60 |
| rule / detector | ACCT-003 / solana_accounts |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:169` |
| cwe | CWE-863 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

The account constraint uses `bump = vault_config.bump`, and that stored bump was written from an instruction argument in `initialize`. Anchor will therefore accept *any* bump the client first persisted, so the seeds constraint stops pinning the address to a single canonical PDA. Bump values are part of the address derivation: letting the client choose them is a validation gap.

```rust
#[account(mut, seeds = [b"vault", vault_config.key().as_ref()], bump = vault_config.bump, realloc = 8, realloc::payer = vault_config, realloc::zero = false)]
```

**Exploit sketch (educational)**

1. Call `initialize` with a bump that still satisfies the (weak) derivation and store it.
1. Reuse that stored bump later to make a seeds check accept a non-canonical address.

**Patch sketch**

- Derive the bump: `bump` (Anchor verifies) or `let (,_ ,bump) = Pubkey::find_program_address(...)`.
- Store the *derived* bump, never the client's.

**PoC stub:** `pocs/sg-sol-019_sg_sol_019_pda_seeds_constraint_.rs` — run with `cargo test --features test-suites sg_sol_019_pda_seeds_constraint_trusts_a_client_`

**Skill checklist satisfied**

- [x] PDAs are derived, not trusted: `seeds` + `bump` verified by Anchor, or

tags: `solana`, `pda`, `seeds`, `ACCT-003`

### SG-SOL-020 — PDA authority depends on a client-supplied `bump` in initialize()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.70 |
| rank score | 3.52 |
| rule / detector | AUTH-001 / solana_authority |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:17 (initialize)` |
| cwe | CWE-269 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

initialize() takes `bump: u8` straight from the instruction and stores it, and other handlers then use that stored value as their seeds constraint (`bump = config.bump`). A PDA is only canonical when the bump is derived with `find_program_address`; storing the caller's number means the first writer decides how authority is derived. Even where `init` seeds constrain this particular deployment, the pattern is how upgrade/freeze/mint authority bugs hide.

```rust
pub fn initialize(ctx: Context<Initialize>, bump: u8, limiter: u64) -> Result<()> {
```

**Exploit sketch (educational)**

1. If the PDA is not uniquely constrained at init, pick a bump that makes a *different* address satisfy the seeds check.
1. Then present an account derived from that alternative bump to handlers trusting the stored value.

**Patch sketch**

- Drop the parameter and let Anchor verify the bump (`seeds = [...], bump`).
- Or derive it: `let (_pda, bump) = Pubkey::find_program_address(&[b"vault", authority.as_ref()], &id());`
- If a bump must be stored, assert it equals the derived value on every read.

**PoC stub:** `pocs/sg-sol-020_sg_sol_020_pda_authority_depends.rs` — run with `cargo test --features test-suites sg_sol_020_pda_authority_depends_on_a_client_sup`

**Skill checklist satisfied**

- [x] PDAs are derived, not trusted: `seeds` + `bump` verified by Anchor, or
- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority

tags: `solana`, `pda`, `authority`, `AUTH-001`

### SG-EVM-020 — No signature expiry in claimTreasuryGrant()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.70 |
| rank score | 3.52 |
| rule / detector | SR-003 / evm_sig_replay |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:87 (claimTreasuryGrant)` |
| cwe | CWE-294 |
| skill pack | `skills/signature-replay/SKILL.md` |

claimTreasuryGrant() accepts a signature with no deadline and no expiry check. A signer's intent is usually time-bounded - rates, collateral ratios and allowances change - so a signature that was reasonable on the day it was signed can be catastrophic months later, and a leaked offline payload never expires.

```solidity
function claimTreasuryGrant(bytes32 doc, uint8 v, bytes32 r, bytes32 s, uint256 amount) external {
```

**Exploit sketch (educational)**

1. Collect signed payloads when conditions are favourable.
1. Hold them until prices/limits move in your favour, then submit.

**Patch sketch**

- Put `uint256 deadline` in the signed payload and `require(block.timestamp <= deadline, "expired")`.
- Keep the default TTL short (minutes to hours) and document it for signers.

**PoC stub:** `pocs/sg-evm-020_sg_evm_020_no_signature_expiry_i.t.sol` — run with `forge test --match-contract SgEvm020NoSignatureExpiryInClaimtreasuryHarness -vvvv`

**Skill checklist satisfied**

- [x] A `deadline` is part of the signed payload and is enforced against `block.timestamp`.

tags: `signature`, `deadline`, `SR-003`

### SG-EVM-021 — Token recovery result is never checked in recoverTokens()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.70 |
| rank score | 3.52 |
| rule / detector | SF-003 / evm_selfdestruct |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:110 (recoverTokens)` |
| cwe | CWE-284 |
| skill pack | `skills/fund-recovery/SKILL.md` |

The recovery path does a low-level `token.call(...)` and then discards the boolean (the code shape here is `(bool ok, ) = ...; ok;`). A non-standard or pausable token that returns false makes the caller believe the rescue succeeded, so a failed recovery looks like a completed one.

```solidity
(bool ok, ) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
```

**Exploit sketch (educational)**

1. Choose a token that returns false instead of reverting (USDT-style) or that is paused.
1. The recovery call reports success while nothing moved.

**Patch sketch**

- `require(ok && (abi.decode(ret, (bool)) ), "transfer failed")` or use SafeERC20.safeTransfer.
- Revert on any zero-length return data as well.

**PoC stub:** `pocs/sg-evm-021_sg_evm_021_token_recovery_result.t.sol` — run with `forge test --match-contract SgEvm021TokenRecoveryResultIsNeverCheckeHarness -vvvv`

**Skill checklist satisfied**

- [x] Token recovery uses `SafeERC20` and checks the return data - a rescue that silently fails is

tags: `unchecked-call`, `token-recovery`, `SF-003`

### SG-SOL-021 — Authority account `user_authority` is used by withdraw() with no signer and no binding

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.65 |
| rank score | 3.44 |
| rule / detector | AUTH-003 / solana_authority |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:174 (withdraw)` |
| cwe | CWE-269 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

`user_authority` in `Withdraw` reads like an authority (AccountInfo<info>) but is not a `Signer`, is not tied by `has_one`/`constraint`/`seeds`, and withdraw() still consumes it. Any mint / freeze / close authority check the program assumes happens here is really happening on an account the client chose. The privilege exists; nothing in the source limits who exercises it.

```rust
pub user_authority: AccountInfo<'info>,
```

**Exploit sketch (educational)**

1. Supply a different key in the `user_authority` slot (or reuse an account you own that matches the shape).
1. Pair it with the missing-signer path in the same handler to complete the authority chain.

**Patch sketch**

- `Signer<'info>` plus `#[account(constraint = user_authority.key() == expected_authority)]`.
- Read SPL authorities from the mint/account data instead of from an unvalidated account.
- Use a two-step authority handover so a single bad call cannot transfer ownership.

**PoC stub:** `pocs/sg-sol-021_sg_sol_021_authority_account_use.rs` — run with `cargo test --features test-suites sg_sol_021_authority_account_user_authority_is_u`

**Skill checklist satisfied**

- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority
- [x] Every account that authorises a privileged action is typed `Signer<'info>` (or its

tags: `solana`, `authority`, `static-note`, `AUTH-003`

### SG-EVM-022 — Single-source price oracle.spotPrice() decides value in priceOf()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.65 |
| rank score | 3.44 |
| rule / detector | OR-003 / evm_oracle |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:74 (priceOf)` |
| cwe | CWE-1231 |
| skill pack | `skills/oracle-price/SKILL.md` |

priceOf() trusts one oracle call (oracle.spotPrice) for a value-deciding calculation, with no deviation check, no second source and no circuit breaker.On HyperEVM the HyperCore spot read is itself a consensus input, so treat unit/exponent mismatches and asset-alias confusion as the realistic failure mode. If that single print is wrong - manipulated, stale, or a different asset's unit - every dependent decision is wrong in the same direction.

```solidity
return oracle.spotPrice(asset);
```

**Exploit sketch (educational)**

1. Identify the oracle's own trust path (a small set of attesters, a single pair, a low-liquidity venue).
1. Move or misreport that one input.
1. Call the value-deciding entry point while the whole system believes the bad number.

**Patch sketch**

- Cross-check a second independent source and revert if they differ by more than a threshold.
- Validate the returned exponent/units before using the number.
- Add a per-block max-move (circuit breaker) and an explicit pause role.

**PoC stub:** `pocs/sg-evm-022_sg_evm_022_single_source_price_o.t.sol` — run with `forge test --match-contract SgEvm022SingleSourcePriceOracleSpotpriceHarness -vvvv`

**Skill checklist satisfied**

- [x] A second, independent source or a max-deviation circuit breaker exists for anything that
- [x] Units/exponents are asserted (1e8 Chainlink vs 1e18 pool decimals vs HyperCore asset

tags: `oracle`, `single-source`, `OR-003`

### SG-SOL-022 — Unchecked arithmetic on `shares` in deposit()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.60 |
| rank score | 3.36 |
| rule / detector | MATH-002 / solana_math |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:33 (deposit)` |
| cwe | CWE-682 |
| skill pack | `skills/solana-math/SKILL.md` |

deposit() assigns `ctx.accounts.user_vault.shares = ctx.accounts.user_vault.shares + shares` from an arithmetic expression with no `checked_*`/`Saturating` wrapper. Token amounts are `u64`; in an anchor build with overflow checks on, an overflow panics the instruction (DoS of the account), and anywhere the checks are off - or the value is derived from a cast - it wraps around and produces a tiny or absurd balance.

```rust
ctx.accounts.user_vault.shares = ctx.accounts.user_vault.shares + shares;
```

**Exploit sketch (educational)**

1. Feed an amount near u64::MAX (multi-token deposits, or a manipulated `limiter` multiplier).
1. The accumulation wraps; your recorded share count becomes attacker-controlled.

**Patch sketch**

- `checked_add`/`checked_mul` with a program error on overflow.
- Bound instruction inputs (`require!(amount < MAX_DEPOSIT, ...)`) before arithmetic.
- Cast through `u128` for intermediates.

**PoC stub:** `pocs/sg-sol-022_sg_sol_022_unchecked_arithmetic_.rs` — run with `cargo test --features test-suites sg_sol_022_unchecked_arithmetic_on_shares_in_dep`

**Skill checklist satisfied**

- [x] Arithmetic uses `checked_add/sub/mul/div` or `Saturating`. If the workspace sets
- [x] Intermediates are widened (`u128`) and narrowed only at the end, after bounds checks.

tags: `solana`, `overflow`, `unchecked-math`, `MATH-002`

### SG-SOL-023 — Unchecked arithmetic on `shares` in withdraw()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.60 |
| rank score | 3.36 |
| rule / detector | MATH-002 / solana_math |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:55 (withdraw)` |
| cwe | CWE-682 |
| skill pack | `skills/solana-math/SKILL.md` |

withdraw() assigns `user_vault.shares = user_vault.shares - amount` from an arithmetic expression with no `checked_*`/`Saturating` wrapper. Token amounts are `u64`; in an anchor build with overflow checks on, an overflow panics the instruction (DoS of the account), and anywhere the checks are off - or the value is derived from a cast - it wraps around and produces a tiny or absurd balance.

```rust
user_vault.shares = user_vault.shares - amount;
```

**Exploit sketch (educational)**

1. Feed an amount near u64::MAX (multi-token deposits, or a manipulated `limiter` multiplier).
1. The accumulation wraps; your recorded share count becomes attacker-controlled.

**Patch sketch**

- `checked_add`/`checked_mul` with a program error on overflow.
- Bound instruction inputs (`require!(amount < MAX_DEPOSIT, ...)`) before arithmetic.
- Cast through `u128` for intermediates.

**PoC stub:** `pocs/sg-sol-023_sg_sol_023_unchecked_arithmetic_.rs` — run with `cargo test --features test-suites sg_sol_023_unchecked_arithmetic_on_shares_in_wit`

**Skill checklist satisfied**

- [x] Arithmetic uses `checked_add/sub/mul/div` or `Saturating`. If the workspace sets
- [x] Intermediates are widened (`u128`) and narrowed only at the end, after bounds checks.

tags: `solana`, `overflow`, `unchecked-math`, `MATH-002`

### SG-EVM-023 — Raw ecrecover without malleability checks in claimTreasuryGrant()

| field | value |
| --- | --- |
| severity | **medium** |
| confidence | 0.60 |
| rank score | 3.36 |
| rule / detector | SR-004 / evm_sig_replay |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:88 (claimTreasuryGrant)` |
| cwe | CWE-294 |
| skill pack | `skills/signature-replay/SKILL.md` |

claimTreasuryGrant() calls `ecrecover` directly. Secp256k1 signatures are malleable: (v, r, s) and (v', r, n-s) both recover the same address. Without a high-s rejection, and without restricting v to {27,28}, the same authorisation appears as two different hashes, which breaks any de-duplication or replay map keyed on the payload.

```solidity
address signer = ecrecover(doc, v, r, s);
```

**Exploit sketch (educational)**

1. Take a used signature, flip s to n - s and adjust v.
1. If dedupe keys on the raw payload rather than the recovered digest, the second variant passes.

**Patch sketch**

- Use OpenZeppelin `ECDSA.tryRecover`/`recover` which enforces low-s and v in {27,28}.
- Key replay maps on the eip-712 digest, not on the submitted bytes.

**PoC stub:** `pocs/sg-evm-023_sg_evm_023_raw_ecrecover_without.t.sol` — run with `forge test --match-contract SgEvm023RawEcrecoverWithoutMalleabilityCHarness -vvvv`

**Skill checklist satisfied**

- [x] Malleability is handled by a library (`ECDSA.recover`/`tryRecover`, enforced low-s,

tags: `signature`, `malleability`, `SR-004`

### SG-SOL-024 — `realloc::payer = vault_config` is not a funded signer in Withdraw

| field | value |
| --- | --- |
| severity | **low** |
| confidence | 0.60 |
| rank score | 1.68 |
| rule / detector | AUTH-002 / solana_authority |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:169` |
| cwe | CWE-269 |
| skill pack | `skills/solana-account-validation/SKILL.md` |

`Withdraw` resizes an account and charges the rent delta to `vault_config`, which is not declared in this struct. Solana requires the rent payer of a resize to be a writable, funded signer; a PDA or program-owned account cannot pay it, so the resize fails (availability) or - if the slot can be filled by whoever calls - the cost lands on a third party. This is a design note rather than a proof of theft, which is why it is graded low/medium.

```rust
#[account(mut, seeds = [b"vault", vault_config.key().as_ref()], bump = vault_config.bump, realloc = 8, realloc::payer = vault_config, realloc::zero = false)]
```

**Exploit sketch (educational)**

1. Trigger the realloc path repeatedly so the charged account bleeds lamports it never agreed to.
1. Or front-run the growth so the rent cost lands on the victim's account.

**Patch sketch**

- `#[account(mut)] payer: Signer<'info>` as `realloc::payer`, verified as the tx fee payer.
- Prefer fixed `space` at init over dynamic realloc in value-critical paths.
- If the PDA must fund growth, fund it explicitly with a signed transfer first.

**PoC stub:** `pocs/sg-sol-024_sg_sol_024_realloc_payer_vault_c.rs` — run with `cargo test --features test-suites sg_sol_024_realloc_payer_vault_config_is_not_a_f`

**Skill checklist satisfied**

- [x] SPL accounts assert `owner == token_program`, the right `mint`, and the expected authority

tags: `solana`, `realloc`, `authority-note`, `AUTH-002`

### SG-SOL-025 — Narrowing cast `as u64` on an amount in slash()

| field | value |
| --- | --- |
| severity | **low** |
| confidence | 0.50 |
| rank score | 1.60 |
| rule / detector | MATH-004 / solana_math |
| chain | solana |
| location | `solana/vault/programs/vault/src/lib.rs:67 (slash)` |
| cwe | CWE-682 |
| skill pack | `skills/solana-math/SKILL.md` |

slash() casts through a narrower integer while computing token amounts. Combined with the multiply/divide ordering above, silent truncation is the second half of the precision bug: the math can be right in `u128` and wrong once cast back.

```rust
let shares = (report.amount as u64) * vault.limiter;
```

**Exploit sketch (educational)**

1. Choose inputs whose intermediate exceeds the target width.
1. The truncated value becomes the share/balance the program trusts.

**Patch sketch**

- Keep intermediates in `u128` and cast only at the end, after bounds checks.
- Add a unit test around `u64::MAX / 2` sized amounts.

**PoC stub:** `pocs/sg-sol-025_sg_sol_025_narrowing_cast_as_u64.rs` — run with `cargo test --features test-suites sg_sol_025_narrowing_cast_as_u64_on_an_amount_in`

**Skill checklist satisfied**

- [x] `as` casts are reviewed for truncation (`u128 as u64`, `i64 as u64`).
- [x] Multiplication happens **before** division; division-first expressions are precision-loss

tags: `solana`, `cast`, `precision`, `MATH-004`

### SG-EVM-024 — Native `.transfer()` gas-stipend transfer in claimTreasuryGrant()

| field | value |
| --- | --- |
| severity | **low** |
| confidence | 0.50 |
| rank score | 1.60 |
| rule / detector | EC-003 / evm_external_calls |
| chain | hyperevm |
| location | `solidity/HyperVault.sol:90 (claimTreasuryGrant)` |
| cwe | CWE-252 |
| skill pack | `skills/external-calls/SKILL.md` |

claimTreasuryGrant() forwards value with `.transfer/send()`, which forwards exactly 2300 gas. That is enough for a plain wallet but not for most smart-contract recipients, so payments to contracts (multisigs, other vaults, account-abstraction wallets) fail - and on HyperEVM the stipend assumption has changed more than once. Reported as low because it is availability, not theft.

```solidity
payable(msg.sender).transfer(amount);
```

**Exploit sketch (educational)**

1. No attacker needed: legitimate users with contract wallets simply cannot be paid.
1. If the result is unchecked, the contract marks the payout as done anyway.

**Patch sketch**

- Prefer withdrawal patterns the user triggers, with `Address.sendValue` + checked result.
- Never assume 2300 gas is enough for every recipient.

**PoC stub:** `pocs/sg-evm-024_sg_evm_024_native_transfer_gas_s.t.sol` — run with `forge test --match-contract SgEvm024NativeTransferGasStipendTransferHarness -vvvv`

**Skill checklist satisfied**

- [x] The 2300-gas stipend of `send`/`transfer` is acceptable for every plausible recipient

tags: `gas-stipend`, `availability`, `EC-003`

---

## Honesty notes

- SolGuardian is a **heuristic** static tool. Every finding carries a confidence score; anything below 0.6 is a review prompt, not a verdict.
- Detectors are deterministic code (see `solguardian/detectors/`), so this report reproduces byte-for-byte without spending model tokens.
- No live exploit code is emitted: PoC files are commented skeletons against the synthetic samples in `samples/`.
- Proof-of-storage, gas-cost modelling, and cross-contract composition are out of scope by design (see README).

## Skill packs used

| skill | applies to | checklist items |
| --- | --- | ---: |
| `skills/access-control/SKILL.md` | evm, hyperevm | 7 |
| `skills/delegatecall-proxy/SKILL.md` | evm, hyperevm | 7 |
| `skills/external-calls/SKILL.md` | evm, hyperevm | 6 |
| `skills/fund-recovery/SKILL.md` | evm, hyperevm | 7 |
| `skills/hyperliquid-hyperevm-notes/SKILL.md` | hyperevm, evm | 7 |
| `skills/oracle-price/SKILL.md` | evm, hyperevm | 7 |
| `skills/poc-stubs/SKILL.md` | evm, hyperevm, solana | 7 |
| `skills/reentrancy/SKILL.md` | evm, hyperevm | 8 |
| `skills/severity-grading/SKILL.md` | evm, hyperevm, solana | 11 |
| `skills/signature-replay/SKILL.md` | evm, hyperevm | 7 |
| `skills/solana-account-validation/SKILL.md` | solana | 9 |
| `skills/solana-cpi/SKILL.md` | solana | 8 |
| `skills/solana-math/SKILL.md` | solana | 7 |
| `skills/solana-signer/SKILL.md` | solana | 7 |
