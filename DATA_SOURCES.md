# DATA_SOURCES.md

Every input this project used, and the rules that kept it that way. Required by the hackathon
data policy: synthetic/teaching data and public documentation only — no client data, no
company-confidential material, no personal information, no social scrapes.

## 1. Code that ships in this repo

| item | origin |
| --- | --- |
| `solguardian/**` (core, detectors, report, agents) | written for this project |
| `skills/*/SKILL.md` | written for this project, distilled from public security documentation (§3) |
| `samples/**` | written for this project — synthetic teaching contracts with deliberate bugs |
| `tests/**` | written for this project |
| `report/templates/foundry_stub.t.sol`, `anchor_stub.rs` | written for this project |

Nothing was copied from another repository, another hackathon project, or any audit report of
a specific protocol. No vendored dependencies: the analyzer is **Python standard library only**
(`re`, `os`, `json`, `argparse`, `dataclasses`, `enum`, `bisect`, `concurrent.futures`,
`unittest`, `time`, `html`). License: MIT.

## 2. Sample contracts

`samples/solidity/Vault.sol`, `samples/solidity/HyperVault.sol`,
`samples/solana/vault/programs/vault/src/lib.rs` and the `samples/clean/` control pair are
original, fictional code:

- no real token addresses, no mainnet contract addresses, no deployed program IDs
  (`SGUARD1an1cSynth3t1cVau1tPr0gr3mXXXXXXXXXXX` is a made-up, non-existent pubkey);
- no protocol is named or imitated — `Vault`/`HyperVault` are generic shapes (deposit,
  withdraw, price read, admin knob) chosen to host one instance of each exploit class;
- every seeded issue carries a `/// @custom:seeded <class>` (Solidity) or `// @seeded <class>`
  (Rust) tag, and the full list is machine-readable in `samples/EXPECTED_FINDINGS.json`;
- the interfaces they import (`IERC20`, `IUniswapV2Pair`, `IAggregator`,
  `IHyperCorePriceOracle`) are minimal local declarations written for these samples, so the
  files parse without any third-party package.

`samples/README.md` documents the seed set; the PoC stubs SolGuardian emits reference only these
files.

## 3. Public documentation used as background for the checklists

The skills packs encode widely published, non-negotiable engineering practice. Sources are
public docs and standards, not case-specific exploit write-ups:

- **Solidity documentation** — external function call semantics, `send`/`transfer`/`call`,
  checked vs unchecked arithmetic, `tx.origin` warnings.
- **OpenZeppelin Contracts docs & audit guidelines** — `ReentrancyGuard`, `AccessControl`,
  `SafeERC20`, `EIP712`/`ECDSA` (low-s and `v` validation), UUPS/Transparent proxy and
  upgrade-authorisation guidance, "pull over push" payments.
- **SWC Registry** (Smart Contract Weakness Classification) — the CWE ids cited on findings
  (CWE-841, CWE-284, CWE-252, CWE-471, CWE-1231, CWE-294, CWE-287, CWE-269, CWE-863, CWE-682,
  CWE-125).
- **EIPs / Ethereum specs** — EIP-712 typed structured data, EIP-1967 proxy storage slots,
  EIP-678 (`SELFDESTRUCT` post-Dencun semantics).
- **Chainlink data-feed documentation** — `latestRoundData` round-integrity and `updatedAt`
  freshness checks, deviation/heartbeat behaviour.
- **Uniswap V2 documentation** — `getReserves` as a spot price and why it is manipulable.
- **Anchor Book / `anchor-lang` docs** — `Accounts` derive constraints (`init`, `mut`,
  `has_one`, `seeds`, `bump`, `realloc`, `associated_token`, `token::`), `Program` vs
  `UncheckedAccount` vs `Signer`, `Context<'_, '_, '_, 'info, T<'info>>`, CPI with
  `invoke`/`invoke_signed`, `remaining_accounts` semantics.
- **Solana program-security documentation** — three critical validation rules (ownership,
  signature, derivation), the account-confusion class, PDA/bump derivation, `is_program`
  checks, token-owner requirements.
- **Hyperliquid docs (public HyperEVM / HyperCore descriptions)** — used *only* for the trust
  assumptions written up in `skills/hyperliquid-hyperevm-notes/SKILL.md` (bridged canonical
  assets, HyperCore price reads as consensus inputs, distinct fee/finality model). No
  proprietary or non-public interface was reproduced, and the sample oracle interface is our
  own emulation of a spot-price read.

## 4. Tools and models

- **IBM Bob 2.0 IDE** — development environment for the project (Agent mode, parallel
  subagents, document understanding, review/commit flow). Task evidence: `bob_sessions/`.
- **No LLM anywhere in the scan path.** Detectors, ranking and grading are deterministic Python;
  a language model cannot create, rank or grade a finding. Where a model helped with prose in
  the build process, that work is visible as Bob task sessions.
- No paid API keys, no RPC provider accounts, no cloud services required to run or test the
  tool.

## 5. Explicitly *not* used

- No client or employer code, and no code from any audit engagement.
- No personal data: no names, wallets, emails or addresses of real users in samples or output.
- No social-media scraping, no forum/NFT/whale-wallet datasets.
- No private/incident exploit databases, no copy of a specific historical attack contract.
- No mainnet fork, no live transaction, no deployed exploit, no testnet funds.
- No third-party scanner output rebranded as ours (SolGuardian's findings come from its own
  detectors).

## 6. Reproducibility

Everything above is offline and deterministic:

```bash
python3 -m unittest discover -s tests -v          # includes a determinism assertion
python3 -m solguardian analyze samples --out out/samples --html
git diff --stat out/            # empty: the report reproduces byte-for-byte
```
