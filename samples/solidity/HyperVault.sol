// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HyperVault (SYNTHETIC TEACHING SAMPLE - HyperEVM style, intentionally seeded)
/// @notice A made-up "lend against Hyperliquid perp exposure" vault shaped like HyperEVM
///         Solidity (EVM bytecode, HyperCore oracle reads emulated behind an interface).
///         No real Hyperliquid contract, address or message format is reproduced.
/// @dev    Seeded issues:
///           6. dangerous delegatecall to an operator-chosen target (upgrade/migrate path)
///           7. signature replay: no nonce, no deadline, no chainid/address binding
///           8. reachable selfdestruct with a caller-chosen beneficiary
///           9. stuck funds: owner-gated recovery behind an address that is never set
interface IHyperCorePriceOracle {
    /// @notice emulated HIP-3 style spot read; real integrations use the HyperCore precompile
    function spotPrice(address asset) external view returns (uint256);
}

contract HyperVault {
    struct Position {
        uint256 collateral;
        uint256 borrowed;
        bool open;
    }

    address public admin;
    address public pendingAdmin;
    address public implementation;
    uint256 public reserveFactorBps = 500;
    bool public frozen;

    IHyperCorePriceOracle public oracle;
    mapping(address => Position) public positions;
    mapping(bytes32 => bool) public usedProofs;

    event Log(uint256 value);

    modifier onlyAdmin() {
        require(msg.sender == admin, "hyprivault: not admin");
        _;
    }

    constructor(address oracle_) {
        admin = msg.sender;
        oracle = IHyperCorePriceOracle(oracle_);
    }

    receive() external payable {}

    /// @custom:seeded dangerous-delegatecall
    /// @dev BUG #6: logic migration via delegatecall into an arbitrary target chosen by the
    ///      operator. The callee runs in this contract's storage context and can selfdestruct
    ///      or rewrite `positions`.
    function migrate(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "hyprivault: migrate failed");
    }

    /// @custom:seeded missing-access-control
    /// @dev BUG: implementation pointer updatable by anyone, pairs with BUG #6.
    function setImplementation(address newImpl) external {
        implementation = newImpl;
    }

    function openPosition(uint256 collateral) external payable {
        Position storage p = positions[msg.sender];
        p.collateral += msg.value;
        p.open = true;
    }

    function priceOf(address asset) public view returns (uint256) {
        /// @custom:seeded oracle-single-feed
        /// @dev BUG: single HyperCore spot read, no deviation / staleness guard against a
        ///      second source, so one manipulated print moves every liquidation.
        return oracle.spotPrice(asset);
    }

    function liquidationValue(address user) external view returns (uint256) {
        Position memory p = positions[user];
        uint256 price = priceOf(address(this));
        return (p.collateral * price) / 1e18 > p.borrowed ? (p.collateral * price) / 1e18 : 0;
    }

    /// @custom:seeded signature-replay
    /// @dev BUG #7: treasury signature is never bound to a nonce, deadline, chain id or this
    ///      contract address, and raw ecrecover is used with no malleability check, so one
    ///      signature can be replayed (repeatedly, on every fork, on every deployment).
    function claimTreasuryGrant(bytes32 doc, uint8 v, bytes32 r, bytes32 s, uint256 amount) external {
        address signer = ecrecover(doc, v, r, s);
        require(signer == admin, "hyprivault: bad signature");
        payable(msg.sender).transfer(amount);
        positions[msg.sender].borrowed += amount;
    }

    function setReserveFactor(uint256 bps) external {
        reserveFactorBps = bps;
    }

    /// @custom:seeded selfdestruct
    /// @dev BUG #8: destruct reachable by an operator with a caller-chosen beneficiary, i.e.
    ///      the whole ETH balance can be pushed to any address in the same transaction.
    function decommission(address payable beneficiary) external {
        selfdestruct(beneficiary);
    }

    /// @custom:seeded stuck-funds
    /// @dev BUG #9: the only withdrawal path is gated on `pendingAdmin`, which is never
    ///      assigned anywhere in this contract, so deposited ETH and ERC20 balances are stranded.
    function recoverTokens(address token, address to, uint256 amount) external {
        require(msg.sender == pendingAdmin, "hyprivault: not pending admin");
        (bool ok, ) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        ok;
    }

    function setFrozen(bool value) external onlyAdmin {
        frozen = value;
    }
}
