// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Vault (SYNTHETIC TEACHING SAMPLE - intentionally seeded, do not deploy)
/// @notice Written for the SolGuardian demo. Not derived from any real protocol,
///         no client data, no mainnet addresses. Each seeded issue is tagged so the
///         detector suite can be scored against ground truth (see samples/EXPECTED_FINDINGS.json).
/// @dev    Seeded issues:
///           1. reentrancy in withdraw()            (state written after external call)
///           2. missing access control on adminDrain()
///           3. tx.origin authentication in setOperator()
///           4. unchecked external-call return in refundPending()
///           5. spot-price oracle assumption in assetValue()
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IAggregator {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract Vault {
    address public owner;
    uint256 public totalDeposits;
    uint256 public constant UNIT = 1e18;

    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public operators;

    IERC20 public rewardToken;
    IAggregator public priceFeed;
    IUniswapV2Pair public pool;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "vault: not owner");
        _;
    }

    constructor(address token_, address feed_, address pool_) {
        owner = msg.sender;
        rewardToken = IERC20(token_);
        priceFeed = IAggregator(feed_);
        pool = IUniswapV2Pair(pool_);
    }

    receive() external payable {
        // accounting-less ingress: ETH landing here is not tracked in balanceOf
    }

    function deposit() external payable {
        require(msg.value > 0, "zero");
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @custom:seeded reentrancy
    /// @dev BUG #1: external call happens before the accounting update, so a callback
    ///      re-entering withdraw() still sees the old balance.
    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "vault: insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "vault: send failed");
        balanceOf[msg.sender] -= amount;
        totalDeposits -= amount;
        emit Withdraw(msg.sender, amount);
    }

    /// @custom:seeded access-control
    /// @dev BUG #2: anyone can empty the vault. No onlyOwner, no operator check.
    function adminDrain(address to, uint256 amount) external {
        uint256 payout = amount == 0 ? address(this).balance : amount;
        (bool sent, ) = to.call{value: payout}("");
        require(sent, "drain failed");
        totalDeposits = 0;
    }

    /// @custom:seeded tx-origin-auth
    /// @dev BUG #3: tx.origin authentication is phishing-able through a malicious
    ///      intermediate contract.
    function setOperator(address op) external {
        require(tx.origin == owner, "vault: not owner (tx.origin)");
        operators[op] = true;
    }

    function mintReward(address user, uint256 amount) external {
        require(operators[msg.sender], "vault: not operator");
        pendingRewards[user] += amount;
    }

    /// @custom:seeded unchecked-call
    /// @dev BUG #4: ERC20.transfer return value discarded - silent failure on tokens
    ///      that return false instead of reverting.
    function refundPending(address user) public returns (uint256 paid) {
        uint256 owed = pendingRewards[user];
        if (owed == 0) {
            return 0;
        }
        pendingRewards[user] = 0;
        rewardToken.transfer(user, owed);
        return owed;
    }

    /// @custom:seeded oracle-spot-price
    /// @dev BUG #5: mark-to-market from an in-pool spot price plus a single feed with
    ///      no round/staleness check. Both inputs are cheap to move in a flash loan.
    function assetValue() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pool.getReserves();
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        uint256 spot = (uint256(answer) * reserve1) / uint256(reserve0);
        return (totalDeposits * spot) / UNIT;
    }

    function ethEquivalent(uint256 shares) external view returns (uint256) {
        return (shares * UNIT) / (assetValue() + 1);
    }

    function setPriceFeed(address feed) external {
        priceFeed = IAggregator(feed);
    }
}
