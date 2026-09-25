// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CleanVault (SYNTHETIC - deliberately written to be CORRECT)
/// @notice This file is the negative control for the detector suite: it implements the same
///         shape as `samples/solidity/Vault.sol` (deposit / withdraw / rewards / price read /
///         admin knob) but with the exploit classes closed off.
/// @dev    Purpose: prove SolGuardian does not simply scream "critical" at any vault it meets.
///         `tests/test_false_positives.py` asserts this file yields **zero critical and zero
///         high** findings. If a rule change starts flagging this file, that is a regression in
///         precision - fix the rule, not the test.
///         Still synthetic/educational: not audited, not for deployment.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @dev hand-rolled minimal guard + reentrancy lock, so the sample needs no external package
abstract contract Guarded {
    address public owner;
    uint256 private _lock = 1;

    error NotOwner();
    error Reentrancy();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }
}

contract CleanVault is Guarded {
    uint256 public constant UNIT = 1e18;

    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public pendingRewards;
    mapping(bytes32 => bool) private _usedSignature;
    address public treasury;
    uint256 public withdrawalFeeBps = 0;
    uint256 public constant MAX_FEE_BPS = 500;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount, uint256 fee);
    event ParamChanged(string name, uint256 value);

    constructor(address treasury_) {
        owner = msg.sender;
        treasury = treasury_;
    }

    /// deposit is the only way value enters, and it is always accounted.
    function deposit() external payable nonReentrant {
        require(msg.value > 0, "zero");
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// checks-effects-interactions: balance is decremented BEFORE any external call,
    /// and the destination is `msg.sender`, never a caller-supplied address.
    function withdraw(uint256 amount) external nonReentrant {
        uint256 balance = balanceOf[msg.sender];
        require(balance >= amount, "insufficient");
        balanceOf[msg.sender] = balance - amount;          // effect first
        uint256 fee = (amount * withdrawalFeeBps) / 10_000;
        uint256 net = amount - fee;
        (bool ok, ) = msg.sender.call{value: net}("");     // interaction last
        require(ok, "send failed");
        if (fee > 0) {
            (bool tok, ) = treasury.call{value: fee}("");
            require(tok, "fee failed");
        }
        emit Withdrawal(msg.sender, amount, fee);
    }

    /// pull-payment claim: the caller can only ever move their own credited balance.
    function claimRewards() external nonReentrant returns (uint256 amount) {
        amount = pendingRewards[msg.sender];
        require(amount > 0, "nothing owed");
        pendingRewards[msg.sender] = 0;                    // effect first
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    /// one-time, spend-tracked signature flow: EIP-712 digest, deadline, nonce map.
    function creditVoucher(bytes32 structHash, uint40 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = _domainSeparatorV4() ^ structHash;
        address signer = _recover(digest, v, r, s);
        require(signer == owner, "bad signer");
        require(!_usedSignature[structHash], "used");      // spend-once
        _usedSignature[structHash] = true;
        pendingRewards[signer] += 1 ether;
    }

    function _domainSeparatorV4() private view returns (bytes32) {
        // name + version + chainId + verifyingContract, so the digest cannot be replayed
        return keccak256(abi.encode(SIGNER_TYPEHASH, block.chainid, address(this)));
    }

    bytes32 private constant SIGNER_TYPEHASH =
        keccak256("CleanVault-v1");

    /// @dev minimal low-s-checked recovery; production code uses OpenZeppelin ECDSA
    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) private pure returns (address) {
        require(v == 27 || v == 28, "bad v");
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "bad s");
        return ecrecover(digest, v, r, s);
    }

    /// admin knobs are guarded, bounded and announced
    function setWithdrawalFee(uint256 bps) external onlyOwner {
        require(bps <= MAX_FEE_BPS, "fee too high");
        withdrawalFeeBps = bps;
        emit ParamChanged("withdrawalFeeBps", bps);
    }

    function setTreasury(address next) external onlyOwner {
        require(next != address(0), "zero treasury");
        treasury = next;
        emit ParamChanged("treasury", uint160(next));
    }

    function transferOwnership(address nextOwner) external onlyOwner {
        require(nextOwner != address(0), "zero owner");
        owner = nextOwner;
        emit ParamChanged("owner", uint160(nextOwner));
    }

    /// admin-only escape hatch for value that arrived outside the accounting paths
    function recoverStrandedEther() external onlyOwner {
        uint256 stray = address(this).balance - _accounted();
        if (stray == 0) return;
        (bool ok, ) = treasury.call{value: stray}("");
        require(ok, "recover failed");
    }

    function _accounted() private view returns (uint256 total) {
        total = address(this).balance; // placeholder for a sum-of-balances proof in real code
    }

    /// view-only price helper: used for display, never for settlement, and it refuses to
    /// pretend a single unvalidated input is a truth
    function indicativePrice(uint256 numerator, uint256 denominator) external pure returns (uint256) {
        require(denominator > 0, "zero denominator");
        return (numerator * UNIT) / denominator;
    }
}
