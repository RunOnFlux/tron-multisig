// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// One outgoing action of a vault operation.
/// - Plain TRX:      data empty, value > 0, tokenValue == 0.
/// - TRC-20 / call:  data = ABI calldata, value = TRX to attach (usually 0), tokenValue == 0.
/// - TRC-10:         tokenValue > 0 and tokenId != 0; data MUST be empty and value MUST be 0
///                   (the TVM only moves TRC-10 through `transferToken`, never with calldata).
/// `to` is the 20-byte TVM address (TRON base58 minus the 0x41 prefix).
/// A TRX or TRC-10 amount must fit an int64 and must not go to the vault itself or to a precompile address
/// (1 .. 0xffffffff): the TVM would halt instead of failing the call, so these revert BadCall(index).
/// A call with non-empty `data` must target an account WITH code (the TVM treats a call to a code-less
/// account as a successful no-op): otherwise BadCall(index). Plain TRX (empty data) to an EOA is fine.
struct Call {
    address to;
    uint256 value;
    bytes data;
    uint256 tokenId;
    uint256 tokenValue;
}

/// Network fee the members sign. Paid by the vault in the SAME transaction, before the calls.
/// token == address(0) pays TRX; any other address is a TRC-20 paid with a balance-checked transfer.
/// amount == 0 means no fee (self-submitted operations).
/// FeeFailed if recipient is address(0) or the vault itself, or (TRX) the amount does not fit an int64 or
/// the recipient is a precompile address.
struct Fee {
    address token;
    uint256 amount;
    address recipient;
}

/// A signed vault operation (TIP-712 typed data, domain = the vault clone).
struct Op {
    Call[] calls;
    uint256 nonce;
    uint256 deadline;
    Fee fee;
}

/// @title SSP TRON vault
/// @notice Every vault is an EIP-1167 clone of one immutable implementation, deployed with CREATE2 by
///         SSPVaultFactory. Its only immutable argument is
///             configHash = keccak256(abi.encodePacked(CONFIG_TAG, uint8 threshold, bytes signers))
///         where `signers` is n x 20-byte addresses, strictly ascending. There is no owner, no admin and
///         no upgrade path: M of the configured signers can do everything, nobody else can do anything.
interface ISSPVault {
    event Executed(bytes32 indexed digest, uint256 indexed nonce, address indexed submitter, uint256 callCount);
    event FeePaid(address indexed token, address indexed recipient, uint256 amount);
    event NoncesInvalidated(uint256 indexed word, uint256 mask);

    error BadConfig();
    error BadSignatureCount();
    error Expired();
    error TooManyCalls();
    error NonceAlreadyUsed();
    error BadSignature();
    error SignatureOrder();
    error NotASigner();
    error BadCall(uint256 index);
    error CallFailed(uint256 index, bytes reason);
    error FeeFailed();
    error OnlySelf();
    error BadResource();

    /// Verify `threshold` signatures over the TIP-712 digest of `op` and execute it.
    /// @param signers    n x 20-byte signer addresses, strictly ascending (must hash to configHash).
    /// @param threshold  M (must hash to configHash).
    /// @param op         the operation.
    /// @param signatures threshold x 65-byte r||s||v (v = 27/28, low-s), ordered by ascending
    ///                   recovered signer address.
    /// Not payable: TRX attached here would not be covered by the signatures. Fund a vault with a
    /// plain transfer instead.
    function execute(bytes calldata signers, uint8 threshold, Op calldata op, bytes calldata signatures) external;

    /// Mark nonces as used without executing anything (cancels already-signed operations).
    /// Only callable by the vault itself, i.e. through a threshold-signed `execute` call to the vault.
    function invalidateNonces(uint256 word, uint256 mask) external;

    /// TRC-1271. `bundle = abi.encode(bytes signers, uint8 threshold, bytes signatures)`; the signatures
    /// are over the TIP-712 digest of `SSPVaultMessage(bytes32 hash)` in this vault's domain, never over
    /// an Op digest, so an Op signature can never be replayed as a message signature (or vice versa).
    function isValidSignature(bytes32 hash, bytes calldata bundle) external view returns (bytes4);

    // ----------------------------------------------------------------- Stake 2.0 (TIP-467), self only
    // resource: 0 = BANDWIDTH, 1 = ENERGY (anything else reverts BadResource). Delegation receivers must be
    // plain accounts (the TVM rejects delegation to contracts).
    function freezeBalanceV2(uint256 amount, uint256 resource) external;
    function unfreezeBalanceV2(uint256 amount, uint256 resource) external;
    function withdrawExpireUnfreeze() external returns (uint256 amount);
    function cancelAllUnfreezeV2() external;
    function delegateResource(address payable receiver, uint256 amount, uint256 resource) external;
    function undelegateResource(address payable receiver, uint256 amount, uint256 resource) external;
    /// Named `voteWitnesses` because a function called `vote` would shadow the TVM `vote` builtin.
    function voteWitnesses(address[] calldata srs, uint256[] calldata votes) external;
    function withdrawReward() external returns (uint256 amount);

    // ----------------------------------------------------------------- views
    function configHash() external view returns (bytes32);
    function domainSeparator() external view returns (bytes32);
    /// Full TIP-712 digest (0x1901 || domainSeparator || hashStruct(op)) that the signers sign.
    function hashOp(Op calldata op) external view returns (bytes32);
    /// Full TIP-712 digest of SSPVaultMessage(hash).
    function hashMessage(bytes32 hash) external view returns (bytes32);
    function nonceBitmap(uint256 word) external view returns (uint256);
    function isNonceUsed(uint256 nonce) external view returns (bool);
    function VERSION() external view returns (string memory);
}
