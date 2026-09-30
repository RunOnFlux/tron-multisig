// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {TIP712} from "@openzeppelin/tron-contracts/utils/cryptography/TIP712.sol";
import {ECDSA} from "@openzeppelin/tron-contracts/utils/cryptography/ECDSA.sol";
import {SafeTRC20} from "@openzeppelin/tron-contracts/token/TRC20/utils/SafeTRC20.sol";
import {ITRC20} from "@openzeppelin/tron-contracts/token/TRC20/ITRC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/tron-contracts/utils/ReentrancyGuardTransient.sol";
import {ISSPVault, Op, Call, Fee} from "./interfaces/ISSPVault.sol";

/// @title SSPVault — implementation behind every SSP TRON vault clone
/// @notice Never used directly. Each vault is an EIP-1167 clone (deployed by SSPVaultFactory) whose
///         runtime code carries one 32-byte immutable argument, `configHash`. Signers and threshold are
///         supplied on every call and must hash to it. There is no owner, admin, guardian, module
///         system or upgrade path.
/// @dev TVM rules this contract relies on (verified on java-tron 4.8.2.2, see tron-spike/RESULTS.md):
///      - the ecrecover precompile returns a dirty `0x41||addr` word: recovered addresses are masked
///        explicitly before any arithmetic comparison;
///      - TRON USDT's `transfer` returns false on success: TRC-20 fees use SafeTRC20.safeTransferChecked;
///      - TRX/TRC-10 can be force-sent without running code: no internal balance accounting exists;
///      - `block.timestamp` is in seconds; `block.chainid & 0xffffffff` is the TIP-712 chain id;
///      - the EIP-1167 DELEGATECALL does not forward a call's TRC-10 token value, so non-payable guards in
///        this implementation never see TRC-10 attached to a call on a clone: such TRC-10 simply lands in
///        the vault as a deposit (like a TransferAssetContract), spendable only by a signed Op;
///      - a CALL forwards ALL remaining energy (no EIP-150 63/64 rule): a call target that loops or hits
///        INVALID makes the whole transaction OUT_OF_ENERGY. Sponsors must only sponsor known targets.
contract SSPVault is ISSPVault, TIP712, ReentrancyGuardTransient {
    string public constant VERSION = "1";

    bytes32 public constant CONFIG_TAG = keccak256("SSP_TRON_VAULT_CONFIG_V1");
    uint256 public constant MAX_SIGNERS = 40;
    uint256 public constant MAX_CALLS = 16;

    bytes32 public constant CALL_TYPEHASH =
        keccak256("Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)");
    bytes32 public constant FEE_TYPEHASH = keccak256("Fee(address token,uint256 amount,address recipient)");
    bytes32 public constant OP_TYPEHASH = keccak256(
        "Op(Call[] calls,uint256 nonce,uint256 deadline,Fee fee)"
        "Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)"
        "Fee(address token,uint256 amount,address recipient)"
    );
    bytes32 public constant MESSAGE_TYPEHASH = keccak256("SSPVaultMessage(bytes32 hash)");

    bytes4 private constant TRC1271_MAGIC = 0x1626ba7e;
    bytes4 private constant TRC1271_INVALID = 0xffffffff;
    uint256 private constant ADDRESS_MASK = 0x00ffffffffffffffffffffffffffffffffffffffff;
    /// EIP-1167 runtime length; the 32-byte configHash follows it in every clone's code.
    uint256 private constant CLONE_RUNTIME = 0x2d;

    /// Permit2-style unordered nonces: word = nonce >> 8, bit = nonce & 255.
    mapping(uint256 word => uint256 bits) public nonceBitmap;

    /// The implementation's own address; execution is refused there (it has no configHash).
    address private immutable _implementation;

    /// Result of signature verification; `execute` maps each failure to its own error.
    enum SigCheck {
        Ok,
        BadSignature,
        SignatureOrder,
        NotASigner
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    /// Stake 2.0 resources: 0 = BANDWIDTH, 1 = ENERGY. Rejecting anything else keeps what the signing
    /// devices display (the SDK decodes only these two) equal to what executes.
    modifier validResource(uint256 resource) {
        if (resource > 1) revert BadResource();
        _;
    }

    constructor() TIP712("SSP Vault", "1") {
        _implementation = address(this);
    }

    receive() external payable {}

    // ------------------------------------------------------------------ execution

    /// @inheritdoc ISSPVault
    function execute(bytes calldata signers, uint8 threshold, Op calldata op, bytes calldata signatures)
        external
        nonReentrant
    {
        _requireConfig(signers, threshold);
        if (signatures.length != uint256(threshold) * 65) revert BadSignatureCount();
        if (block.timestamp > op.deadline) revert Expired();
        uint256 callCount = op.calls.length;
        if (callCount > MAX_CALLS) revert TooManyCalls();

        // Signatures first (pure: ecrecover only), so an invalid operation reverts before paying for the
        // nonce write. Then effects before interactions: the nonce is burned before any external call.
        bytes32 digest = _hashTypedDataV4(_hashOp(op));
        SigCheck result = _checkSignatures(digest, signers, threshold, signatures);
        if (result == SigCheck.BadSignature) revert BadSignature();
        if (result == SigCheck.SignatureOrder) revert SignatureOrder();
        if (result == SigCheck.NotASigner) revert NotASigner();

        _useNonce(op.nonce);

        for (uint256 i; i < callCount; ++i) {
            _performCall(i, op.calls[i]);
        }
        _payFee(op.fee);

        emit Executed(digest, op.nonce, msg.sender, callCount);
    }

    /// @inheritdoc ISSPVault
    function invalidateNonces(uint256 word, uint256 mask) external onlySelf {
        nonceBitmap[word] |= mask;
        emit NoncesInvalidated(word, mask);
    }

    /// @inheritdoc ISSPVault
    function isValidSignature(bytes32 hash, bytes calldata bundle) external view returns (bytes4) {
        (bytes memory signers, uint8 threshold, bytes memory signatures) =
            abi.decode(bundle, (bytes, uint8, bytes));
        if (!_isConfig(signers, threshold)) return TRC1271_INVALID;
        if (signatures.length != uint256(threshold) * 65) return TRC1271_INVALID;
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, hash)));
        return _checkSignaturesMemory(digest, signers, threshold, signatures) == SigCheck.Ok
            ? TRC1271_MAGIC
            : TRC1271_INVALID;
    }

    // ------------------------------------------------------------------ Stake 2.0 (TIP-467), self only

    /// @inheritdoc ISSPVault
    function freezeBalanceV2(uint256 amount, uint256 resource) external onlySelf validResource(resource) {
        freezebalancev2(amount, resource);
    }

    /// @inheritdoc ISSPVault
    function unfreezeBalanceV2(uint256 amount, uint256 resource) external onlySelf validResource(resource) {
        unfreezebalancev2(amount, resource);
    }

    /// @inheritdoc ISSPVault
    function withdrawExpireUnfreeze() external onlySelf returns (uint256 amount) {
        amount = withdrawexpireunfreeze();
    }

    /// @inheritdoc ISSPVault
    function cancelAllUnfreezeV2() external onlySelf {
        cancelallunfreezev2();
    }

    /// @inheritdoc ISSPVault
    function delegateResource(address payable receiver, uint256 amount, uint256 resource) external onlySelf validResource(resource) {
        receiver.delegateResource(amount, resource);
    }

    /// @inheritdoc ISSPVault
    function undelegateResource(address payable receiver, uint256 amount, uint256 resource) external onlySelf validResource(resource) {
        receiver.unDelegateResource(amount, resource);
    }

    /// @inheritdoc ISSPVault
    function voteWitnesses(address[] calldata srs, uint256[] calldata votes) external onlySelf {
        address[] memory srList = srs;
        uint256[] memory voteList = votes;
        vote(srList, voteList);
    }

    /// @inheritdoc ISSPVault
    function withdrawReward() external onlySelf returns (uint256 amount) {
        amount = withdrawreward();
    }

    // ------------------------------------------------------------------ token receiver hooks

    function onTRC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onTRC721Received.selector;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    // ------------------------------------------------------------------ views

    /// @inheritdoc ISSPVault
    function configHash() public view returns (bytes32 h) {
        if (address(this) == _implementation) revert BadConfig();
        uint256 size;
        assembly ("memory-safe") {
            size := extcodesize(address())
        }
        if (size != CLONE_RUNTIME + 32) revert BadConfig();
        assembly ("memory-safe") {
            // Under DELEGATECALL, CODECOPY would read the implementation: read the clone's own code.
            extcodecopy(address(), 0x00, CLONE_RUNTIME, 32)
            h := mload(0x00)
        }
    }

    /// @inheritdoc ISSPVault
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @inheritdoc ISSPVault
    function hashOp(Op calldata op) external view returns (bytes32) {
        return _hashTypedDataV4(_hashOp(op));
    }

    /// @inheritdoc ISSPVault
    function hashMessage(bytes32 hash) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, hash)));
    }

    /// @inheritdoc ISSPVault
    function isNonceUsed(uint256 nonce) external view returns (bool) {
        return nonceBitmap[nonce >> 8] & (1 << (nonce & 0xff)) != 0;
    }

    // ------------------------------------------------------------------ internals

    function _requireConfig(bytes calldata signers, uint8 threshold) private view {
        uint256 len = signers.length;
        if (len == 0 || len % 20 != 0 || len / 20 > MAX_SIGNERS) revert BadConfig();
        if (threshold == 0 || threshold > len / 20) revert BadConfig();
        if (keccak256(abi.encodePacked(CONFIG_TAG, threshold, signers)) != configHash()) revert BadConfig();
        // Defence in depth: the configHash was built from a sorted list, but never trust that. A strictly
        // ascending list also rules out duplicate signers.
        uint256 prev;
        for (uint256 i; i < len / 20; ++i) {
            uint256 s = _signerAtCalldata(signers, i);
            if (s <= prev) revert BadConfig();
            prev = s;
        }
    }

    function _isConfig(bytes memory signers, uint8 threshold) private view returns (bool) {
        uint256 len = signers.length;
        if (len == 0 || len % 20 != 0 || len / 20 > MAX_SIGNERS) return false;
        if (threshold == 0 || threshold > len / 20) return false;
        if (keccak256(abi.encodePacked(CONFIG_TAG, threshold, signers)) != configHash()) return false;
        uint256 prev;
        for (uint256 i; i < len / 20; ++i) {
            uint256 s = _signerAtMemory(signers, i);
            if (s <= prev) return false;
            prev = s;
        }
        return true;
    }

    function _useNonce(uint256 nonce) private {
        uint256 word = nonce >> 8;
        uint256 bit = 1 << (nonce & 0xff);
        uint256 current = nonceBitmap[word];
        if (current & bit != 0) revert NonceAlreadyUsed();
        nonceBitmap[word] = current | bit;
    }

    function _hashOp(Op calldata op) private pure returns (bytes32) {
        uint256 len = op.calls.length;
        bytes32[] memory callHashes = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            Call calldata c = op.calls[i];
            callHashes[i] =
                keccak256(abi.encode(CALL_TYPEHASH, c.to, c.value, keccak256(c.data), c.tokenId, c.tokenValue));
        }
        bytes32 feeHash = keccak256(abi.encode(FEE_TYPEHASH, op.fee.token, op.fee.amount, op.fee.recipient));
        return keccak256(
            abi.encode(OP_TYPEHASH, keccak256(abi.encodePacked(callHashes)), op.nonce, op.deadline, feeHash)
        );
    }

    /// Signatures are `threshold` packed 65-byte r||s||v, ordered by strictly ascending recovered signer.
    /// Both lists are sorted, so membership is a single merge-walk.
    function _checkSignatures(bytes32 digest, bytes calldata signers, uint8 threshold, bytes calldata signatures)
        private
        pure
        returns (SigCheck)
    {
        uint256 n = signers.length / 20;
        uint256 last;
        uint256 j;
        for (uint256 k; k < threshold; ++k) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                let o := add(signatures.offset, mul(k, 65))
                r := calldataload(o)
                s := calldataload(add(o, 32))
                v := byte(0, calldataload(add(o, 64)))
            }
            uint256 signer = _recover(digest, v, r, s);
            if (signer == 0) return SigCheck.BadSignature;
            if (signer <= last) return SigCheck.SignatureOrder;
            while (j < n && _signerAtCalldata(signers, j) < signer) ++j;
            if (j == n || _signerAtCalldata(signers, j) != signer) return SigCheck.NotASigner;
            last = signer;
            ++j;
        }
        return SigCheck.Ok;
    }

    function _checkSignaturesMemory(bytes32 digest, bytes memory signers, uint8 threshold, bytes memory signatures)
        private
        pure
        returns (SigCheck)
    {
        uint256 n = signers.length / 20;
        uint256 last;
        uint256 j;
        for (uint256 k; k < threshold; ++k) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                let o := add(add(signatures, 0x20), mul(k, 65))
                r := mload(o)
                s := mload(add(o, 32))
                v := byte(0, mload(add(o, 64)))
            }
            uint256 signer = _recover(digest, v, r, s);
            if (signer == 0) return SigCheck.BadSignature;
            if (signer <= last) return SigCheck.SignatureOrder;
            while (j < n && _signerAtMemory(signers, j) < signer) ++j;
            if (j == n || _signerAtMemory(signers, j) != signer) return SigCheck.NotASigner;
            last = signer;
            ++j;
        }
        return SigCheck.Ok;
    }

    /// OZ ECDSA (low-s enforced, zero address rejected), then an explicit 160-bit mask: the TVM ecrecover
    /// precompile leaves the TRON 0x41 prefix above the address, and this value is compared numerically.
    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) private pure returns (uint256 signer) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, v, r, s);
        if (err != ECDSA.RecoverError.NoError) return 0;
        assembly ("memory-safe") {
            signer := and(recovered, ADDRESS_MASK)
        }
    }

    function _signerAtCalldata(bytes calldata signers, uint256 i) private pure returns (uint256 a) {
        assembly ("memory-safe") {
            a := shr(96, calldataload(add(signers.offset, mul(i, 20))))
        }
    }

    function _signerAtMemory(bytes memory signers, uint256 i) private pure returns (uint256 a) {
        assembly ("memory-safe") {
            a := shr(96, mload(add(add(signers, 0x20), mul(i, 20))))
        }
    }

    function _performCall(uint256 index, Call calldata c) private {
        if (c.tokenValue != 0) {
            // TRC-10 moves only through transferToken: no calldata, no TRX attached.
            if (c.tokenId == 0 || c.data.length != 0 || c.value != 0) revert BadCall(index);
            payable(c.to).transferToken(c.tokenValue, trcToken(c.tokenId));
            return;
        }
        if (c.tokenId != 0) revert BadCall(index);
        (bool ok, bytes memory reason) = c.to.call{value: c.value}(c.data);
        if (!ok) revert CallFailed(index, reason);
    }

    function _payFee(Fee calldata fee) private {
        if (fee.amount == 0) return;
        if (fee.recipient == address(0)) revert FeeFailed();
        if (fee.token == address(0)) {
            (bool ok,) = payable(fee.recipient).call{value: fee.amount}("");
            if (!ok) revert FeeFailed();
        } else {
            SafeTRC20.safeTransferChecked(ITRC20(fee.token), fee.recipient, fee.amount);
        }
        emit FeePaid(fee.token, fee.recipient, fee.amount);
    }
}
