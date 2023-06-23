// SPDX-License-Identifier: MIT

pragma solidity 0.8.15;
pragma abicoder v1;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@1inch/solidity-utils/contracts/libraries/SafeERC20.sol";

import "./interfaces/ICumulativeMerkleDrop128.sol";

/// @title CumulativeMerkleDrop128
/// @dev This contract allows for claims of tokens based on a merkle tree.
contract CumulativeMerkleDrop128 is Ownable, ICumulativeMerkleDrop128 {
    using SafeERC20 for IERC20;

    /// @notice The token to be claimed.
    address public immutable override token;

    /// @notice The current merkle root for the claims tree.
    bytes16 public override merkleRoot;
    /// @notice Tracks the cumulative amount claimed for each address.
    mapping(address => uint256) public cumulativeClaimed;

    /// @param token_ The token to be claimed.
    constructor(address token_) {
        token = token_;
    }

    /// @notice Sets a new merkle root for the claims tree.
    /// @dev Only callable by the owner.
    /// @param merkleRoot_ The new merkle root.
    function setMerkleRoot(bytes16 merkleRoot_) external override onlyOwner {
        emit MerkelRootUpdated(merkleRoot, merkleRoot_);
        merkleRoot = merkleRoot_;
    }

    /// @notice Allows an account to claim an amount of the token.
    /// @param salt Random data to ensure uniqueness of the merkle leaf.
    /// @param account The address of the account making the claim.
    /// @param cumulativeAmount The cumulative amount the account is claiming.
    /// @param expectedMerkleRoot The expected current merkle root.
    /// @param merkleProof The merkle proof needed to claim the tokens.
    function claim(
        bytes16 salt,
        address account,
        uint256 cumulativeAmount,
        bytes16 expectedMerkleRoot,
        bytes calldata merkleProof
    ) external override {
        require(merkleRoot == expectedMerkleRoot, "CMD: Merkle root was updated");

        // Verify the merkle proof
        bytes16 leaf = bytes16(keccak256((abi.encodePacked(salt, account, cumulativeAmount))));
        require(_verifyAsm(merkleProof, expectedMerkleRoot, leaf), "CMD: Invalid proof");

        // Mark it claimed
        uint256 preclaimed = cumulativeClaimed[account];
        require(preclaimed < cumulativeAmount, "CMD: Nothing to claim");
        cumulativeClaimed[account] = cumulativeAmount;

        // Send the token
        unchecked {
            uint256 amount = cumulativeAmount - preclaimed;
            IERC20(token).safeTransfer(account, amount);
            emit Claimed(account, amount);
        }
    }

    /// @dev Verifies a merkle proof in assembly.
    /// @param proof The merkle proof.
    /// @param root The root of the merkle tree.
    /// @param leaf The leaf being proven.
    function _verifyAsm(bytes calldata proof, bytes16 root, bytes16 leaf) private pure returns (bool valid) {
        /// @solidity memory-safe-assembly
        assembly {  // solhint-disable-line no-inline-assembly
            let ptr := proof.offset

            for { let end := add(ptr, proof.length) } lt(ptr, end) { ptr := add(ptr, 0x10) } {
                let node := calldataload(ptr)

                switch lt(leaf, node)
                case 1 {
                    mstore(0x00, leaf)
                    mstore(0x10, node)
                }
                default {
                    mstore(0x00, node)
                    mstore(0x10, leaf)
                }

                leaf := keccak256(0x00, 0x20)
            }

            valid := iszero(shr(128, xor(root, leaf)))
        }
    }
}
