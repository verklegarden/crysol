// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

/**
 * @title IERC5561Announcer
 *
 * @notice Interface to announce a tx to an [EIP-5564] stealth address
 *
 * @dev Metadata Specification and Recommendations
 *
 *      The first byte of the metadata MUST be the view tag. The view tag provides
 *      a probabilistic filter to skip computations when checking announcements.
 *
 *      The following recommendations are given in [EIP-5564]:
 *
 *      - Tx transferring the native token, eg ETH:
 *
 *         Index      |  Description                                  | Length in bytes
 *        -----------------------------------------------------------------------------
 *        [0x00]      | View tag                                      |              1
 *        [0x01:0x04] | `0xeeeeeeee`                                  |              4
 *        [0x05:0x24] | `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`  |             20
 *        [0x18:0x38] | Amount in wei                                 |             32
 *
 *      - Tx involving a contract call with a single argument, eg ERC-20/ERC-721
 *        transfers:
 *
 *         Index      |  Description                                  | Length in bytes
 *        -----------------------------------------------------------------------------
 *        [0x00]      | View tag                                      |             1
 *        [0x01:0x04] | Solidity function selector                    |             4
 *        [0x05:0x24] | Contract address                              |             20
 *        [0x18:0x38] | One word argument, eg token amount            |             32
 *
 * @custom:references
 *      - [EIP-5564]: https://eips.ethereum.org/EIPS/eip-5564
 *      - [EIP-5564 Scheme Registry]: https://eips.ethereum.org/assets/eip-5564/scheme_ids
 */
interface IERC5564Announcer {
    /// @notice Emitted to announce a tx to a stealth address.
    ///
    /// @param schemeId Scheme id based on [EIP-5564 Scheme Registry] registry.
    /// @param stealthAddress The stealth address.
    /// @param caller The address announcing the tx.
    /// @param ephemeralPubKey The ephemeral public key created during the
    ///                        stealth address generation.
    /// @param metadata Bytes blob providing the view tag and arbitrary
    ///                 additional metadata. Note that [EIP-5564] provides
    ///                 recommendations.
    event Announcement(
        uint indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    /// @notice Announces a tx to stealth address `stealthAddress` using scheme
    ///         `schemeId` and ephemeral public key `ephemeralPubKey`. View tag
    ///         and additional metadata are provided via `metadata`.
    ///
    /// @param schemeId Scheme id based on [EIP-5564 Scheme Registry] registry.
    /// @param stealthAddress The stealth address.
    /// @param ephemeralPubKey The ephemeral public key created during the
    ///                        stealth address generation.
    /// @param metadata Bytes blob providing the view tag and arbitrary
    ///                 additional metadata. Note that [EIP-5564] provides
    ///                 recommendations.
    function announce(
        uint schemeId,
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory metadata
    ) external;
}

/**
 * @title ERC5564Announcer
 *
 * @notice Minimal [EIP-5564] stealth address announcement contract
 */
contract ERC5564Announcer is IERC5564Announcer {
    /// @inheritdoc IERC5564Announcer
    function announce(
        uint schemeId,
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory metadata
    ) external {
        emit Announcement(
            schemeId, stealthAddress, msg.sender, ephemeralPubKey, metadata
        );
    }
}
