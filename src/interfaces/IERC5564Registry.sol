/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

/// @notice Registry to map an address or other identifier to its stealth meta-address.

/**
 * @title IERC5564Registry
 *
 * @notice Interface for an [ERC-5564 Stealth Meta-Address Registry]
 *
 * @dev The stealth meta-address registry maps recipient identifiers, such as
 *      eg. Ethereum addresses or ENS domains, to their stealth meta-address.
 *
 * @custom:references
 *      - [ERC-5564]: https://eips.ethereum.org/EIPS/eip-5564
 *      - [ERC-5564 Stealth Meta-Address Registry]: https://eips.ethereum.org/EIPS/eip-6538
 */
interface IERC5564Registry {
    /// @notice Emitted when a registrant updates their stealth meta-address.
    ///
    /// @param registrant The registrant's identifier.
    /// @param schemeId The scheme id based on [ERC-5564 Scheme Registry].
    /// @param stealthMetaAddress The registrant's stealth meta address.
    event StealthMetaAddressSet(
        bytes indexed registrant, uint indexed schemeId, bytes stealthMetaAddress
    );

    /// @notice Returns the stealth meta address of recipient `recipient` for
    ///         scheme id `schemeId` or zero if not registered.
    ///
    /// @param recipient The recipient's identifier.
    /// @param schemeId The scheme id based on [ERC-5564 Scheme Registry].
    /// @return stealthMetaAddress The stealth meta-address if recipient
    ///                            registered for given scheme id, zero otherwise.
    function stealthMetaAddressOf(bytes memory recipient, uint schemeId)
        external
        view
        returns (bytes memory stealthMetaAddress);

    // TODO: Mutating functions not included yet.
}
