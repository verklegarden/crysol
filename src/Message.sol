/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

// TODO: Rename to Ethereum Signed Message Hash.
//       However, make clear via docs that hash is _not yet_ signed!
/**
 * @title Message
 *
 * @notice Functionality for constructing Ethereum Message Hashes
 *
 * @dev An Ethereum Message Hash is a hash composed of a prefix and the actual
 *      message. The prefix makes a signature for the hash recognizable as an
 *      Ethereum specific signature.
 *
 *      An Ethereum Message Hash is defined via the [`eth_sign`] RPC call as:
 *          keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
 *
 *      Note that this library only provides functionality for creating Ethereum
 *      Message Hashes for keccak256 digests and not arbitrary bytes.
 *
 * @custom:references
 *      - [eth_sign]: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign
 */
library Message {
    /// @dev Returns an Ethereum Message Hash from the keccak256 digest from
    ///      message `message`.
    function deriveEthereumMessageHash(bytes memory message)
        internal
        pure
        returns (bytes32)
    {
        bytes32 digest;
        assembly ("memory-safe") {
            let len := mload(message)
            let offset := add(message, 0x20)

            digest := keccak256(offset, len)
        }

        return deriveEthereumMessageHash(digest);
    }

    /// @dev Returns an Ethereum Message Hash from hash digest `digest`.
    function deriveEthereumMessageHash(bytes32 digest)
        internal
        pure
        returns (bytes32)
    {
        bytes32 ethMessageHash;
        assembly ("memory-safe") {
            // Note that the prefix's length is 0x1c, leading to a total length
            // of 0x1c + 0x20 = 0x3c.
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, digest)
            ethMessageHash := keccak256(0x00, 0x3c)
        }
        return ethMessageHash;
    }
}
