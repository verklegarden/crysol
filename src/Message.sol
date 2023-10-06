/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

/**
 * @title Message
 *
 * @notice ??
 */
library Message {
    function deriveEthereumSignedMessage(bytes memory blob)
        internal
        pure
        returns (bytes32)
    {
        bytes32 digest = keccak256(blob);

        return deriveEthereumSignedMessageHash(digest);
    }

    function deriveEthereumSignedMessageHash(bytes32 digest)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
    }
}
