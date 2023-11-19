/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Secp256k1, PrivateKey} from "../../curves/Secp256k1.sol";

// TODO: Library to derive deterministic nonces following RFC 6979.
//
//       For Rust implementation (used by foundry), see:
//       - https://github.com/RustCrypto/signatures/blob/master/rfc6979/src/lib.rs#L77
//       - https://github.com/RustCrypto/signatures/blob/master/rfc6979/src/lib.rs#L135

/**
 * @title Nonce
 *
 * @notice ...
 *
 * @dev ...
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library Nonce {
    using Nonce for PrivateKey;
    using Secp256k1 for PrivateKey;

    /// @dev Derives a deterministic nonce from private key `privKey` and message
    ///      `message`.
    function deriveNonce(PrivateKey privKey, bytes memory message)
        internal
        pure
        returns (uint)
    {
        bytes32 digest = keccak256(message);

        return privKey.deriveNonce(digest);
    }

    /// @dev Derives a deterministic nonce from private key `privKey` and message
    ///      `message`.
    function deriveNonce(PrivateKey privKey, bytes32 digest)
        internal
        pure
        returns (uint)
    {
        // TODO: Nonce should be curve independent, ie not bounded by Q.
        //       This responsibility should be delegated to the caller?
        return uint(keccak256(abi.encodePacked(privKey.asUint(), digest)))
            % Secp256k1.Q;
    }
}
