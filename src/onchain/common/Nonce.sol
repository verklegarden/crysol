/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

// TODO: Derive deterministic nonces via RFC-6979.
//
//       For Rust implementation (used by foundry), see:
//       - https://github.com/RustCrypto/signatures/blob/master/rfc6979/src/lib.rs#L77
//       - https://github.com/RustCrypto/signatures/blob/master/rfc6979/src/lib.rs#L135

/**
 * @title Nonce
 *
 * @notice Provides deterministic nonce derivation
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library Nonce {
    /// @dev Derives a deterministic non-zero nonce from secret key `sk` and
    ///      message `message`.
    ///
    /// @dev Note that a nonce is of type uint and not bounded to any field!
    ///
    /// @custom:invariant Keccak256 image is never zero:
    ///     ∀ (sk, msg) ∊ (SecretKey, bytes): keccak256(sk ‖ keccak256(message)) != 0
    function deriveNonceFrom(uint sk, bytes memory message)
        internal
        pure
        returns (uint)
    {
        bytes32 digest = keccak256(message);

        return deriveNonceFrom(sk, digest);
    }

    /// @dev Derives a deterministic non-zero nonce from secret key `sk` and
    ///      hash digest `digest`.
    ///
    /// @dev Note that a nonce is of type uint and not bounded to any field!
    ///
    /// @custom:invariant Keccak256 image is never zero:
    ///     ∀ (sk, digest) ∊ (SecretKey, bytes32): keccak256(sk ‖ digest) != 0
    function deriveNonceFrom(uint sk, bytes32 digest)
        internal
        pure
        returns (uint)
    {
        return uint(keccak256(abi.encodePacked(sk, digest)));
    }
}
