/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

/*
From the RFC-6979:
Deterministic signatures retain the cryptographic
security features associated with digital signatures but can be more
easily implemented in various environments, since they do not need
access to a source of high-quality randomness.
 */

/**
 * @title Nonce
 *
 * @notice Provides deterministic nonce derivation TODO: using keccak256 as HMAC
 *
 * @custom:reference
 *      - [RFC-6979]: https://datatracker.ietf.org/doc/html/rfc6979
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Nonce {

    /// @dev Generates a deterministic nonce ∊ [1, `fieldModulus`) from secret
    ///      key `sk` and message digest `digest`.
    ///
    /// TODO: Need formal definition of algorithm. Counter is necessary to not
    ///       introduce potential bias via modulus operation. While the bias is
    ///       ok for secp256k1, it may not be for future curves or different
    ///       hash functions. Note that general algorithm may be defined via
    ///       abstract hash function as in random oracle model.
    ///       However, practical implementation on Ethereum (at least for now)
    ///       should only use keccak256.
    ///
    /// TODO: Assumes `digest` to be a keccak256 digest? Depends on formal
    ///       definition.
    ///
    /// @dev Reverts if:
    ///        fieldModulus ∊ {0, 1}
    function generate_new(uint sk, uint fieldModulus, bytes32 digest)
        internal
        pure
        returns (uint)
    {
        if (fieldModulus == 0 || fieldModulus == 1) {
            revert("FieldModulusInvalid()");
        }

        // Computes a nonce suitable for given field modulus without introducing
        // potential biases via repeatingly adding an increasing counter to the
        // hash input.
        uint nonce;
        // TODO: Size of i defined as 256 bit? While less should be sufficient,
        //       this algorithm actually does not _guarantee_ finding a suitable
        //       nonce due to i's finite range.
        uint i;
        do {
            nonce = uint(keccak256(abi.encodePacked(sk, digest, i)));
            i++;
        } while (nonce == 0 || nonce >= fieldModulus);

        return nonce;
    }

    // -- NEW --

    function generate__new(uint sk, uint fieldModulus, bytes32 digest)
        internal
        pure
        returns (uint)
    {
        assert(sk < fieldModulus);
        assert(uint(digest) < fieldModulus);

        // Let nonce = H(sk || digest || ctr)
        uint nonce;
        uint ctr;
        do {
            nonce = uint(keccak256(abi.encodePacked(sk, digest, ctr)));

            // forgefmt: disable-next-item
            unchecked { ++ctr; }
        } while (nonce == 0 || nonce >= fieldModulus);

        return nonce;
    }

    // -- RFC-6979 --
    // Probably won't use

    /// @dev Generates a deterministic nonce in the range [1, fieldModulus)
    ///      using keccak256 as HMAC.
    ///
    /// @dev TODO: IMPORTANT: Nonce may be unsuitable for ECDSA if r == 0.
    ///      However, this means the keccak256 hash image of a valid secp256k1
    ///      public key is zero. The security of Ethereum is based on this not happening,
    ///      it has a security of 160 bits.
    ///      Due to this negligible probablity, this library DOES NOT provide a way to
    ///      generate a different nonce for same arguments.
    ///
    ///      If this is ever a problem for you: don't panic and may the force be with you.
    ///
    /// @dev Assumes:
    ///      - digest = keccak256(message) % fieldModulus
    ///      - sk \in [1, fieldModulus)
    function generate(uint sk, uint fieldModulus, bytes32 digest)
        internal
        pure
        returns (uint)
    {
        assert(sk < fieldModulus);
        assert(uint(digest) < fieldModulus);

        // Initialize v and k as specified.
        bytes32 v =
            bytes32(0x0101010101010101010101010101010101010101010101010101010101010101);
        bytes32 k =
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000);

        // Let k = H(v || 0x00 || sk || digest)
        k = keccak256(
                abi.encodePacked(
                    v, bytes1(0x00), sk, digest
                )
        );
        // Let v = H(v) TODO: Can be precomputed?
        v = keccak256(abi.encodePacked(v));
        // Let k = H(v || 0x01 || sk || digest)
        k = keccak256(abi.encodePacked(v, bytes1(0x01), sk, digest));
        // Let v = H(v) TODO: Can be precomputed?
        v = keccak256(abi.encodePacked(v));

        bytes memory t;
        uint tlen;
        while (true) {
            // Let v = H(v)
            v = keccak256(abi.encodePacked(v));

            // Let t = t || v
            t = abi.encodePacked(t, v);

            // Let k = bitsToInt(t)

            k = bytes32(t);

            // ???

            if (uint(k) != 0 && uint(k) < fieldModulus) {
                return uint(k);
            }
        }

        assert(false);
        return 0; // Added to silence compiler warnings.
    }

    // -- OLD --

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
