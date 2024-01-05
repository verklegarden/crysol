/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// TODO:
//  - [ ] Complete addition formula from Renes-Costello-Batina 2015?
//      - See https://eprint.iacr.org/2015/1060 Algorithm 7 + 8
//      - For double Algorithm 9
//
//  - [X] Differentitate between bytes and serialization!
//      - Serialization:
//          - toEncodedPoint() -> SEC1 encoded ("normal")
//          - toCompressedEncodedPoint() -> compressed SEC1 encoded
//      - TODO: Note that identity case not implemented!!!!

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "./Secp256k1Arithmetic.sol";

import {Random} from "../Random.sol";

/**
 * @notice SecretKey is an secp256k1 secret key
 *
 * @dev Note that a secret key MUST be a field element, ie sk ∊ [1, Q).
 *
 * @dev Note that a secret key MUST be created cryptographically sound.
 *      Generally, this means via randomness sources from an CSPRNG.
 *
 * @custom:example Securly generating a random secret key:
 *
 *      ```solidity
 *      import {Secp256k1, SecretKey} from "crysol/curves/Secp256k1.sol";
 *      contract Example {
 *          using Secp256k1 for SecretKey;
 *
 *          SecretKey sk = Secp256k1.newSecretKey();
 *          assert(sk.isValid());
 *      }
 *      ````
 */
type SecretKey is uint;

/**
 * @notice PublicKey is a secret key's public identifier
 *
 * @dev A public key is a point on the secp256k1 curve computed via [sk]G.
 *
 * @custom:example Deriving a public key from a secret key:
 *
 *      ```solidity
 *      import {Secp256k1, SecretKey, PublicKey} from "crysol/curves/Secp256k1.sol";
 *      contract Example {
 *          using Secp256k1 for SecretKey;
 *          using Secp256k1 for PublicKey;
 *
 *          SecretKey sk = Secp256k1.newSecretKey();
 *
 *          PublicKey memory pk = sk.toPublicKey();
 *          assert(pk.isValid());
 *      }
 *      ```
 */
struct PublicKey {
    uint x;
    uint y;
}

/**
 * @title Secp256k1
 *
 * @notice Providing common cryptography-related functionality for the secp256k1
 *         elliptic curve
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 * @author Inspired by Chronicle Protocol's Scribe (https://github.com/chronicleprotocol/scribe)
 */
library Secp256k1 {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using Secp256k1Arithmetic for Point;

    // ~~~~~~~ Prelude ~~~~~~~
    // forgefmt: disable-start
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));
    modifier vmed() {
        if (block.chainid != 31337) revert("requireVm");
        _;
    }
    // forgefmt: disable-end
    // ~~~~~~~~~~~~~~~~~~~~~~~

    //--------------------------------------------------------------------------
    // Private Constants

    uint private constant _ADDRESS_MASK =
        0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    //--------------------------------------------------------------------------
    // Secp256k1 Constants
    //
    // Reimported from Secp256k1Arithmetic.

    /// @dev The generator G as PublicKey.
    function G() internal pure returns (PublicKey memory) {
        Point memory g = Secp256k1Arithmetic.G();

        return PublicKey(g.x, g.y);
    }

    /// @dev The order of the group generated via generator G.
    uint internal constant Q = Secp256k1Arithmetic.Q;

    //--------------------------------------------------------------------------
    // Secret Key

    /// @dev Returns a new cryptographically secure secret key.
    ///
    /// @custom:vm Random::readUint()(uint)
    function newSecretKey() internal vmed returns (SecretKey) {
        uint scalar;
        while (scalar == 0 || scalar >= Q) {
            // Note to not introduce potential bias via bounding operation.
            scalar = Random.readUint();
        }
        return secretKeyFromUint(scalar);
    }

    /// @dev Returns whether secret key `sk` is valid.
    ///
    /// @dev Note that a secret key MUST be a secp256k1 field element in order
    ///      to be valid, ie sk ∊ [1, Q).
    function isValid(SecretKey sk) internal pure returns (bool) {
        uint scalar = sk.asUint();

        return scalar != 0 && scalar < Q;
    }

    /// @dev Returns the public key of secret key `sk`.
    ///
    /// @dev Reverts if:
    ///      - Secret key invalid
    ///
    /// @custom:vm vm.createWallet(uint)
    function toPublicKey(SecretKey sk)
        internal
        vmed
        returns (PublicKey memory)
    {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        // Use vm to compute pk = [sk]G.
        Vm.Wallet memory wallet = vm.createWallet(sk.asUint());
        return PublicKey(wallet.publicKeyX, wallet.publicKeyY);
    }

    /// @dev Returns uint `scalar` as secret key.
    ///
    /// @dev Reverts if:
    ///      - Scalar not in [1, Q)
    function secretKeyFromUint(uint scalar) internal pure returns (SecretKey) {
        if (scalar == 0 || scalar >= Q) {
            revert("ScalarInvalid()");
        }

        return SecretKey.wrap(scalar);
    }

    /// @dev Returns secret key `sk` as uint.
    function asUint(SecretKey sk) internal pure returns (uint) {
        return SecretKey.unwrap(sk);
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Returns the address of public key `pk`.
    ///
    /// @dev An Ethereum address is defined as the rightmost 160 bits of the
    ///      keccak256 hash of the concatenation of the hex-encoded x and y
    ///      coordinates of the corresponding ECDSA public key.
    ///
    ///      See "Appendix F: Signing Transactions" §134 in the Yellow Paper.
    function toAddress(PublicKey memory pk) internal pure returns (address) {
        bytes32 digest = pk.toHash();

        address addr;
        assembly ("memory-safe") {
            addr := and(digest, _ADDRESS_MASK)
        }
        return addr;
    }

    /// @dev Returns the keccak256 hash of public key `pk`.
    function toHash(PublicKey memory pk) internal pure returns (bytes32) {
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(pk, 0x40)
        }
        return digest;
    }

    /// @dev Returns whether public key `pk` is a valid secp256k1 public key.
    ///
    /// @dev Note that a public key is valid if its either on the curve or the
    ///      identity (aka point at infinity) point.
    function isValid(PublicKey memory pk) internal pure returns (bool) {
        return pk.intoPoint().isOnCurve();
    }

    /// @dev Returns the y parity of public key `pk`.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in the Yellow Paper.
    function yParity(PublicKey memory pk) internal pure returns (uint) {
        return pk.intoPoint().yParity();
    }

    /// @dev Mutates public key `pk` to affine point.
    function intoPoint(PublicKey memory pk)
        internal
        pure
        returns (Point memory)
    {
        Point memory point;
        assembly ("memory-safe") {
            point := pk
        }
        return point;
    }

    /// @dev Mutates affine point `point` to a public key.
    function intoPublicKey(Point memory point)
        internal
        pure
        returns (PublicKey memory)
    {
        PublicKey memory pk;
        assembly ("memory-safe") {
            pk := point
        }
        return pk;
    }

    /// @dev Returns public key `pk` as projective point.
    function toProjectivePoint(PublicKey memory pk)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        return pk.intoPoint().toProjectivePoint();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Secret Key

    /// @dev Returns bytes `blob` as secret key.
    ///
    /// @dev Reverts if:
    ///      - Length not 32 bytes
    ///      - Deserialized scalar not in [1, Q)
    function secretKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (SecretKey)
    {
        if (blob.length != 32) {
            revert("InvalidLength()");
        }

        uint scalar;
        assembly ("memory-safe") {
            scalar := mload(add(blob, 0x20))
        }

        return secretKeyFromUint(scalar);
    }

    /// @dev Returns secret key `sk` as bytes.
    function toBytes(SecretKey sk) internal pure returns (bytes memory) {
        return abi.encodePacked(sk.asUint());
    }

    //----------------------------------
    // Public Key

    // TODO: Not totally correct. Identity case is missing!
    //       See https://www.secg.org/sec1-v2.pdf page 10.
    /// @dev Decodes public key from SEC1 encoded bytes blob `blob`.
    ///
    /// @dev Reverts if:
    ///      - Length not 65 bytes
    ///      - Prefix byte not 0x04
    ///      - Decoded public key invalid
    ///
    /// @dev Expects uncompressed 65 bytes encoding:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    function publicKeyFromEncoded(bytes memory blob)
        internal
        pure
        returns (PublicKey memory)
    {
        // Revert if length not 65.
        if (blob.length != 65) {
            revert("InvalidLength()");
        }

        // Read prefix byte.
        bytes32 prefix;
        assembly ("memory-safe") {
            prefix := byte(0, mload(add(blob, 0x20)))
        }

        // Revert if prefix not 0x04.
        if (uint(prefix) != 0x04) {
            revert("InvalidPrefix()");
        }

        // Read x and y coordinates.
        uint x;
        uint y;
        assembly ("memory-safe") {
            x := mload(add(blob, 0x21))
            y := mload(add(blob, 0x41))
        }

        // Make public key.
        PublicKey memory pk = PublicKey(x, y);

        // Revert if public key invalid.
        if (!pk.isValid()) {
            revert("InvalidPublicKey()");
        }

        return pk;
    }

    // TODO: Not totally correct. Identity case is missing!
    //       See https://www.secg.org/sec1-v2.pdf page 10.
    /// @dev Encodes public key `pk` as SEC1 encoded bytes.
    ///
    /// @dev Provides uncompressed 65 bytes encoding:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    function toEncoded(PublicKey memory pk)
        internal
        pure
        returns (bytes memory blob)
    {
        return abi.encodePacked(bytes1(0x04), pk.x, pk.y);
    }

    /// @dev Decodes public key from ABI-encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///      - Length not 64 bytes
    ///      - Decoded public key invalid
    ///
    /// @dev Expects 64 bytes encoding:
    ///         [32 bytes x coordinate][32 bytes y coordinate]
    function publicKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (PublicKey memory)
    {
        // Revert if length not 65.
        if (blob.length != 64) {
            revert("InvalidLength()");
        }

        // Read x and y coordinates of public key.
        uint x;
        uint y;
        assembly ("memory-safe") {
            x := mload(add(blob, 0x20))
            y := mload(add(blob, 0x40))
        }

        // Make public key.
        PublicKey memory pk = PublicKey(x, y);

        // Revert if public key invalid.
        if (!pk.isValid()) {
            revert("InvalidPublicKey()");
        }

        return pk;
    }

    /// @dev Encodes public key `pk` as ABI-encoded bytes.
    ///
    /// @dev Provides 64 bytes encoding:
    ///         [32 bytes x coordinate][32 bytes y coordinate]
    function toBytes(PublicKey memory pk)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(pk.x, pk.y);
    }
}
