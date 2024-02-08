/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

import {Random} from "../common/Random.sol";

import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "./Secp256k1Arithmetic.sol";

/**
 * @notice SecretKey is an secp256k1 secret key
 *
 * @dev Note that a secret key MUST be a field element, ie sk ∊ [1, Q).
 *
 * @dev Note that a secret key MUST be created cryptographically sound.
 *      Generally, this means via randomness sourced from an CSPRNG.
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
 *          assert(pk.toAddress() != address(0));
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
 * @custom:references
 *      - [SEC-1 v2]: https://www.secg.org/sec1-v2.pdf
 *      - [SEC-2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: https://github.com/ethereum/yellowpaper
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
    /// @dev Note that a secret key MUST be a field element in order to be valid,
    ///      ie sk ∊ [1, Q).
    function isValid(SecretKey sk) internal pure returns (bool) {
        uint scalar = sk.asUint();

        return scalar != 0 && scalar < Q;
    }

    /// @dev Returns the public key of secret key `sk`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
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
    ///        Scalar not in [1, Q)
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
    ///      See "Appendix F: Signing Transactions" §134 in the [Yellow Paper].
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

    // TODO: docs PublicKey.toString()
    function toString(PublicKey memory pk)
        internal
        view
        vmed
        returns (string memory)
    {
        string memory str = "Secp256k1::PublicKey({";
        str = string.concat(str, " x: ", vm.toString(pk.x), ",");
        str = string.concat(str, " y: ", vm.toString(pk.x));
        str = string.concat(str, " })");
        return str;
    }

    /// @dev Returns whether public key `pk` is a valid secp256k1 public key.
    ///
    /// @dev Note that a public key is valid if its either on the curve or the
    ///      identity (aka point at infinity) point.
    function isValid(PublicKey memory pk) internal pure returns (bool) {
        // TODO: Should identity be a valid public key?
        //       Point memory p = pk.intoPoint();
        //       return p.isOnCurve() && !p.isIdentity();
        return pk.intoPoint().isOnCurve();
    }

    /// @dev Returns the y parity of public key `pk`.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in the [Yellow Paper].
    function yParity(PublicKey memory pk) internal pure returns (uint) {
        return pk.intoPoint().yParity();
    }

    /// @dev Returns whether public key `pk` equals public key `other`.
    function eq(PublicKey memory pk, PublicKey memory other)
        internal
        pure
        returns (bool)
    {
        return pk.intoPoint().eq(other.intoPoint());
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
    ///        Length not 32 bytes
    function secretKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (SecretKey)
    {
        if (blob.length != 32) {
            revert("LengthInvalid()");
        }

        uint scalar;
        assembly ("memory-safe") {
            scalar := mload(add(blob, 0x20))
        }

        // Note to not use secretKeyFromUint(uint) to not revert in case secrect
        // key is invalid.
        // This responsibility is delegated to the caller.
        return SecretKey.wrap(scalar);
    }

    /// @dev Returns secret key `sk` as bytes.
    function toBytes(SecretKey sk) internal pure returns (bytes memory) {
        return abi.encodePacked(sk.asUint());
    }

    //----------------------------------
    // Public Key

    /// @dev Decodes public key from ABI-encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 64 bytes
    ///
    /// @dev Expects 64 bytes encoding:
    ///         [32 bytes x coordinate][32 bytes y coordinate]
    function publicKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (PublicKey memory)
    {
        // Revert if length not 64.
        if (blob.length != 64) {
            revert("LengthInvalid()");
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

        // Note that public key's validity is not verified.
        // This responsibility is delegated to the caller.
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
