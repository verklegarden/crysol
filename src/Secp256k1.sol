/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Points, Point, ProjectivePoint} from "./arithmetic/Points.sol";
import {Fp, Felt} from "./arithmetic/Fp.sol";

import "./Errors.sol" as Errors;

/**
 * @notice SecretKey is an secp256k1 secret key
 *
 * @dev Note that a secret key MUST be a valid scalar for secp256k1,
 *      ie sk ∊ [1, Q).
 *
 * @dev Note that a secret key MUST be created cryptographically sound.
 *      Generally, this means via randomness sourced from an CSPRNG.
 *
 * @custom:example Securly generating a random secret key:
 *
 *      ```solidity
 *      import {Secp256k1Offchain} from "crysol-offchain/Secp256k1Offchain.sol";
 *      import {Secp256k1, SecretKey} from "crysol/Secp256k1.sol";
 *      contract Example {
 *          using Secp256k1Offchain for SecretKey;
 *          using Secp256k1 for SecretKey;
 *
 *          SecretKey sk = Secp256k1Offchain.newSecretKey();
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
 *      import {Secp256k1Offchain} from "crysol-offchain/secp256k1/Secp256k1Offchain.sol";
 *      import {Secp256k1, SecretKey, PublicKey} from "crysol/secp256k1/Secp256k1.sol";
 *      contract Example {
 *          using Secp256k1Offchain for SecretKey;
 *          using Secp256k1 for SecretKey;
 *          using Secp256k1 for PublicKey;
 *
 *          SecretKey sk = Secp256k1Offchain.newSecretKey();
 *
 *          PublicKey memory pk = sk.toPublicKey();
 *          assert(pk.isValid());
 *          assert(pk.toAddress() != address(0));
 *      }
 *      ```
 */
struct PublicKey {
    Felt x;
    Felt y;
}

/**
 * @title Secp256k1
 *
 * @notice Provides common cryptography-related functionality for the secp256k1
 *         elliptic curve
 *
 * @custom:references
 *      - [SEC-1 v2]: https://www.secg.org/sec1-v2.pdf
 *      - [SEC-2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: https://github.com/ethereum/yellowpaper
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 * @author Inspired by Chronicle Protocol's Scribe (https://github.com/chronicleprotocol/scribe)
 */
library Secp256k1 {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using Points for Point;
    using Fp for Felt;

    //--------------------------------------------------------------------------
    // Private Constants

    uint private constant _ADDRESS_MASK =
        0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    //--------------------------------------------------------------------------
    // UNDEFINED Constants

    /// @dev The undefined secret key instance.
    ///
    ///      This secret key instance is used to indicate undefined behaviour.
    SecretKey private constant _UNDEFINED_SECRET_KEY =
        SecretKey.wrap(type(uint).max);

    /// @dev The undefined public key instance.
    ///
    ///      This public key instance is used to indicate undefined behaviour.
    function _UNDEFINED_PUBLIC_KEY() private pure returns (PublicKey memory) {
        return PublicKey(
            Fp.unsafeFromUint(type(uint).max), Fp.unsafeFromUint(type(uint).max)
        );
    }

    //--------------------------------------------------------------------------
    // Secp256k1 Constants
    //
    // Secp256k1 is a Koblitz curve specified as:
    //      y² ≡ x³ + ax + b (mod p)
    //
    // where:
    uint internal constant A = 0;
    uint internal constant B = 7;
    uint internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @dev The generator G as PublicKey.
    ///
    /// @dev Note that the generator is also called base point.
    function G() internal pure returns (PublicKey memory) {
        // Gₓ = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
        // Gᵧ = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
        return PublicKey(
            Fp.unsafeFromUint(
                0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
            ),
            Fp.unsafeFromUint(
                0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
            )
        );
    }

    /// @dev The order of the group generated via G.
    uint internal constant Q =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Taken from [SEC-2 v2] section 2.4.1 "Recommended Parameters secp256k1".
    //--------------------------------------------------------------------------

    //--------------------------------------------------------------------------
    // Secret Key

    /// @dev Tries to instantiate a secret key from scalar `scalar`.
    ///
    /// @dev Note that returned secret key is undefined if function fails to
    ///      instantiate secret key.
    function trySecretKeyFromUint(uint scalar)
        internal
        pure
        returns (SecretKey, bool)
    {
        if (scalar == 0 || scalar >= Q) {
            return (_UNDEFINED_SECRET_KEY, false);
        }

        return (SecretKey.wrap(scalar), true);
    }

    /// @dev Instantiates secret key from scalar `scalar`.
    ///
    /// @dev Reverts if:
    ///        Scalar not in [1, Q)
    function secretKeyFromUint(uint scalar) internal pure returns (SecretKey) {
        (SecretKey sk, bool ok) = trySecretKeyFromUint(scalar);
        if (!ok) {
            revert Errors.CRYSOL_ScalarMalleable();
        }

        return sk;
    }

    /// @dev Instantiates secret key from scalar `scalar` without performing
    ///      safety checks.
    ///
    /// @dev This function is unsafe and may lead to undefined behaviour if
    ///      used incorrectly.
    function unsafeSecretKeyFromUint(uint scalar)
        internal
        pure
        returns (SecretKey)
    {
        return SecretKey.wrap(scalar);
    }

    /// @dev Returns secret key `sk` as uint.
    function asUint(SecretKey sk) internal pure returns (uint) {
        return SecretKey.unwrap(sk);
    }

    /// @dev Returns whether secret key `sk` is valid.
    function isValid(SecretKey sk) internal pure returns (bool) {
        uint scalar = sk.asUint();

        return scalar != 0 && scalar < Q;
    }

    /// @dev Returns the address of secret key `sk`.
    ///
    /// @dev Note that this function is substantially cheaper than first
    ///      computing `sk`'s public key and deriving it's address manually.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function toAddress(SecretKey sk) internal pure returns (address) {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        return G().intoPoint().mulToAddress(sk.asUint());
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Tries to instantiate a public key from felt coordinates `x` and
    ///      `y`.
    ///
    /// @dev Note that returned public key is undefined if function fails to
    ///      instantiate point.
    function tryPublicKeyFromFelts(Felt x, Felt y)
        internal
        pure
        returns (PublicKey memory, bool)
    {
        if (!x.isValid() || !y.isValid()) {
            return (_UNDEFINED_PUBLIC_KEY(), false);
        }

        PublicKey memory pk = PublicKey(x, y);
        if (!pk.isValid()) {
            return (_UNDEFINED_PUBLIC_KEY(), false);
        }

        return (pk, true);
    }

    /// @dev Instantiates public key from felt coordinates `x` and `y`.
    ///
    /// @dev Reverts if:
    ///         Coordinate x not a valid felt
    ///       ∨ Coordinate y not a valid felt
    ///       ∨ Coordinates not on the curve
    function publicKeyFromFelts(Felt x, Felt y)
        internal
        pure
        returns (PublicKey memory)
    {
        (PublicKey memory pk, bool ok) = tryPublicKeyFromFelts(x, y);
        if (!ok) {
            revert("PublicKeyInvalid()");
        }

        return pk;
    }

    /// @dev Instantiates public key from felt coordinates `x` and `y` without
    ///      performing safety checks.
    ///
    /// @dev This function is unsafe and may lead to undefined behaviour if
    ///      used incorrectly.
    function unsafePublicKeyFromFelts(Felt x, Felt y)
        internal
        pure
        returns (PublicKey memory)
    {
        return PublicKey(x, y);
    }

    /// @dev Tries to instantiate a public key from coordinates `x` and `y`.
    ///
    /// @dev Note that returned public key is undefined if function fails to
    ///      instantiate public key.
    function tryPublicKeyFromUints(uint x, uint y)
        internal
        pure
        returns (PublicKey memory, bool)
    {
        return tryPublicKeyFromFelts(Fp.unsafeFromUint(x), Fp.unsafeFromUint(y));
    }

    /// @dev Instantiates public key from coordinates `x` and `y`.
    ///
    /// @dev Reverts if:
    ///         Coordinate x not a felt
    ///       ∨ Coordinate y not a felt
    ///       ∨ Coordinates not on the curve
    function publicKeyFromUints(uint x, uint y)
        internal
        pure
        returns (PublicKey memory)
    {
        (PublicKey memory pk, bool ok) = tryPublicKeyFromUints(x, y);
        if (!ok) {
            revert("PublicKeyInvalid()");
        }

        return pk;
    }

    /// @dev Instantiates public key from coordinates `x` and `y` without
    ///      performing safety checks.
    ///
    /// @dev This function is unsafe and may lead to undefined behaviour if
    ///      used incorrectly.
    function unsafePublicKeyFromUints(uint x, uint y)
        internal
        pure
        returns (PublicKey memory)
    {
        return Points.unsafeFromUints(x, y).intoPublicKey();
    }

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
            // Note to clean dirty upper bits.
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
    /// @dev Note that the identity point is not a valid public key.
    function isValid(PublicKey memory pk) internal pure returns (bool) {
        Point memory p = pk.intoPoint();

        return p.isOnCurve() && !p.isIdentity();
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

    /// @dev Decodes secret key from bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 32 bytes
    ///      ∨ Deserialized secret key invalid
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

        // Try to make secret key.
        (SecretKey sk, bool ok) = trySecretKeyFromUint(scalar);
        if (!ok) {
            revert("SecretKeyInvalid()");
        }

        return sk;
    }

    /// @dev Encodes secret key `sk` as bytes.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function toBytes(SecretKey sk) internal pure returns (bytes memory) {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        return abi.encodePacked(sk.asUint());
    }

    //----------------------------------
    // Public Key

    /// @dev Decodes public key from ABI-encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 64 bytes
    ///      ∨ Deserialized public key invalid
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

        // Try to construct public key from coordinates.
        (PublicKey memory pk, bool ok) = tryPublicKeyFromUints(x, y);
        if (!ok) {
            revert("PublicKeyInvalid()");
        }

        return pk;
    }

    /// @dev Encodes public key `pk` as ABI-encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///
    /// @dev Provides 64 bytes encoding:
    ///         [32 bytes x coordinate][32 bytes y coordinate]
    function toBytes(PublicKey memory pk)
        internal
        pure
        returns (bytes memory)
    {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        return abi.encodePacked(pk.x.asUint(), pk.y.asUint());
    }
}
