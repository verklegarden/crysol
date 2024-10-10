/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {ModularArithmetic} from "../common/ModularArithmetic.sol";

/**
 * @notice Point is a secp256k1 point in affine coordinates
 *
 * @dev The identity, aka point at infinity, is represented via:
 *          x = y = 0
 */
struct Point {
    uint x;
    uint y;
}

/**
 * @notice ProjectivePoint is a secp256k1 point in projective coordinates
 *
 * @dev A projective point represents an affine point (x, y) as (X, Y, Z)
 *      satisfying the following equations:
 *          x = X / Z
 *          y = Y / Z
 */
struct ProjectivePoint {
    uint x;
    uint y;
    uint z;
}

/**
 * @title Secp256k1Arithmetic
 *
 * @notice Provides common arithmetic-related functionality for the secp256k1
 *         elliptic curve
 *
 * @custom:references
 *      - [SEC-1 v2]: https://www.secg.org/sec1-v2.pdf
 *      - [SEC-2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: https://github.com/ethereum/yellowpaper
 *      - [Renes-Costello-Batina 2015]: https://eprint.iacr.org/2015/1060.pdf
 *      - [Dubois 2023]: https://eprint.iacr.org/2023/939.pdf
 *      - [Vitalik 2018]: https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Secp256k1Arithmetic {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Optimization Constants

    /// @dev Used during projective point addition.
    uint private constant B3 = mulmod(B, 3, P);

    /// @dev Used during modular inversion.
    uint private constant NEG_2 = addmod(0, P - 2, P);

    /// @dev Used during compressed point decoding.
    ///
    /// @dev Note that the square root of an secp256k1 field element x can be
    ///      computed via x^{SQUARE_ROOT_EXPONENT} (mod p).
    uint private constant SQUARE_ROOT_EXPONENT = (P + 1) / 4;

    /// @dev Used as substitute for `Identity().intoPublicKey().toAddress()`.
    address private constant IDENTITY_ADDRESS =
        0x3f17f1962B36e491b30A40b2405849e597Ba5FB5;

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

    /// @dev The generator G as Point.
    ///
    /// @dev Note that the generator is also called base point.
    function G() internal pure returns (Point memory) {
        // Gₓ = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
        // Gᵧ = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
        return Point(
            0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        );
    }

    /// @dev The order of the group generated via G.
    uint internal constant Q =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Taken from [SEC-2 v2] section 2.4.1 "Recommended Parameters secp256k1".
    //--------------------------------------------------------------------------

    //--------------------------------------------------------------------------
    // Point

    /// @dev Returns the additive identity.
    ///
    /// @dev Note that the identity is represented via:
    ///         point.x = point.y = 0
    ///
    /// @dev Note that the identity is a valid point on the curve to enable
    ///      arithmetic functionality. However, the identity is not a valid
    ///      PublicKey and MUST NOT be used as cryptographic object.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function Identity() internal pure returns (Point memory) {
        return Point(0, 0);
    }

    /// @dev Returns whether point `point` is the identity.
    function isIdentity(Point memory point) internal pure returns (bool) {
        return (point.x | point.y) == 0;
    }

    /// @dev Returns whether point `point` is on the curve.
    ///
    /// @dev Note that the identity is on the curve.
    function isOnCurve(Point memory point) internal pure returns (bool) {
        if (point.x >= P || point.y >= P) {
            return false;
        }

        if (point.isIdentity()) {
            return true;
        }

        // Verify whether y² ≡ x³ + ax + b (mod p).
        // Note that adding a * x can be waived as ∀x: a * x = 0.
        uint left = mulmod(point.y, point.y, P);
        uint right =
            addmod(mulmod(point.x, mulmod(point.x, point.x, P), P), B, P);

        return left == right;
    }

    /// @dev Returns the parity of point `point`'s y coordinate.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in [Yellow Paper].
    function yParity(Point memory point) internal pure returns (uint) {
        return point.y & 1;
    }

    /// @dev Returns whether point `point` equals point `other`.
    function eq(Point memory point, Point memory other)
        internal
        pure
        returns (bool)
    {
        return (point.x == other.x) && (point.y == other.y);
    }

    /// @dev Returns the product of point `point` and scalar `scalar` as
    ///      address.
    ///
    /// @dev Note that this function is substantially cheaper than
    ///      `mul(ProjectivePoint,uint)(ProjectivePoint)` with the caveat that
    ///      only the point's address is returned instead of the point itself.
    function mulToAddress(Point memory point, uint scalar)
        internal
        pure
        returns (address)
    {
        if (scalar >= Q) {
            revert("ScalarMustBeFelt()");
        }

        if (scalar == 0 || point.isIdentity()) {
            return IDENTITY_ADDRESS;
        }

        // Note that ecrecover can be abused to perform an elliptic curve
        // multiplication with the caveat that the point's address is returned
        // instead of the point itself.
        //
        // For further details, see [Vitalik 2018] and [SEC-1 v2] section 4.1.6
        // "Public Key Recovery Operation".

        uint8 v;
        // Unchecked because point.yParity() ∊ {0, 1} which cannot overflow by
        // adding 27.
        unchecked {
            v = uint8(point.yParity() + 27);
        }
        uint r = point.x;
        uint s = mulmod(r, scalar, Q);

        return ecrecover(0, v, bytes32(r), bytes32(s));
    }

    //--------------------------------------------------------------------------
    // Projective Point

    /// @dev Returns the additive identity as projective point.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function ProjectiveIdentity()
        internal
        pure
        returns (ProjectivePoint memory)
    {
        return ProjectivePoint(0, 1, 0);
    }

    /// @dev Returns whether projective point `point` is the identity.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function isIdentity(ProjectivePoint memory point)
        internal
        pure
        returns (bool)
    {
        return (point.x | point.z == 0);
    }

    /// @dev Returns the sum of projective points `point` and `other` as
    ///      projective point.
    ///
    /// @dev Uses algorithm 7 from [Renes-Costello-Batina 2015] based on a
    ///      complete addition formula for Weierstrass curves with a = 0.
    function add(ProjectivePoint memory point, ProjectivePoint memory other)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        // Return early if addition with identity.
        if (point.isIdentity()) {
            return other;
        }
        if (other.isIdentity()) {
            return point;
        }
        // forgefmt: disable-start

        // Inputs:
        // - P = (x1, y1, z1)
        uint x1 = point.x; uint y1 = point.y; uint z1 = point.z;
        // - Q = (x2, y2, z2)
        uint x2 = other.x; uint y2 = other.y; uint z2 = other.z;

        // Output:
        // - (x3, y3, z3) = P + Q
        uint x3; uint y3; uint z3;

        // Constants:
        // - B3 = mulmod(B, 3, P)

        // Variables:
        uint t0; uint t1; uint t2; uint t3; uint t4;

        // Computations:
        // Note that x - y = x + (P - y) (mod P)
        t0 = mulmod(x1, x2, P);
        t1 = mulmod(y1, y2, P);
        t2 = mulmod(z1, z2, P);
        t3 = addmod(x1, y1, P);
        t4 = addmod(x2, y2, P);
        t3 = mulmod(t3, t4, P);
        t4 = addmod(t0, t1, P);
        unchecked { t3 = addmod(t3, P - t4, P); }
        t4 = addmod(y1, z1, P);
        x3 = addmod(y2, z2, P);
        t4 = mulmod(t4, x3, P);
        x3 = addmod(t1, t2, P);
        unchecked { t4 = addmod(t4, P - x3, P); }
        x3 = addmod(x1, z1, P);
        y3 = addmod(x2, z2, P);
        x3 = mulmod(x3, y3, P);
        y3 = addmod(t0, t2, P);
        unchecked { y3 = addmod(x3, P - y3, P); }
        x3 = addmod(t0, t0, P);
        t0 = addmod(x3, t0, P);
        t2 = mulmod(B3, t2, P);
        z3 = addmod(t1, t2, P);
        unchecked { t1 = addmod(t1, P - t2, P); }
        y3 = mulmod(B3, y3, P);
        x3 = mulmod(t4, y3, P);
        t2 = mulmod(t3, t1, P);
        unchecked { x3 = addmod(t2, P - x3, P); }
        y3 = mulmod(y3, t0, P);
        t1 = mulmod(t1, z3, P);
        y3 = addmod(t1, y3, P);
        t0 = mulmod(t0, t3, P);
        z3 = mulmod(z3, t4, P);
        z3 = addmod(z3, t0, P);
        // forgefmt: disable-end

        return ProjectivePoint(x3, y3, z3);
    }

    /// @dev Returns the product of projective point `point` and scalar `scalar`
    ///      as projective point.
    ///
    /// @dev Uses the repeated add-and-double algorithm.
    function mul(ProjectivePoint memory point, uint scalar)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        if (scalar >= Q) {
            revert("ScalarMustBeFelt()");
        }

        if (scalar == 0) {
            return ProjectiveIdentity();
        }

        ProjectivePoint memory copy = point;
        ProjectivePoint memory result = ProjectiveIdentity();

        // TODO: Can endomorphism be used?
        //       See Faster Point Multiplication on Elliptic Curves with
        //       Efficient Endomorphism from GLV.
        while (scalar != 0) {
            if (scalar & 1 == 1) {
                result = result.add(copy);
            }
            scalar >>= 1;
            copy = copy.add(copy);
        }

        return result;
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    //----------------------------------
    // Point

    /// @dev Returns point `point` as projective point.
    function toProjectivePoint(Point memory point)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        if (point.isIdentity()) {
            return ProjectiveIdentity();
        }

        return ProjectivePoint(point.x, point.y, 1);
    }

    //----------------------------------
    // Projective Point

    /// @dev Mutates projective point `point` to affine point.
    function intoPoint(ProjectivePoint memory point)
        internal
        view
        returns (Point memory)
    {
        Point memory p;

        if (point.isIdentity()) {
            assembly ("memory-safe") {
                p := point
            }
            p.x = 0;
            p.y = 0;
            return p;
        }

        // Compute z⁻¹, i.e. the modular inverse of point.z.
        uint zInv = ModularArithmetic.computeInverse(point.z, P);

        // Compute affine coordinates being x * z⁻¹ and y * z⁻¹, respectively.
        uint x = mulmod(point.x, zInv, P);
        uint y = mulmod(point.y, zInv, P);

        // Store x and y in point.
        assembly ("memory-safe") {
            mstore(point, x)
            mstore(add(point, 0x20), y)
        }

        // Return as Point(point.x, point.y).
        // Note that from this moment, point.z is dirty memory!
        // TODO: Clean dirty memory.
        assembly ("memory-safe") {
            p := point
        }
        return p;
    }

    /// @dev Returns projective point `point` as affine point.
    function toPoint(ProjectivePoint memory point)
        internal
        view
        returns (Point memory)
    {
        if (point.isIdentity()) {
            return Identity();
        }

        // Compute z⁻¹, i.e. the modular inverse of point.z.
        uint zInv = ModularArithmetic.computeInverse(point.z, P);

        // Compute affine coordinates being x * z⁻¹ and y * z⁻¹, respectively.
        uint x = mulmod(point.x, zInv, P);
        uint y = mulmod(point.y, zInv, P);

        // Return newly allocated point.
        return Point(x, y);
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    /// @dev Decodes point from [SEC-1 v2] encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///          Blob not 0x00
    ///        ∧ Length not 65 bytes
    ///          ∨ Prefix byte not 0x04
    ///      ∨ Deserialized point not on curve
    ///
    /// @dev Expects uncompressed 65 bytes encoding if point is not identity:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    ///
    ///      Expects single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function pointFromEncoded(bytes memory blob)
        internal
        pure
        returns (Point memory)
    {
        // Note to catch special encoding for identity.
        if (blob.length == 1 && bytes1(blob) == bytes1(0x00)) {
            return Identity();
        }

        // Revert if length not 65.
        if (blob.length != 65) {
            revert("LengthInvalid()");
        }

        // Read prefix byte.
        uint prefix;
        assembly ("memory-safe") {
            prefix := byte(0, mload(add(blob, 0x20)))
        }

        // Revert if prefix not 0x04.
        if (prefix != 0x04) {
            revert("PrefixInvalid()");
        }

        // Read x and y coordinates.
        uint x;
        uint y;
        assembly ("memory-safe") {
            x := mload(add(blob, 0x21))
            y := mload(add(blob, 0x41))
        }

        // Make point.
        Point memory point = Point(x, y);

        // Revert if identity not 1 byte encoded.
        // TODO: Not explicitly tested.
        // TODO: Should have own error for identity not 1 byte encoded?
        if (point.isIdentity()) {
            revert("PointNotOnCurve()");
        }

        // Revert if point not on curve.
        if (!point.isOnCurve()) {
            revert("PointNotOnCurve()");
        }

        return point;
    }

    /// @dev Encodes point `point` as [SEC-1 v2] encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Point not on curve
    ///
    /// @dev Provides uncompressed 65 bytes encoding if point is not identity:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    ///
    ///      Provides single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function toEncoded(Point memory point)
        internal
        pure
        returns (bytes memory blob)
    {
        if (!point.isOnCurve()) {
            revert("PointNotOnCurve()");
        }

        // Note to catch special encoding for identity.
        if (point.isIdentity()) {
            return bytes(hex"00");
        }

        return abi.encodePacked(bytes1(0x04), point.x, point.y);
    }

    /// @dev Decodes point from [SEC-1 v2] compressed encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///          Blob not 0x00
    ///        ∧ Length not 33 bytes
    ///          ∨ Prefix byte not one in [0x02, 0x03]
    ///      ∨ Deserialized point not on curve
    ///
    /// @dev Expects compressed 33 bytes encoding if point is not identity:
    ///         [0x02 or 0x03 prefix][32 bytes x coordinate]
    ///
    ///      Expects single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function pointFromCompressedEncoded(bytes memory blob)
        internal
        view
        returns (Point memory)
    {
        // Note to catch special encoding for identity.
        if (blob.length == 1 && bytes1(blob) == bytes1(0x00)) {
            return Identity();
        }

        // Revert if length not 33.
        if (blob.length != 33) {
            revert("LengthInvalid()");
        }

        // Read prefix byte.
        uint prefix;
        assembly ("memory-safe") {
            prefix := byte(0, mload(add(blob, 0x20)))
        }

        // Revert if prefix not 0x02 or 0x03.
        if (prefix != 0x02 && prefix != 0x03) {
            revert("PrefixInvalid()");
        }

        // Read x coordinate.
        uint x;
        assembly ("memory-safe") {
            x := mload(add(blob, 0x21))
        }

        // Revert if identity not 1 byte encoded.
        // TODO: Should have own error for identity not 1 byte encoded?
        //
        // Note that identity is explicitly enforced to be 1 byte encoded,
        // eventhough for x = 0 the resulting point is not on the curve anyway.
        if (x == 0) {
            revert("PointNotOnCurve()");
        }

        // Compute α = x³ + ax + b (mod p).
        // Note that adding a * x can be waived as ∀x: a * x = 0.
        uint alpha = addmod(mulmod(x, mulmod(x, x, P), P), B, P);

        // Compute β = √α              (mod p)
        //           = α^{(p + 1) / 4} (mod p)
        uint beta = ModularArithmetic.computeExponentiation(
            alpha, SQUARE_ROOT_EXPONENT, P
        );

        // Compute y coordinate.
        //
        // Note that y = β if β ≡ prefix (mod 2) else p - β.
        uint y;
        unchecked {
            y = beta & 1 == prefix & 1 ? beta : P - beta;
        }

        // Make point.
        Point memory point = Point(x, y);

        // Revert if point not on curve.
        // TODO: Find vectors for x coordinates not on the curve.
        if (!point.isOnCurve()) {
            revert("PointNotOnCurve()");
        }

        return point;
    }

    /// @dev Encodes point `point` as [SEC-1 v2] compressed encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Point not on curve
    ///
    /// @dev Provides compressed 33 bytes encoding if point is not identity:
    ///         [0x02 or 0x03 prefix][32 bytes x coordinate]
    ///
    ///      Provides single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function toCompressedEncoded(Point memory point)
        internal
        pure
        returns (bytes memory blob)
    {
        if (!point.isOnCurve()) {
            revert("PointNotOnCurve()");
        }

        // Note to catch special encoding for identity.
        if (point.isIdentity()) {
            return bytes(hex"00");
        }

        bytes1 prefix = point.yParity() == 0 ? bytes1(0x02) : bytes1(0x03);

        return abi.encodePacked(prefix, point.x);
    }
}
