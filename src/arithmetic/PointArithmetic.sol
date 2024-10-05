/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Secp256k1} from "../Secp256k1.sol";
import {FieldArithmetic, Felt} from "./FieldArithmetic.sol";

/**
 * @notice Point is a secp256k1 point in affine coordinates
 *
 * @dev The identity, aka point at infinity, is represented via:
 *          x = y = 0
 */
struct Point {
    Felt x;
    Felt y;
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
    Felt x;
    Felt y;
    Felt z;
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
library PointArithmetic {
    using FieldArithmetic for Felt;
    using PointArithmetic for Point;
    using PointArithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Optimization Constants

    /// @dev Used during projective point addition.
    uint private constant _B3 = mulmod(_B, 3, _P);

    /// @dev Used during compressed point decoding.
    ///
    /// @dev Note that the square root of an secp256k1 field element x can be
    ///      computed via x^{_SQUARE_ROOT_EXPONENT} (mod p).
    uint private constant _SQUARE_ROOT_EXPONENT = (_P + 1) / 4;

    /// @dev Used as substitute for `Identity().intoPublicKey().toAddress()`.
    address private constant _IDENTITY_ADDRESS =
        0x3f17f1962B36e491b30A40b2405849e597Ba5FB5;

    //--------------------------------------------------------------------------
    // UNDEFINED Constants

    function _UNDEFINED_POINT() private pure returns (Point memory) {
        return Point(
            FieldArithmetic.unsafeFeltFromUint(type(uint).max),
            FieldArithmetic.unsafeFeltFromUint(type(uint).max)
        );
    }

    //--------------------------------------------------------------------------
    // Secp256k1 Constants
    //
    // Reimported from Secp256k1.

    uint private constant _B = Secp256k1.B;
    uint private constant _P = Secp256k1.P;
    uint private constant _Q = Secp256k1.Q;

    //--------------------------------------------------------------------------
    // Point

    function pointFromUints(uint x, uint y)
        internal
        pure
        returns (Point memory)
    {
        (Point memory p, bool ok) = tryPointFromUints(x, y);
        if (!ok) {
            revert("PointInvalid()");
        }

        return p;
    }

    function tryPointFromUints(uint x, uint y)
        internal
        pure
        returns (Point memory, bool)
    {
        bool ok;
        Felt x_;
        Felt y_;

        (x_, ok) = FieldArithmetic.tryFeltFromUint(x);
        if (!ok) {
            return (_UNDEFINED_POINT(), false);
        }

        (y_, ok) = FieldArithmetic.tryFeltFromUint(y);
        if (!ok) {
            return (_UNDEFINED_POINT(), false);
        }

        Point memory p = Point(x_, y_);
        if (!p.isOnCurve()) {
            return (_UNDEFINED_POINT(), false);
        }

        return (p, true);
    }

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
        return Point(FieldArithmetic.ZERO, FieldArithmetic.ZERO);
    }

    /// @dev Returns whether point `point` is the identity.
    function isIdentity(Point memory point) internal pure returns (bool) {
        return (point.x.asUint() | point.y.asUint()) == 0;
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
        // forgefmt: disable-start
        Felt left = point.y
                        .mul(point.y);
        Felt right = point.x
                        .mul(point.x)
                        .mul(point.x)
                        .add(FieldArithmetic.unsafeFeltFromUint(_B));
        // forgefmt: disable-end

        return left.asUint() == right.asUint();
    }

    /// @dev Returns the parity of point `point`'s y coordinate.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in [Yellow Paper].
    function yParity(Point memory point) internal pure returns (uint) {
        return point.y.parity();
    }

    /// @dev Returns whether point `point` equals point `other`.
    function eq(Point memory point, Point memory other)
        internal
        pure
        returns (bool)
    {
        return point.x.asUint() == other.x.asUint()
            && point.y.asUint() == other.y.asUint();
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
        if (scalar >= _Q) {
            revert("ScalarTooBig()");
        }

        if (scalar == 0 || point.isIdentity()) {
            return _IDENTITY_ADDRESS;
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
        uint r = point.x.asUint();
        uint s = mulmod(r, scalar, _Q);

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
        return ProjectivePoint(
            FieldArithmetic.ZERO, FieldArithmetic.ONE, FieldArithmetic.ZERO
        );
    }

    /// @dev Returns whether projective point `point` is the identity.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function isIdentity(ProjectivePoint memory point)
        internal
        pure
        returns (bool)
    {
        return (point.x.asUint() | point.z.asUint()) == 0;
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

        // Inputs:
        // - P = (x1, y1, z1)
        Felt x1 = point.x;
        Felt y1 = point.y;
        Felt z1 = point.z;
        // - Q = (x2, y2, z2)
        Felt x2 = other.x;
        Felt y2 = other.y;
        Felt z2 = other.z;

        // Output:
        // - (x3, y3, z3) = P + Q
        Felt x3;
        Felt y3;
        Felt z3;

        // Constants:
        Felt b3 = FieldArithmetic.unsafeFeltFromUint(_B3);

        // Variables:
        Felt t0;
        Felt t1;
        Felt t2;
        Felt t3;
        Felt t4;

        // Computations:
        t0 = x1.mul(x2);
        t1 = y1.mul(y2);
        t2 = z1.mul(z2);
        t3 = x1.add(y1);
        t4 = x2.add(y2);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = y1.add(z1);
        x3 = y2.add(z2);
        t4 = t4.mul(x3);
        x3 = t1.add(t2);
        t4 = t4.sub(x3);
        x3 = x1.add(z1);
        y3 = x2.add(z1);
        x3 = x3.mul(y3);
        y3 = t0.add(t2);
        y3 = x2.sub(y3);
        x3 = t0.add(t0);
        t0 = x3.add(t0);
        t2 = b3.mul(t2);
        z3 = t1.add(t2);
        t1 = t1.sub(t2);
        y3 = b3.mul(y3);
        x3 = t4.mul(y3);
        t2 = t3.mul(t1);
        x3 = t2.sub(x3);
        y3 = y3.mul(t0);
        t1 = t1.mul(z3);
        y3 = t1.add(y3);
        t0 = t0.mul(t3);
        z3 = z3.mul(t4);
        z3 = z3.add(t0);

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
        if (scalar >= _Q) {
            revert("ScalarTooBig()");
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

        return ProjectivePoint(point.x, point.y, FieldArithmetic.ONE);
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
            // Note to clean dirty p.z memory.
            point.z = FieldArithmetic.ZERO;

            assembly ("memory-safe") {
                p := point
            }
            p.x = FieldArithmetic.ZERO;
            p.y = FieldArithmetic.ZERO;

            return p;
        }

        // Compute z⁻¹, i.e. the modular inverse of point.z.
        Felt zInv = point.z.inv();

        // Compute affine coordinates being x * z⁻¹ and y * z⁻¹, respectively.
        Felt x = point.x.mul(zInv);
        Felt y = point.y.mul(zInv);

        // Store x and y in point.
        assembly ("memory-safe") {
            mstore(point, x)
            mstore(add(point, 0x20), y)
        }

        // Return as Point(point.x, point.y).
        // Note to clean dirty p.z memory.
        point.z = FieldArithmetic.ZERO;
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
        Felt zInv = point.z.inv();

        // Compute affine coordinates being x * z⁻¹ and y * z⁻¹, respectively.
        Felt x = point.x.mul(zInv);
        Felt y = point.y.mul(zInv);

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
        uint xRaw;
        uint yRaw;
        assembly ("memory-safe") {
            xRaw := mload(add(blob, 0x21))
            yRaw := mload(add(blob, 0x41))
        }

        // Construct coordinates to field elements.
        // Note that function reverts if not a field element.
        Felt x = FieldArithmetic.feltFromUint(xRaw);
        Felt y = FieldArithmetic.feltFromUint(yRaw);

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

        return
            abi.encodePacked(bytes1(0x04), point.x.asUint(), point.y.asUint());
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
        uint xRaw;
        assembly ("memory-safe") {
            xRaw := mload(add(blob, 0x21))
        }

        // Revert if identity not 1 byte encoded.
        // TODO: Should have own error for identity not 1 byte encoded?
        //
        // Note that identity is explicitly enforced to be 1 byte encoded,
        // eventhough for x = 0 the resulting point is not on the curve anyway.
        if (xRaw == 0) {
            revert("PointNotOnCurve()");
        }

        // Construct field element from x coordinate.
        // Note that function reverts if not a field element.
        Felt x = FieldArithmetic.feltFromUint(xRaw);

        // Compute α = x³ + ax + b (mod p).
        // Note that adding a * x can be waived as ∀x: a * x = 0.
        // forgefmt: disable-next-item
        Felt alpha = x.mul(x)
                      .mul(x)
                      .add(FieldArithmetic.unsafeFeltFromUint(_B));

        // Compute β = √α              (mod p)
        //           = α^{(p + 1) / 4} (mod p)
        Felt beta =
            alpha.exp(FieldArithmetic.unsafeFeltFromUint(_SQUARE_ROOT_EXPONENT));

        // Compute y coordinate.
        //
        // Note that y = β if β ≡ prefix (mod 2) else p - β.
        uint yRaw;
        unchecked {
            yRaw = beta.asUint() & 1 == prefix & 1
                ? beta.asUint()
                : _P - beta.asUint();
        }

        // Construct field element.
        // Note that y coordinate is guaranteed to be a field element.
        Felt y = FieldArithmetic.unsafeFeltFromUint(yRaw);

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

        return abi.encodePacked(prefix, point.x.asUint());
    }
}
