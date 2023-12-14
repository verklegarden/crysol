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
 * @notice Point is a secp256k1 point in affine coordinates
 *
 * @dev The point at infinity is represented via:
 *          x = y = type(uint).max
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
 *          x = X / Z²
 *          y = Y / Z³
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
 *      - [SEC 2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: TODO
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 * @author Inspired by Chronicle Protocol's Scribe (https://github.com/chronicleprotocol/scribe)
 */
library Secp256k1Arithmetic {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

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

    // Taken from [SEC 2 v2] section 2.4.1 "Recommended Parameters secp256k1".
    //--------------------------------------------------------------------------

    //--------------------------------------------------------------------------
    // Point

    /// @dev Returns the zero point.
    ///
    /// @dev Note that the zero point is invalid and this function only provided
    ///      for convenience.
    function ZeroPoint() internal pure returns (Point memory) {
        return Point(0, 0);
    }

    /// @dev Returns whether point `point` is the zero point.
    function isZeroPoint(Point memory point) internal pure returns (bool) {
        return (point.x | point.y) == 0;
    }

    /// @dev Returns the additive identity.
    ///
    /// @dev Note that the identity is represented via:
    ///         point.x = point.y = type(uint).max
    ///
    /// @dev Note that the identity is also called point at infinity.
    function Identity() internal pure returns (Point memory) {
        return Point(type(uint).max, type(uint).max);
    }

    /// @dev Returns whether point `point` is the identity.
    ///
    /// @dev Note that the identity is represented via:
    ///         point.x = point.y = type(uint).max
    ///
    /// @dev Note that the identity is also called point at infinity.
    function isIdentity(Point memory point) internal pure returns (bool) {
        return (point.x & point.y) == type(uint).max;
    }

    /// @dev Returns whether point `point` is on the curve.
    ///
    /// @dev Note that secp256k1 curve is specified as y² ≡ x³ + ax + b (mod p)
    ///      where:
    ///         a = 0
    ///         b = 7
    ///
    /// @dev Note that the identity is also on the curve.
    function isOnCurve(Point memory point) internal pure returns (bool) {
        if (point.isIdentity()) {
            return true;
        }

        uint left = mulmod(point.y, point.y, P);
        // Note that adding a * x can be waived as ∀ x: a * x = 0.
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
    function equals(Point memory point, Point memory other)
        internal
        pure
        returns (bool)
    {
        return (point.x == other.x) && (point.y == other.y);
    }

    //----------------------------------
    // Arithmetic

    /// @dev Returns the sum of points `point` and `other` as new point.
    ///
    /// @dev TODO Note about performance. intoPoint() conversion is expensive.
    ///           Also created new point struct in memory.
    ///
    /// @dev Reverts if:
    ///      - Point not on curve
    function add(Point memory point, Point memory other)
        internal
        pure
        returns (Point memory)
    {
        // Revert if any point not on curve.
        if (!point.isOnCurve()) {
            revert("PointNotOnCurve(point)");
        }
        if (!other.isOnCurve()) {
            revert("PointNotOnCurve(other)");
        }

        // Catch addition with identity.
        // Note that point at infinity serves as identity.
        if (point.isPointAtInfinity()) {
            return other;
        }
        if (other.isPointAtInfinity()) {
            return point;
        }

        // Perform addition in Jacobian coordinates.
        JacobianPoint memory jSum;
        JacobianPoint memory jPoint = point.toJacobianPoint();

        if (point.equals(other)) {
            // point = other → sum = point + point
            jSum = _jDouble(jPoint);
        } else {
            // point != other → sum = point + other
            jSum = _jAdd(jPoint, other.toJacobianPoint());
        }

        // Return sum as Affine point.
        // Note that conversion is expensive!
        return jSum.intoPoint();
    }

    /// @dev Returns a new point being the product of point `point` and scalar
    ///      `scalar`.
    ///
    /// @dev TODO Note about performance. intoPoint() conversion is expensive.
    ///           Also created new point struct in memory.
    ///
    /// @dev Reverts if:
    ///      - Point not on curve
    function mul(Point memory point, uint scalar)
        internal
        pure
        returns (Point memory)
    {
        if (!point.isOnCurve()) {
            revert("PointNotOnCurve(point)");
        }

        // Catch muliplication with identity or scalar of zero.
        if (point.isPointAtInfinity() || scalar == 0) {
            return PointAtInfinity();
        }

        // Perform multiplicatino in Jacobian coordinates.
        JacobianPoint memory jProduct;
        JacobianPoint memory jPoint = point.toJacobianPoint();

        jProduct = _jMul(jPoint, scalar);

        // Return product as Affine point.
        // Note that conversion is expensive!
        return jProduct.intoPoint();
    }

    //----------------------------------
    // Type Conversion

    /// @dev Returns point `point` as Jacobian point.
    function toJacobianPoint(Point memory point)
        internal
        pure
        returns (JacobianPoint memory)
    {
        // TODO: Point at infinity jacobian encoding = (maxUint maxUint, 1)?
        return JacobianPoint(point.x, point.y, 1);
    }

    //--------------------------------------------------------------------------
    // Projective Point
    //
    // TODO: Jacobian arithmetic is private for now as they provide less
    //       security guarantees.
    //       If you need Jacobian functionality exposed, eg for performance
    //       gains, let me know!

    /// @dev Returns whether Jacobian point `jPoint` is the point at infinity.
    ///
    /// @dev Note that point at infinity is represented via:
    ///         jPoint.x = jPoint.y = type(uint).max
    ///         jPoint.z = 1
    function isPointAtInfinity(JacobianPoint memory jPoint)
        internal
        pure
        returns (bool)
    {
        bool xy = (jPoint.x & jPoint.y) == type(uint).max;

        return xy && (jPoint.z == 1);
    }

    //----------------------------------
    // Type Conversion

    /// @dev Mutates Jacobian point `jPoint` to Affine point.
    function intoPoint(JacobianPoint memory jPoint)
        internal
        pure
        returns (Point memory)
    {
        // Compute z⁻¹, i.e. the modular inverse of jPoint.z.
        uint zInv = modularInverseOf(jPoint.z);

        // Compute (z⁻¹)² (mod P)
        uint zInv_2 = mulmod(zInv, zInv, P);

        // Compute jPoint.x * (z⁻¹)² (mod P), i.e. the x coordinate of given
        // Jacobian point in Affine representation.
        uint x = mulmod(jPoint.x, zInv_2, P);

        // Compute jPoint.y * (z⁻¹)³ (mod P), i.e. the y coordinate of given
        // Jacobian point in Affine representation.
        uint y = mulmod(jPoint.y, mulmod(zInv, zInv_2, P), P);

        // Store x and y in jPoint.
        assembly ("memory-safe") {
            mstore(jPoint, x)
            mstore(add(jPoint, 0x20), y)
        }

        // Return as Point(jPoint.x, jPoint.y).
        // Note that jPoint.z is from now on dirty memory!
        Point memory point;
        assembly ("memory-safe") {
            point := jPoint
        }
        return point;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns the modular inverse of `x` for modulo `P`.
    ///
    ///      The modular inverse of `x` is x⁻¹ such that x * x⁻¹ ≡ 1 (mod P).
    ///
    /// @dev Reverts if:
    ///      - x not in [1, P)
    ///
    /// @dev Uses the Extended Euclidean Algorithm.
    ///
    /// @custom:invariant Terminates in finite time.
    function modularInverseOf(uint x) internal pure returns (uint) {
        // TODO: Refactor to use Fermats Little Theorem.
        //       While generally less performant due to the modexp precompile
        //       pricing its less cheaper in EVM context.
        //       For more info, see page 4 in "Speeding up Elliptic Curve Computations for Ethereum Account Abstraction".

        if (x == 0) {
            revert("Modular inverse of zero does not exist");
        }
        if (x >= P) {
            revert("NotAFieldElement(x)");
        }

        uint t;
        uint q;
        uint newT = 1;
        uint r = P;

        assembly ("memory-safe") {
            // Implemented in assembly to circumvent division-by-zero
            // and over-/underflow protection.
            //
            // Functionally equivalent Solidity code:
            //      while (x != 0) {
            //          q = r / x;
            //          (t, newT) = (newT, addmod(t, (P - mulmod(q, newT, P)), P));
            //          (r, x) = (x, r - (q * x));
            //      }
            //
            // For the division r / x, x is guaranteed to not be zero via the
            // loop condition.
            //
            // The subtraction of form P - mulmod(_, _, P) is guaranteed to not
            // underflow due to the subtrahend being a (mod P) result,
            // i.e. the subtrahend being guaranteed to be less than P.
            //
            // The subterm q * x is guaranteed to not overflow because
            // q * x ≤ r due to q = ⎣r / x⎦.
            //
            // The term r - (q * x) is guaranteed to not underflow because
            // q * x ≤ r and therefore r - (q * x) ≥ 0.
            for {} x {} {
                q := div(r, x)

                let tmp := t
                t := newT
                newT := addmod(tmp, sub(P, mulmod(q, newT, P)), P)

                tmp := r
                r := x
                x := sub(tmp, mul(q, x))
            }
        }

        return t;
    }

    /// @dev Returns whether `xInv` is the modular inverse of `x`.
    ///
    /// @dev Note that there is no modular inverse for zero.
    ///
    /// @dev Reverts if:
    ///      - x not in [1, P)
    ///      - xInv not in [1, P)
    function areModularInverse(uint x, uint xInv)
        internal
        pure
        returns (bool)
    {
        if (x >= P) {
            revert("NotAFieldElement(x)");
        }
        if (xInv >= P) {
            revert("NotAFieldElement(xInv)");
        }

        return mulmod(x, xInv, P) == 1;
    }

    //--------------------------------------------------------------------------
    // Private Functions

    //----------------------------------
    // Jacobian Point
    //
    // Functionality stolen from Jordi Baylina's [ecsol](https://github.com/jbaylina/ecsol/blob/c2256afad126b7500e6f879a9369b100e47d435d/ec.sol).

    /// @dev Assumptions:
    ///      - Each point is on the curve
    ///      - No point is the point at infinity
    function _jAdd(JacobianPoint memory jPoint, JacobianPoint memory other)
        private
        pure
        returns (JacobianPoint memory)
    {
        assert(!jPoint.isPointAtInfinity() && !other.isPointAtInfinity());

        JacobianPoint memory sum;

        uint l;
        uint lz;
        uint da;
        uint db;

        if (jPoint.x == other.x && jPoint.y == other.y) {
            (l, lz) = _mul(jPoint.x, jPoint.z, jPoint.x, jPoint.z);
            (l, lz) = _mul(l, lz, 3, 1);
            (l, lz) = _add(l, lz, A, 1);

            (da, db) = _mul(jPoint.y, jPoint.z, 2, 1);
        } else {
            (l, lz) = _sub(other.y, other.z, jPoint.y, jPoint.z);
            (da, db) = _sub(other.x, other.z, jPoint.x, jPoint.z);
        }

        (l, lz) = _div(l, lz, da, db);

        (sum.x, da) = _mul(l, lz, l, lz);
        (sum.x, da) = _sub(sum.x, da, jPoint.x, jPoint.z);
        (sum.x, da) = _sub(sum.x, da, other.x, other.z);

        (sum.y, db) = _sub(jPoint.x, jPoint.z, sum.x, da);
        (sum.y, db) = _mul(sum.y, db, l, lz);
        (sum.y, db) = _sub(sum.y, db, jPoint.y, jPoint.z);

        if (da != db) {
            sum.x = mulmod(sum.x, db, P);
            sum.y = mulmod(sum.y, da, P);
            sum.z = mulmod(da, db, P);
        } else {
            sum.z = da;
        }

        return sum;
    }

    /// @dev Assumptions:
    ///      - Point is on the curve
    ///      - Point is not the point at infinity
    function _jDouble(JacobianPoint memory jPoint)
        private
        pure
        returns (JacobianPoint memory)
    {
        // TODO: There are faster doubling formulas.
        return _jAdd(jPoint, jPoint);
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Point

    /// @dev Returns point `point` as projective point.
    function toProjectivePoint(Point memory point)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        return ProjectivePoint(point.x, point.y, 1);
    }

    /// @dev Assumptions:
    ///      - Point is on the curve
    ///      - Point is not the point at infinity
    ///      - Scalar is not zero
    function _jMul(ProjectivePoint memory jPoint, uint scalar)
        private
        pure
        returns (ProjectivePoint memory)
    {
        assert(!jPoint.isIdentity());
        assert(scalar != 0);

        ProjectivePoint memory copy = jPoint;
        ProjectivePoint memory product = ZeroPoint().toProjectivePoint();

        while (scalar != 0) {
            if (scalar & 1 == 1) {
                product = _jAdd(product, copy);
            }
            scalar = scalar >> 1; // Divide by 2.
            copy = _jDouble(copy);
        }

        return product;
    }

    //----------------------------------
    // Projective Point

    /// @dev Mutates projective point `jPoint` to affine point.
    function intoPoint(ProjectivePoint memory jPoint)
        internal
        pure
        returns (Point memory)
    {
        // Compute z⁻¹, i.e. the modular inverse of jPoint.z.
        uint zInv = modularInverseOf(jPoint.z);

        // Compute (z⁻¹)² (mod p)
        uint zInv_2 = mulmod(zInv, zInv, P);

        // Compute jPoint.x * (z⁻¹)² (mod p), i.e. the x coordinate of given
        // projective point in affine representation.
        uint x = mulmod(jPoint.x, zInv_2, P);

        // Compute jPoint.y * (z⁻¹)³ (mod p), i.e. the y coordinate of given
        // projective point in affine representation.
        uint y = mulmod(jPoint.y, mulmod(zInv, zInv_2, P), P);

        // Store x and y in jPoint.
        assembly ("memory-safe") {
            mstore(jPoint, x)
            mstore(add(jPoint, 0x20), y)
        }

        // Return as Point(jPoint.x, jPoint.y).
        // Note that from this moment, jPoint.z is dirty memory!
        Point memory point;
        assembly ("memory-safe") {
            point := jPoint
        }
        return point;
    }

    //--------------------------------------------------------------------------
    // Utils

    // @todo Use Fermats Little Theorem. While generally less performant, it is
    //       cheaper on EVM due to the modexp precompile.
    //       See "Speeding up Elliptic Curve Computations for Ethereum Account Abstraction" page 4.

    /// @dev Returns the modular inverse of `x` for modulo `P`.
    ///
    ///      The modular inverse of `x` is x⁻¹ such that x * x⁻¹ ≡ 1 (mod p).
    ///
    /// @dev Reverts if:
    ///      - x not in [1, P)
    ///
    /// @dev Uses the Extended Euclidean Algorithm.
    ///
    /// @custom:invariant Terminates in finite time.
    function modularInverseOf(uint x) internal pure returns (uint) {
        if (x == 0) {
            revert("Modular inverse of zero does not exist");
        }
        if (x >= P) {
            revert("TODO(modularInverse: x >= P)");
        }

        uint t;
        uint q;
        uint newT = 1;
        uint r = P;

        assembly ("memory-safe") {
            // Implemented in assembly to circumvent division-by-zero
            // and over-/underflow protection.
            //
            // Functionally equivalent Solidity code:
            //      while (x != 0) {
            //          q = r / x;
            //          (t, newT) = (newT, addmod(t, (P - mulmod(q, newT, P)), P));
            //          (r, x) = (x, r - (q * x));
            //      }
            //
            // For the division r / x, x is guaranteed to not be zero via the
            // loop condition.
            //
            // The subtraction of form P - mulmod(_, _, P) is guaranteed to not
            // underflow due to the subtrahend being a (mod P) result,
            // i.e. the subtrahend being guaranteed to be less than P.
            //
            // The subterm q * x is guaranteed to not overflow because
            // q * x ≤ r due to q = ⎣r / x⎦.
            //
            // The term r - (q * x) is guaranteed to not underflow because
            // q * x ≤ r and therefore r - (q * x) ≥ 0.
            for {} x {} {
                q := div(r, x)

                let tmp := t
                t := newT
                newT := addmod(tmp, sub(P, mulmod(q, newT, P)), P)

                tmp := r
                r := x
                x := sub(tmp, mul(q, x))
        }

        return product;
    }

    /// @dev Returns whether `xInv` is the modular inverse of `x`.
    function areModularInverse(uint x, uint xInv)
        internal
        pure
        returns (bool)
    {
        if (x == 0 || xInv == 0) {
            revert("Modular inverse of zero does not exist");
        }
        if (x >= P || xInv >= P) {
            revert("TODO(modularInverse: x >= P)");
        }

        return mulmod(x, xInv, P) == 1;
    }


    //--------------------------------------------------------------------------
    // Private Functions

    //----------------------------------
    // Helpers

    function _add(uint x1, uint z1, uint x2, uint z2)
        private
        pure
        returns (uint, uint)
    {
        uint x3 = addmod(mulmod(z2, x1, P), mulmod(x2, z1, P), P);
        uint z3 = mulmod(z1, z2, P);

        return (x3, z3);
    }

    function _sub(uint x1, uint z1, uint x2, uint z2)
        private
        pure
        returns (uint, uint)
    {
        uint x3 = addmod(mulmod(z2, x1, P), mulmod(P - x2, z1, P), P);
        uint z3 = mulmod(z1, z2, P);

        return (x3, z3);
    }

    function _mul(uint x1, uint z1, uint x2, uint z2)
        private
        pure
        returns (uint, uint)
    {
        uint x3 = mulmod(x1, x2, P);
        uint z3 = mulmod(z1, z2, P);

        return (x3, z3);
    }

    function _div(uint x1, uint z1, uint x2, uint z2)
        private
        pure
        returns (uint, uint)
    {
        uint x3 = mulmod(x1, z2, P);
        uint z3 = mulmod(z1, x2, P);

        return (x3, z3);
    }
}
