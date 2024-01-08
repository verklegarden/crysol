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
 *      - [SEC-2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: https://github.com/ethereum/yellowpaper
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 * @author Inspired by Chronicle Protocol's Scribe (https://github.com/chronicleprotocol/scribe)
 */
library Secp256k1Arithmetic {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Optimization Constants

    uint private constant B3 = mulmod(B, 3, P);

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

    /// @dev Returns the zero point.
    ///
    /// @dev Note that the zero point is invalid and this function only provided
    ///      for convenience.
    function zeroPoint() internal pure returns (Point memory) {
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
    function identity() internal pure returns (Point memory) {
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
        // Note that adding a * x can be waived as ∀x: a * x = 0.
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

    //--------------------------------------------------------------------------
    // Projective Point
    //
    // Coming soon...

    /// @dev Returns the additive identity as projective point.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function projectiveIdentity()
        internal
        pure
        returns (ProjectivePoint memory)
    {
        return ProjectivePoint(0, 1, 0);
    }

    /// @dev Returns whether projective point `jPoint` is the identity.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function isIdentity(ProjectivePoint memory jPoint)
        internal
        pure
        returns (bool)
    {
        return (jPoint.x | jPoint.z == 0) && jPoint.y == 1;
    }

    function add(ProjectivePoint memory jPoint, ProjectivePoint memory jOther)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        // Uses https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl.
        //
        // TODO: Use x3, y3, z3!
        // Addition formula:
        //      x = r² - j - (2 * v)                          (mod P)
        //      y = (r * (v - x)) - 2 * s1 * j                (mod P)
        //      z = ((z1 + z2)² - (z1 * z1) - (z2 * z2)) * h  (mod P)
        //
        // where:
        //      u1 = x1 * z2²       (mod P)
        //      u2 = x2 * z1²       (mod P)
        //      s1 = y1 * z2³       (mod P)
        //      s2 = y2 * z1³       (mod P)
        //      h  = u2 - u1        (mod P)
        //      i  = (2 * h)²       (mod P) <- Just optimization
        //      j  = h * i          (mod P)
        //      r  = 2 * (s2 - s1)  (mod P)
        //      v  = u1 * i         (mod P)
        //
        // and:
        //      (x1, y1, z1) = jPoint
        //      (x2, y2, z2) = jOther

        // Return early if addition with additive identity.
        if (jPoint.isIdentity()) {
            return jOther;
        }
        if (jOther.isIdentity()) {
            return jPoint;
        }

        // Cache variables on stack.
        //uint x1 = jPoint.x; uint y1 = jPoint.y; uint z1 = jPoint.z;
        //uint x2 = jOther.x; uint y2 = jOther.y; uint z2 = jOther.z;

        // Results.
        uint x3;
        uint y3;
        uint z3;

        {
            // Compute z1_2 = z1² and z2_2 = z2².
            uint z1_2 = mulmod(jPoint.z, jPoint.z, P);
            uint z2_2 = mulmod(jOther.z, jOther.z, P);

            // Compute u1 = x1 * z2² and u2 = x2 * z1².
            uint u1 = mulmod(jPoint.x, z2_2, P);
            uint u2 = mulmod(jOther.x, z1_2, P);

            // Compute s1 = y1 * z2³ and s2 = y2 * z1³.
            uint s1 = mulmod(jPoint.y, mulmod(z2_2, jOther.z, P), P);
            uint s2 = mulmod(jOther.y, mulmod(z1_2, jPoint.z, P), P);

            // Compute h = u2 - u1
            //           = u2 + (P - u1)
            uint h = addmod(u2, P - u1, P);

            // Compute i = (2 * h)²
            uint i = mulmod(mulmod(2, h, P), mulmod(2, h, P), P);

            // Compute j = (h * i)
            uint j = mulmod(h, i, P);

            // Compute r = 2 * (s2 - s1)
            //           = 2 * (s2 + (P - s1))
            uint r = mulmod(2, addmod(s2, P - s1, P), P);

            // Compute v = u1 * i
            uint v = mulmod(u1, i, P);

            // Compute x3 = r² - j - (2 * v)
            uint r_2 = mulmod(r, r, P);
            x3 = addmod(r_2, P - j, P);
            x3 = addmod(x3, P - mulmod(2, v, P), P);

            // Compute y3 = (r * (v - x)) - 2 * s1 * j
            //              ^ left        | ^ right
            uint left = mulmod(r, addmod(v, P - x3, P), P);
            uint right = mulmod(2, mulmod(s1, j, P), P);
            y3 = addmod(left, P - right, P);

            // Compute z3 = ((z1 + z2)² - (z1 * z1) - (z2 * z2)) * h
            //                  first     second      third
            uint first = mulmod(
                addmod(jPoint.z, jOther.z, P), addmod(jPoint.z, jOther.z, P), P
            );
            uint second = mulmod(jPoint.z, jPoint.z, P);
            uint third = mulmod(jOther.z, jOther.z, P);

            uint sum = addmod(first, P - second, P);
            sum = addmod(sum, P - third, P);

            z3 = mulmod(sum, h, P);
        }

        if (x3 | y3 | z3 == 0) {
            revert(
                "TODO: Implement full addition formula. Doubling not supported."
            );
        }

        return ProjectivePoint(x3, y3, z3);
    }

    function double(ProjectivePoint memory jPoint)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        // Uses https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l.

        uint x1 = jPoint.x;
        uint y1 = jPoint.y;
        uint z1 = jPoint.z;

        uint a = mulmod(x1, x1, P);
        uint b = mulmod(y1, y1, P);
        uint c = mulmod(b, b, P);

        uint d;
        {
            uint mid = mulmod(addmod(x1, b, P), addmod(x1, b, P), P);
            uint minus = addmod(mid, P - a, P);
            minus = addmod(minus, P - c, P);
            d = mulmod(2, minus, P);
        }

        uint e = mulmod(3, a, P);
        uint f = mulmod(e, e, P);

        uint x3 = addmod(f, P - mulmod(2, d, P), P);

        uint y3;
        {
            uint left = mulmod(e, addmod(d, P - x3, P), P);
            uint right = mulmod(8, c, P);
            y3 = addmod(left, P - right, P);
        }

        uint z3 = mulmod(2, mulmod(y1, z1, P), P);

        return ProjectivePoint(x3, y3, z3);
    }

    /*
        TODO: This is the implementation we want!

    /// @dev Returns the sum of projective points `jPoint` and `jOther` as 
    ///      projective point.
    ///
    /// @dev Uses the complete addition formula from Renes-Costello-Batina 2015.
    ///      See https://eprint.iacr.org/2015/1060.pdf Alg 7.
    function add(ProjectivePoint memory jPoint, ProjectivePoint memory jOther)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        // TODO: This implementation can be optimized.
        //       See for example https://github.com/RustCrypto/elliptic-curves/blob/master/k256/src/arithmetic/projective.rs#L96.

        // TODO: Could be removed. Should be?
        if (jPoint.isIdentity()) {
            return jOther;
        }
        if (jOther.isIdentity()) {
            return jPoint;
        }

        // forgefmt: disable-start

        // Inputs: P = (x1, y1, z1), Q = (x2, y2, z2)
        uint x1 = jPoint.x; uint x2 = jOther.x;
        uint y1 = jPoint.y; uint y2 = jOther.y;
        uint z1 = jPoint.z; uint z2 = jOther.z;

        // Output: (x3, y3, z3) = P + Q
        uint x3;
        uint y3;
        uint z3;

        // Constants used:
        // - B3 = mulmod(B, 3, P)

        // Variables:
        uint t0; uint t1; uint t2; uint t3; uint t4;

        // Alg:
        // Note that x - y = x + (P - y) (mod P)
        t0 = mulmod(x1, x2, P); // Step 1
        t1 = mulmod(y1, y2, P);
        t2 = mulmod(z1, z2, P);
        t3 = addmod(x1, y1, P);
        t4 = addmod(x2, y2, P); // Step 5
        t3 = mulmod(t3, t4, P);
        t4 = addmod(t0, t1, P);
        unchecked { t3 = addmod(t3, P - t4, P); }
        t4 = addmod(y1, z1, P);
        x3 = addmod(y2, z2, P); // Step 10
        t4 = mulmod(t4, x3, P);
        x3 = addmod(t1, t2, P);
        unchecked { t4 = addmod(t4, P - x3, P); }
        x3 = addmod(x1, z1, P);
        y3 = addmod(x2, z2, P); // Step 15
        x3 = mulmod(x3, y3, P);
        y3 = addmod(t0, t2, P);
        unchecked { y3 = addmod(x3, P - y3, P); }
        x3 = addmod(t0, t0, P);
        t0 = addmod(x3, t0, P); // Step 20
        t2 = mulmod(B3, t2, P);
        z3 = addmod(t1, t2, P);
        unchecked { t1 = addmod(t1, P - t2, P); }
        y3 = mulmod(B3, y3, P);
        x3 = mulmod(t4, y3, P); // Step 25
        t2 = mulmod(t3, t1, P);
        unchecked { x3 = addmod(t2, P - x3, P); }
        y3 = mulmod(y3, t0, P);
        t1 = mulmod(t1, z3, P);
        y3 = addmod(t1, y3, P); // Step 30
        t0 = mulmod(t0, t3, P);
        z3 = mulmod(z3, t4, P);
        z3 = addmod(z3, t0, P);
        // forgefmt: disable-end

        return ProjectivePoint(x3, y3, z3);
    }
    */

    function mul(ProjectivePoint memory jPoint, uint scalar)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        if (scalar == 0) {
            // TODO: [0]P defines as zero point?
            return zeroPoint().toProjectivePoint();
        }

        ProjectivePoint memory copy = jPoint;
        ProjectivePoint memory result = Secp256k1Arithmetic.projectiveIdentity();

        while (scalar != 0) {
            if (scalar & 1 == 1) {
                result = result.add(copy);
            }
            scalar >>= 1;
            copy = copy.double();
        }

        return result;
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
        if (point.isIdentity()) {
            return projectiveIdentity();
        }

        return ProjectivePoint(point.x, point.y, 1);
    }

    //----------------------------------
    // Projective Point

    /// @dev Mutates projective point `jPoint` to affine point.
    function intoPoint(ProjectivePoint memory jPoint)
        internal
        pure
        returns (Point memory)
    {
        if (jPoint.isIdentity()) {
            return identity();
        }

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
        // TODO: Refactor to use Fermats Little Theorem.
        //       While generally less performant, it is cheaper on EVM due to
        //       the modexp precompile pricing.
        //       See "Speeding up Elliptic Curve Computations for Ethereum Account Abstraction" page 4.

        // TODO: Define appropriate errors.
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
        }

        return t;
    }

    /// @dev Returns whether `xInv` is the modular inverse of `x`.
    ///
    /// @dev Note that there is no modular inverse for zero.
    ///
    /// @dev Reverts if:
    ///      - x not in [0, P)
    ///      - xInv not in [0, P)
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
}
