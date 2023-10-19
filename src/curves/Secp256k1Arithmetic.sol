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
 * @notice AffinePoint is a secp256k1 point in Affine coordinates
 *
 * @dev The point at infinity is represented via:
 *          x = y = type(uint).max
 */
struct AffinePoint {
    uint x;
    uint y;
}
// @todo Represent point at infinity via zero point?

/**
 * @notice JacobianPoint is a secp256k1 point in Jacobian coordinates
 *
 * @dev Jacobian point represents Affine point (x, y) as (X, Y, Z) satisfying
 *      the following equations:
 *          x = X / Z²
 *          y = Y / Z³
 */
struct JacobianPoint {
    uint x;
    uint y;
    uint z;
}

/**
 * @title Secp256k1Arithmetic
 *
 * @notice Library providing common arithmetic-related functionality for the
 *         secp256k1 elliptic curve
 *
 * @dev ...
 *
 * @custom:references
 *      - [SEC 2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: TODO
 */
library Secp256k1Arithmetic {
    using Secp256k1Arithmetic for AffinePoint;
    using Secp256k1Arithmetic for JacobianPoint;

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

    /// @dev The generator G as AffinePoint.
    function G() internal pure returns (AffinePoint memory) {
        return AffinePoint(
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
    // Affine Point

    /// @dev Returns the zero point.
    ///
    /// @dev Note that the zero point is invalid and this function only provided
    ///      for convenience.
    function ZeroPoint() internal pure returns (AffinePoint memory) {
        return AffinePoint(0, 0);
    }

    /// @dev Returns whether `self` is the zero point.
    function isZeroPoint(AffinePoint memory self)
        internal
        pure
        returns (bool)
    {
        return (self.x | self.y) == 0;
    }

    /// @dev Returns the point at infinity.
    ///
    /// @dev Note that point at infinity is represented via:
    ///         self.x = self.y = type(uint).max
    function PointAtInfinity() internal pure returns (AffinePoint memory) {
        return AffinePoint(type(uint).max, type(uint).max);
    }

    /// @dev Returns whether `self` is the point at infinity.
    ///
    /// @dev Note that point at infinity is represented via:
    ///         self.x = self.y = type(uint).max
    function isPointAtInfinity(AffinePoint memory self)
        internal
        pure
        returns (bool)
    {
        return (self.x & self.y) == type(uint).max;
    }

    /// @dev Returns whether `self` is a point on the curve.
    ///
    /// @dev Note that secp256k1 curve is specified as y² ≡ x³ + ax + b (mod P)
    ///      where:
    ///         a = 0
    ///         b = 7
    function isOnCurve(AffinePoint memory self) internal pure returns (bool) {
        uint left = mulmod(self.y, self.y, P);
        // Note that adding a * x can be waived as ∀x: a * x = 0.
        uint right = addmod(mulmod(self.x, mulmod(self.x, self.x, P), P), B, P);

        return left == right;
    }

    /// @dev Returns the parity of `self`'s y coordinate.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///      See "Appendix F: Signing Transactions" in [Yellow Paper].
    function yParity(AffinePoint memory self) internal pure returns (uint) {
        return self.y & 1;
    }

    /// @dev Returns Affine point `self` as Jacobian point.
    function toJacobianPoint(AffinePoint memory self)
        internal
        pure
        returns (JacobianPoint memory)
    {
        return JacobianPoint(self.x, self.y, 1);
    }

    //--------------------------------------------------------------------------
    // Jacobian Point

    function intoAffinePoint(JacobianPoint memory self)
        internal
        pure
        returns (AffinePoint memory)
    {
        // Compute z⁻¹, i.e. the modular inverse of self.z.
        uint zInv = modularInverseOf(self.z);

        // Compute (z⁻¹)² (mod P)
        uint zInv_2 = mulmod(zInv, zInv, P);

        // Compute self.x * (z⁻¹)² (mod P), i.e. the x coordinate of given
        // Jacobian point in Affine representation.
        uint x = mulmod(self.x, zInv_2, P);

        // Compute self.y * (z⁻¹)³ (mod P), i.e. the y coordinate of given
        // Jacobian point in Affine representation.
        uint y = mulmod(self.y, mulmod(zInv, zInv_2, P), P);

        // Store x and y in self.
        assembly ("memory-safe") {
            mstore(self, x)
            mstore(add(self, 0x20), y)
        }

        // Return AffinePoint (self.x, self.y).
        AffinePoint memory point;
        assembly ("memory-safe") {
            point := self
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
    ///      The modular inverse of `x` is x⁻¹ such that x * x⁻¹ ≡ 1 (mod P).
    ///
    /// @dev Reverts if:
    ///      - `x` not in [0, P)
    ///
    /// @dev Uses the Extended Euclidean Algorithm.
    ///
    /// @custom:invariant Terminates in finite time.
    function modularInverseOf(uint x) internal pure returns (uint) {
        if (x >= P) revert("TODO(modularInverse: x >= P)");

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
}
