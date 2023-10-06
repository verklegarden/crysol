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
 * @notice AffinePoint is a secp256k1 point in Affine coordinates.
 *
 * @dev The point at infinity is represented via:
 *          x = y = type(uint).max
 */
struct AffinePoint {
    uint x;
    uint y;
}

/**
 * @notice JacobianPoint is a secp256k1 point in Jacobian coordinates.
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

    function mul(AffinePoint memory self, uint scalar)
        internal
        pure
        returns (AffinePoint memory)
    {
        return self.toJacobianPoint().mul(scalar).intoAffinePoint();
    }

    //--------------------------------------------------------------------------
    // Jacobian Point

    function mul(JacobianPoint memory self, uint scalar)
        internal
        pure
        returns (JacobianPoint memory)
    {
        if (scalar >= Q) revert("TODO(mul): scalar >= Q");

        // @todo Verify whether correct.
        if (scalar == 0) return ZeroPoint().toJacobianPoint();

        // @todo ...
        return ZeroPoint().toJacobianPoint();
    }

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

    // @todo Must be different points?
    //       If error -> Return PaI, not random stuff!
    /// @dev Adds Affine point `p` to Jacobian point `self` and stores the
    ///      result in `self`.
    ///
    ///      Failure is defined via the point at infinity and raised if:
    ///      - AffinePoint not on curve
    ///
    ///      Computation based on: https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2007-bl.
    ///
    /// @dev Enables computing the sum of different points with O(1) modular
    ///      inverse computations.
    ///
    /// @custom:invariant Only mutates `self` memory variable.
    /// @custom:invariant Reverts iff out of gas.
    /// @custom:invariant Uses constant amount of gas.
    function intoAddAffinePoint(JacobianPoint memory self, AffinePoint memory p)
        internal
        pure
        returns (JacobianPoint memory)
    {
        // Addition formula:
        //      x = r² - j - (2 * v)             (mod P)
        //      y = (r * (v - x)) - (2 * y1 * j) (mod P)
        //      z = (z1 + h)² - z1² - h²         (mod P)
        //
        // where:
        //      r = 2 * (s - y1) (mod P)
        //      j = h * i        (mod P)
        //      v = x1 * i       (mod P)
        //      h = u - x1       (mod P)
        //      s = y2 * z1³     (mod P)       Called s2 in reference
        //      i = 4 * h²       (mod P)
        //      u = x2 * z1²     (mod P)       Called u2 in reference
        //
        // and:
        //      x1 = self.x
        //      y1 = self.y
        //      z1 = self.z
        //      x2 = p.x
        //      y2 = p.y
        //
        // Note that the formula assumes z2 = 1, which always holds if z2's
        // point is given in Affine coordinates.

        // Fail if p not on curve.
        if (!p.isOnCurve()) {
            self = PointAtInfinity().toJacobianPoint();
            return self;
        }

        // Cache self's coordinates on stack.
        uint x1 = self.x;
        uint y1 = self.y;
        uint z1 = self.z;

        // Compute z1_2 = z1²     (mod P)
        //              = z1 * z1 (mod P)
        uint z1_2 = mulmod(z1, z1, P);

        // Compute h = u        - x1       (mod P)
        //           = u        + (P - x1) (mod P)
        //           = x2 * z1² + (P - x1) (mod P)
        //
        // Unchecked because the only protected operation performed is P - x1
        // where x1 is guaranteed by the caller to be an x coordinate belonging
        // to a point on the curve, i.e. being less than P.
        uint h;
        unchecked {
            h = addmod(mulmod(p.x, z1_2, P), P - x1, P);
        }

        // Compute h_2 = h²    (mod P)
        //             = h * h (mod P)
        uint h_2 = mulmod(h, h, P);

        // Compute i = 4 * h² (mod P)
        uint i = mulmod(4, h_2, P);

        // Compute z = (z1 + h)² - z1²       - h²       (mod P)
        //           = (z1 + h)² - z1²       + (P - h²) (mod P)
        //           = (z1 + h)² + (P - z1²) + (P - h²) (mod P)
        //             ╰───────╯   ╰───────╯   ╰──────╯
        //               left         mid       right
        //
        // Unchecked because the only protected operations performed are
        // subtractions from P where the subtrahend is the result of a (mod P)
        // computation, i.e. the subtrahend being guaranteed to be less than P.
        unchecked {
            uint left = mulmod(addmod(z1, h, P), addmod(z1, h, P), P);
            uint mid = P - z1_2;
            uint right = P - h_2;

            self.z = addmod(left, addmod(mid, right, P), P);
        }

        // Compute v = x1 * i (mod P)
        uint v = mulmod(x1, i, P);

        // Compute j = h * i (mod P)
        uint j = mulmod(h, i, P);

        // Compute r = 2 * (s               - y1)       (mod P)
        //           = 2 * (s               + (P - y1)) (mod P)
        //           = 2 * ((y2 * z1³)      + (P - y1)) (mod P)
        //           = 2 * ((y2 * z1² * z1) + (P - y1)) (mod P)
        //
        // Unchecked because the only protected operation performed is P - y1
        // where y1 is guaranteed by the caller to be an y coordinate belonging
        // to a point on the curve, i.e. being less than P.
        uint r;
        unchecked {
            r = mulmod(
                2, addmod(mulmod(p.y, mulmod(z1_2, z1, P), P), P - y1, P), P
            );
        }

        // Compute x = r² - j - (2 * v)             (mod P)
        //           = r² - j + (P - (2 * v))       (mod P)
        //           = r² + (P - j) + (P - (2 * v)) (mod P)
        //                  ╰─────╯   ╰───────────╯
        //                    mid         right
        //
        // Unchecked because the only protected operations performed are
        // subtractions from P where the subtrahend is the result of a (mod P)
        // computation, i.e. the subtrahend being guaranteed to be less than P.
        unchecked {
            uint r_2 = mulmod(r, r, P);
            uint mid = P - j;
            uint right = P - mulmod(2, v, P);

            self.x = addmod(r_2, addmod(mid, right, P), P);
        }

        // Compute y = (r * (v - x))       - (2 * y1 * j)       (mod P)
        //           = (r * (v - x))       + (P - (2 * y1 * j)) (mod P)
        //           = (r * (v + (P - x))) + (P - (2 * y1 * j)) (mod P)
        //             ╰─────────────────╯   ╰────────────────╯
        //                    left                 right
        //
        // Unchecked because the only protected operations performed are
        // subtractions from P where the subtrahend is the result of a (mod P)
        // computation, i.e. the subtrahend being guaranteed to be less than P.
        unchecked {
            uint left = mulmod(r, addmod(v, P - self.x, P), P);
            uint right = P - mulmod(2, mulmod(y1, j, P), P);

            self.y = addmod(left, right, P);
        }

        return self;
    }

    //--------------------------------------------------------------------------
    // Utils

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
