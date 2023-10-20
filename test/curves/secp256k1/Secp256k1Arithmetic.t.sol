// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {
    Secp256k1Arithmetic,
    AffinePoint,
    JacobianPoint
} from "src/curves/Secp256k1Arithmetic.sol";
import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

contract Secp256k1ArithmeticTest is Test {
    using Secp256k1Arithmetic for AffinePoint;
    using Secp256k1Arithmetic for JacobianPoint;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    //--------------------------------------------------------------------------
    // Test: Affine Point

    // -- ZeroPoint

    function test_ZeroPoint() public {
        assertTrue(Secp256k1Arithmetic.ZeroPoint().isZeroPoint());
    }

    // -- isZeroPoint

    function testFuzz_AffinePoint_isZeroPoint(AffinePoint memory point)
        public
    {
        if (point.x == 0 && point.y == 0) {
            assertTrue(point.isZeroPoint());
        } else {
            assertFalse(point.isZeroPoint());
        }
    }

    // -- PointAtInfinity

    function test_PointAtInfinity() public {
        assertTrue(Secp256k1Arithmetic.PointAtInfinity().isPointAtInfinity());
    }

    // -- isPointAtInfinity

    function testFuzz_AffinePoint_isPointAtInfinity(AffinePoint memory point)
        public
    {
        if (point.x == type(uint).max && point.y == type(uint).max) {
            assertTrue(point.isPointAtInfinity());
        } else {
            assertFalse(point.isPointAtInfinity());
        }
    }

    // -- isOnCurve

    function testVectors_AffinePoint_isOnCurve() public {
        assertTrue(Secp256k1Arithmetic.G().isOnCurve());

        // @todo Test some more points.
    }

    function testFuzz_AffinePoint_isOnCurve(PrivateKey privKey) public {
        vm.assume(privKey.isValid());

        assertTrue(privKey.toPublicKey().intoAffinePoint().isOnCurve());
    }

    // -- yParity

    function test_AffinePoint_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = AffinePoint(x, y).yParity();

        assertEq(want, got);
    }

    // -- toJacobianPoint

    function test_AffinePoint_toJacobianPoint(PrivateKey privKey) public {
        vm.assume(privKey.isValid());

        AffinePoint memory want = privKey.toPublicKey().intoAffinePoint();
        AffinePoint memory got = want.toJacobianPoint().intoAffinePoint();

        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }

    //--------------------------------------------------------------------------
    // Test: Jacobian Point
}
