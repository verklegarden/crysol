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

import {Secp256k1ArithmeticWrapper} from "./Secp256k1ArithmeticWrapper.sol";

contract Secp256k1ArithmeticTest is Test {
    using Secp256k1Arithmetic for AffinePoint;
    using Secp256k1Arithmetic for JacobianPoint;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    Secp256k1ArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new Secp256k1ArithmeticWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Affine Point

    // -- ZeroPoint

    function test_ZeroPoint() public {
        assertTrue(wrapper.ZeroPoint().isZeroPoint());
    }

    // -- isZeroPoint

    function testFuzz_AffinePoint_isZeroPoint(AffinePoint memory point)
        public
    {
        if (point.x == 0 && point.y == 0) {
            assertTrue(wrapper.isZeroPoint(point));
        } else {
            assertFalse(wrapper.isZeroPoint(point));
        }
    }

    // -- PointAtInfinity

    function test_PointAtInfinity() public {
        assertTrue(wrapper.PointAtInfinity().isPointAtInfinity());
    }

    // -- isPointAtInfinity

    function testFuzz_AffinePoint_isPointAtInfinity(AffinePoint memory point)
        public
    {
        if (point.x == type(uint).max && point.y == type(uint).max) {
            assertTrue(wrapper.isPointAtInfinity(point));
        } else {
            assertFalse(wrapper.isPointAtInfinity(point));
        }
    }

    // -- isOnCurve

    function testVectors_AffinePoint_isOnCurve() public {
        assertTrue(wrapper.isOnCurve(Secp256k1Arithmetic.G()));

        // @todo Test some more points.
    }

    function testFuzz_AffinePoint_isOnCurve(PrivateKey privKey) public {
        vm.assume(privKey.isValid());

        AffinePoint memory point = privKey.toPublicKey().intoAffinePoint();

        assertTrue(wrapper.isOnCurve(point));
    }

    // -- yParity

    function testFuzz_AffinePoint_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(AffinePoint(x, y));

        assertEq(want, got);
    }

    // -- toJacobianPoint

    function testFuzz_AffinePoint_toJacobianPoint(PrivateKey privKey) public {
        vm.assume(privKey.isValid());

        AffinePoint memory want = privKey.toPublicKey().intoAffinePoint();
        AffinePoint memory got = wrapper.toJacobianPoint(want).intoAffinePoint();

        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }

    //--------------------------------------------------------------------------
    // Test: Jacobian Point

    // @todo Test no new memory allocation.
    // @todo Not a real test. Use vectors from Paul Miller.
    function testFuzz_JacobianPoint_intoAffinePoint(PrivateKey privKey)
        public
    {
        vm.assume(privKey.isValid());

        AffinePoint memory want = privKey.toPublicKey().intoAffinePoint();
        AffinePoint memory got = wrapper.intoAffinePoint(want.toJacobianPoint());

        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // @todo Test: modularInverseOf: Differential fuzz against sage?
    function testVectors_modularInverseOf() public {
        uint x;
        uint want;
        uint got;

        // sage: inverse_mod(1, P) == 1
        x = 1;
        want = 1;
        got = wrapper.modularInverseOf(x);
        assertEq(want, got);

        // sage: inverse_mod(P - 1, P) == P -1
        x = Secp256k1Arithmetic.P - 1;
        want = Secp256k1Arithmetic.P - 1;
        got = wrapper.modularInverseOf(x);
        assertEq(want, got);

        // sage: inverse_mod(10, P) == 34737626771194858627071295502606372355980995399692169211837275202372650401499
        x = 10;
        want =
            34737626771194858627071295502606372355980995399692169211837275202372650401499;
        got = wrapper.modularInverseOf(x);
        assertEq(want, got);
    }

    function testFuzz_modularInverseOf_RevertsIf_XEqualToOrBiggerThanP(uint x)
        public
    {
        vm.assume(x >= Secp256k1Arithmetic.P);

        // @todo Test for proper error message.
        vm.expectRevert();
        wrapper.modularInverseOf(x);
    }
}
