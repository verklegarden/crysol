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

    // -- modularInverseOf

    function testFuzz_modularInverseOf(uint x) public {
        vm.assume(x != 0);
        vm.assume(x < Secp256k1Arithmetic.P);

        uint xInv = Secp256k1Arithmetic.modularInverseOf(x);

        // Verify x * xInv ≡ 1 (mod P).
        assertEq(mulmod(x, xInv, Secp256k1Arithmetic.P), 1);
    }

    function test_modularInverseOf_RevertsIf_XIsZero() public {
        // @todo Test for proper error message.
        vm.expectRevert();
        wrapper.modularInverseOf(0);
    }

    function testFuzz_modularInverseOf_RevertsIf_XEqualToOrBiggerThanP(uint x)
        public
    {
        vm.assume(x >= Secp256k1Arithmetic.P);

        // @todo Test for proper error message.
        vm.expectRevert();
        wrapper.modularInverseOf(x);
    }

    // -- areModularInverse

    function testFuzz_areModularInverse(uint x) public {
        vm.assume(x != 0);
        vm.assume(x < Secp256k1Arithmetic.P);

        assertTrue(
            wrapper.areModularInverse(
                x, Secp256k1Arithmetic.modularInverseOf(x)
            )
        );
    }

    function testFuzz_areModularInverse_FailsIf_NotModularInverse(
        uint x,
        uint xInv
    ) public {
        vm.assume(x != 0);
        vm.assume(x < Secp256k1Arithmetic.P);
        vm.assume(xInv != 0);
        vm.assume(xInv < Secp256k1Arithmetic.P);

        vm.assume(mulmod(x, xInv, Secp256k1Arithmetic.P) != 1);

        assertFalse(wrapper.areModularInverse(x, xInv));
    }

    function test_areModularInverse_RevertsIf_XIsZero() public {
        // @todo Test for proper error message.
        vm.expectRevert();
        wrapper.areModularInverse(0, 1);
    }

    function test_areModularInverse_RevertsIf_XInvIsZero() public {
        // @todo Test for proper error message.
        vm.expectRevert();
        wrapper.areModularInverse(1, 0);
    }

    function testFuzz_areModularInverse_RevertsIf_XEqualToOrBiggerThanP(uint x)
        public
    {
        vm.assume(x >= Secp256k1Arithmetic.P);

        // @todo Test for proper error message.
        vm.expectRevert();
        wrapper.areModularInverse(x, 1);
    }

    function testFuzz_areModularInverse_RevertsIf_XInvEqualToOrBiggerThanP(
        uint xInv
    ) public {
        vm.assume(xInv >= Secp256k1Arithmetic.P);

        // @todo Test for proper error message.
        vm.expectRevert();
        wrapper.areModularInverse(1, xInv);
    }
}

/**
 * @title Secp256k1ArithmeticWrapper
 *
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256k1ArithmeticWrapper {
    using Secp256k1Arithmetic for AffinePoint;
    using Secp256k1Arithmetic for JacobianPoint;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (AffinePoint memory) {
        return Secp256k1Arithmetic.G();
    }

    //--------------------------------------------------------------------------
    // Affine Point

    function ZeroPoint() public pure returns (AffinePoint memory) {
        return Secp256k1Arithmetic.ZeroPoint();
    }

    function isZeroPoint(AffinePoint memory point) public pure returns (bool) {
        return point.isZeroPoint();
    }

    function PointAtInfinity() public pure returns (AffinePoint memory) {
        return Secp256k1Arithmetic.PointAtInfinity();
    }

    function isPointAtInfinity(AffinePoint memory point)
        public
        pure
        returns (bool)
    {
        return point.isPointAtInfinity();
    }

    function isOnCurve(AffinePoint memory point) public pure returns (bool) {
        return point.isOnCurve();
    }

    function yParity(AffinePoint memory point) public pure returns (uint) {
        return point.yParity();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Affine Point

    function toJacobianPoint(AffinePoint memory point)
        public
        pure
        returns (JacobianPoint memory)
    {
        return point.toJacobianPoint();
    }

    //----------------------------------
    // Jacobian Point

    function intoAffinePoint(JacobianPoint memory jacPoint)
        public
        pure
        returns (AffinePoint memory)
    {
        return jacPoint.intoAffinePoint();
    }

    //--------------------------------------------------------------------------
    // Utils

    function modularInverseOf(uint x) public pure returns (uint) {
        return Secp256k1Arithmetic.modularInverseOf(x);
    }

    function areModularInverse(uint x, uint xInv) public pure returns (bool) {
        return Secp256k1Arithmetic.areModularInverse(x, xInv);
    }
}
