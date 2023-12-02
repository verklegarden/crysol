// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "src/curves/Secp256k1Arithmetic.sol";

/**
 * @notice Secp256k1Arithmetic Unit Tests
 */
contract Secp256k1ArithmeticTest is Test {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    Secp256k1ArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new Secp256k1ArithmeticWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Point

    // -- ZeroPoint

    function test_ZeroPoint() public {
        assertTrue(wrapper.ZeroPoint().isZeroPoint());
    }

    // -- isZeroPoint

    function testFuzz_Point_isZeroPoint(Point memory point) public {
        if (point.x == 0 && point.y == 0) {
            assertTrue(wrapper.isZeroPoint(point));
        } else {
            assertFalse(wrapper.isZeroPoint(point));
        }
    }

    // -- Identity

    function test_Identity() public {
        assertTrue(wrapper.Identity().isIdentity());
    }

    // -- isIdentity

    function testFuzz_Point_isIdentity(Point memory point) public {
        if (point.x == type(uint).max && point.y == type(uint).max) {
            assertTrue(wrapper.isIdentity(point));
        } else {
            assertFalse(wrapper.isIdentity(point));
        }
    }

    // -- isOnCurve

    function testVectors_Point_isOnCurve() public {
        assertTrue(wrapper.isOnCurve(wrapper.G()));

        // TODO: Test Point.isOnCurve(): Add more points.
    }

    function testFuzz_Point_isOnCurve(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory point = sk.toPublicKey().intoPoint();

        assertTrue(wrapper.isOnCurve(point));
    }

    function test_Point_isOnCurve_PointAtInfinity() public {
        assertTrue(wrapper.isOnCurve(Secp256k1Arithmetic.PointAtInfinity()));
    }

    // -- yParity

    function testFuzz_Point_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(Point(x, y));

        assertEq(want, got);
    }

    // -- equals

    function testFuzz_Point_equals(PrivateKey privKey) public {
        vm.assume(privKey.isValid());

        Point memory point = privKey.toPublicKey().intoPoint();

        assertTrue(wrapper.equals(point, point));
    }

    function testFuzz_Point_equals_FailsIfPointsDoNotEqual(
        PrivateKey privKey1,
        PrivateKey privKey2
    ) public {
        vm.assume(privKey1.asUint() != privKey2.asUint());
        vm.assume(privKey1.isValid());
        vm.assume(privKey2.isValid());

        Point memory point1 = privKey1.toPublicKey().intoPoint();
        Point memory point2 = privKey2.toPublicKey().intoPoint();

        assertFalse(wrapper.equals(point1, point2));
    }

    function test_Point_equals_DoesNotRevert_IfPointsNotOnCurve(
        Point memory point1,
        Point memory point2
    ) public {
        wrapper.equals(point1, point2);
    }

    //----------------------------------
    // TODO: Test: Arithmetic

    //----------------------------------
    // Test: Type Conversion

    // -- toProjectivePoint

    function testFuzz_Point_toProjectivePoint(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory want = sk.toPublicKey().intoPoint();
        Point memory got = wrapper.toProjectivePoint(want).intoPoint();

        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }

    //--------------------------------------------------------------------------
    // Test: Projective Point

    //----------------------------------
    // Test: Type Conversion

    // TODO: Test no new memory allocation.
    // TODO: Not a real test. Use vectors from Paul Miller.
    function testFuzz_ProjectivePoint_intoPoint(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory want = sk.toPublicKey().intoPoint();
        Point memory got = wrapper.intoPoint(want.toProjectivePoint());

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
        // TODO: Test for proper error message.
        vm.expectRevert();
        wrapper.modularInverseOf(0);
    }

    function testFuzz_modularInverseOf_RevertsIf_XEqualToOrBiggerThanP(uint x)
        public
    {
        vm.assume(x >= Secp256k1Arithmetic.P);

        vm.expectRevert("NotAFieldElement(x)");
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
        vm.assume(x < Secp256k1Arithmetic.P);
        vm.assume(xInv < Secp256k1Arithmetic.P);

        vm.assume(mulmod(x, xInv, Secp256k1Arithmetic.P) != 1);

        assertFalse(wrapper.areModularInverse(x, xInv));
    }

    function testFuzz_areModularInverse_RevertsIf_XEqualToOrBiggerThanP(uint x)
        public
    {
        vm.assume(x >= Secp256k1Arithmetic.P);

        vm.expectRevert("NotAFieldElement(x)");
        wrapper.areModularInverse(x, 1);
    }

    function testFuzz_areModularInverse_RevertsIf_XInvEqualToOrBiggerThanP(
        uint xInv
    ) public {
        vm.assume(xInv >= Secp256k1Arithmetic.P);

        vm.expectRevert("NotAFieldElement(xInv)");
        wrapper.areModularInverse(1, xInv);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256k1ArithmeticWrapper {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (Point memory) {
        return Secp256k1Arithmetic.G();
    }

    //--------------------------------------------------------------------------
    // Point

    function ZeroPoint() public pure returns (Point memory) {
        return Secp256k1Arithmetic.ZeroPoint();
    }

    function isZeroPoint(Point memory point) public pure returns (bool) {
        return point.isZeroPoint();
    }

    function Identity() public pure returns (Point memory) {
        return Secp256k1Arithmetic.Identity();
    }

    function isIdentity(Point memory point) public pure returns (bool) {
        return point.isIdentity();
    }

    function isOnCurve(Point memory point) public pure returns (bool) {
        return point.isOnCurve();
    }

    function yParity(Point memory point) public pure returns (uint) {
        return point.yParity();
    }

    function equals(Point memory point, Point memory other)
        public
        pure
        returns (bool)
    {
        return point.equals(other);
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Point

    function toProjectivePoint(Point memory point)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return point.toProjectivePoint();
    }

    //----------------------------------
    // Projective Point

    function intoPoint(ProjectivePoint memory jPoint)
        public
        pure
        returns (Point memory)
    {
        return jPoint.intoPoint();
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
