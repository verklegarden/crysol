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
 * @notice Secp256k1Arithmetic Property Tests
 */
contract Secp256k1ArithmeticPropertiesTest is Test {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Test: Projective Point

    // -- add

    function testProperty_ProjectivePoint_add_NeverReturnsZeroPoint(
        SecretKey sk1,
        SecretKey sk2
    ) public {
        vm.assume(sk1.isValid());
        vm.assume(sk2.isValid());

        ProjectivePoint memory p1 = sk1.toPublicKey().toProjectivePoint();
        ProjectivePoint memory p2 = sk2.toPublicKey().toProjectivePoint();

        Point memory sum = p1.add(p2).intoPoint();

        assertFalse(sum.isZeroPoint());
    }

    function testProperty_ProjectivePoint_add_ResultIsOnCurve(
        SecretKey sk1,
        SecretKey sk2
    ) public {
        vm.assume(sk1.isValid());
        vm.assume(sk2.isValid());

        ProjectivePoint memory p1 = sk1.toPublicKey().toProjectivePoint();
        ProjectivePoint memory p2 = sk2.toPublicKey().toProjectivePoint();

        Point memory sum = p1.add(p2).intoPoint();

        assertTrue(sum.isOnCurve());
    }

    // -- mul

    function testProperty_ProjectivePoint_mul_NeverReturnsZeroPoint(
        SecretKey sk,
        uint scalar
    ) public {
        vm.assume(sk.isValid());

        // TODO: Make Felt type to circumvent manual bounding?
        vm.assume(scalar < Secp256k1Arithmetic.Q);

        ProjectivePoint memory p = sk.toPublicKey().toProjectivePoint();

        Point memory product = p.mul(scalar).intoPoint();

        assertFalse(product.isZeroPoint());
    }

    function testProperty_ProjectivePoint_mul_ResultIsOnCurve(
        SecretKey sk,
        uint scalar
    ) public {
        vm.assume(sk.isValid());

        // TODO: Make Felt type to circumvent manual bounding?
        vm.assume(scalar < Secp256k1Arithmetic.Q);

        ProjectivePoint memory p = sk.toPublicKey().toProjectivePoint();

        Point memory product = p.mul(scalar).intoPoint();

        assertTrue(product.isOnCurve());
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    function testProperty_Point_Encoded_SerializationLoop(Point memory start)
        public
    {
        Point memory end =
            Secp256k1Arithmetic.pointFromEncoded(start.toEncoded());

        assertTrue(start.eq(end));
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    function testProperty_ModularInversion_ComputationIsConstant(uint x, uint y)
        public
    {
        vm.assume(x != 0);
        vm.assume(x < Secp256k1Arithmetic.P);
        vm.assume(y != 0);
        vm.assume(y < Secp256k1Arithmetic.P);

        uint first;
        uint second;
        uint before;

        // First
        before = gasleft();
        Secp256k1Arithmetic.modularInverseOf(x);
        first = before - gasleft();

        // Second
        before = gasleft();
        Secp256k1Arithmetic.modularInverseOf(y);
        second = before - gasleft();

        // Note to expect small cost differences.
        assertApproxEqAbs(first, second, 100);
    }
}
