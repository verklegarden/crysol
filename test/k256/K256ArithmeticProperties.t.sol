// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {K256, SecretKey, PublicKey} from "src/k256/K256.sol";
import {
    K256Arithmetic, Point, ProjectivePoint
} from "src/k256/K256Arithmetic.sol";

/**
 * @notice K256Arithmetic Property Tests
 */
contract K256ArithmeticPropertiesTest is Test {
    using K256 for SecretKey;
    using K256 for PublicKey;
    using K256 for Point;

    using K256Arithmetic for Point;
    using K256Arithmetic for ProjectivePoint;

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
        vm.assume(scalar < K256Arithmetic.Q);

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
        vm.assume(scalar < K256Arithmetic.Q);

        ProjectivePoint memory p = sk.toPublicKey().toProjectivePoint();

        Point memory product = p.mul(scalar).intoPoint();

        assertTrue(product.isOnCurve());
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    function testProperty_Point_Encoded_SerializationLoop(Point memory start)
        public
    {
        Point memory end = K256Arithmetic.pointFromEncoded(start.toEncoded());

        assertTrue(start.eq(end));
    }

    function testProperty_Point_CompressedEncoded_SerializationLoop(
        SecretKey sk
    ) public {
        vm.assume(sk.isValid());

        Point memory start = sk.toPublicKey().intoPoint();

        Point memory end = K256Arithmetic.pointFromCompressedEncoded(
            start.toCompressedEncoded()
        );

        assertTrue(start.eq(end));
    }
}
