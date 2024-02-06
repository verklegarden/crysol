// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {K256, SecretKey, PublicKey} from "src/k256/K256.sol";
import {
    K256Arithmetic,
    Point,
    ProjectivePoint
} from "src/k256/K256Arithmetic.sol";

/**
 * @notice K256 Property Tests
 */
contract K256PropertiesTest is Test {
    using K256 for SecretKey;
    using K256 for PublicKey;
    using K256 for Point;

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    //----------------------------------
    // Secret Key

    function testProperty_SecretKey_Bytes_SerializationLoop(SecretKey start)
        public
    {
        SecretKey end = K256.secretKeyFromBytes(start.toBytes());

        assertEq(start.asUint(), end.asUint());
    }

    //----------------------------------
    // Public Key

    function testProperty_PublicKey_Bytes_SerializationLoop(
        PublicKey memory start
    ) public {
        PublicKey memory end = K256.publicKeyFromBytes(start.toBytes());

        assertTrue(start.eq(end));
    }
}
