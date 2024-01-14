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
 * @notice Secp256k1 Property Tests
 */
contract Secp256k1PropertiesTest is Test {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    //----------------------------------
    // Secret Key

    function testProperty_SecretKey_Bytes_SerializationLoop(SecretKey start)
        public
    {
        SecretKey end = Secp256k1.secretKeyFromBytes(start.toBytes());

        assertEq(start.asUint(), end.asUint());
    }

    //----------------------------------
    // Public Key

    function testProperty_PublicKey_Bytes_SerializationLoop(
        PublicKey memory start
    ) public {
        PublicKey memory end = Secp256k1.publicKeyFromBytes(start.toBytes());

        assertTrue(start.eq(end));
    }
}
