// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";
import {Points, Point, ProjectivePoint} from "src/arithmetic/Points.sol";

/**
 * @notice Secp256k1 Property Tests
 */
contract Secp256k1PropertiesTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    //----------------------------------
    // Secret Key

    function testProperty_SecretKey_Bytes_SerializationLoop(SecretKey start)
        public
        pure
    {
        vm.assume(start.isValid());

        SecretKey end = Secp256k1.secretKeyFromBytes(start.toBytes());

        assertEq(start.asUint(), end.asUint());
    }

    //----------------------------------
    // Public Key

    function testProperty_PublicKey_Bytes_SerializationLoop(SecretKey sk)
        public
    {
        vm.assume(sk.isValid());

        PublicKey memory start = sk.toPublicKey();
        PublicKey memory end = Secp256k1.publicKeyFromBytes(start.toBytes());

        assertTrue(start.eq(end));
    }
}
