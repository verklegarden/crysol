// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "src/offchain/secp256k1/Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256k1/Secp256k1.sol";

import {ECDSAOffchain} from
    "src/offchain/secp256k1/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/onchain/secp256k1/signatures/ECDSA.sol";

/**
 * @notice Secp256k1 ECDSA Property Tests
 */
contract ECDSAPropertiesTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;

    using ECDSAOffchain for SecretKey;
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    //--------------------------------------------------------------------------
    // Properties: Signature

    function testProperty_sign_CreatesVerifiableSignatures(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        PublicKey memory pk = sk.toPublicKey();
        Signature memory sig = sk.sign(message);

        assertTrue(pk.verify(message, sig));
    }

    function testProperty_sign_CreatesDeterministicSignatures(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig1 = sk.sign(message);
        Signature memory sig2 = sk.sign(message);

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);
    }

    function testProperty_sign_CreatesNonMalleableSignatures(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(message);

        assertFalse(sig.isMalleable());
    }

    //--------------------------------------------------------------------------
    // Properties: (De)Serialization

    function testProperty_Encoding_SerializationLoop(Signature memory start)
        public
    {
        vm.assume(!start.isMalleable());

        Signature memory end = ECDSA.signatureFromEncoded(start.toEncoded());

        assertEq(start.v, end.v);
        assertEq(start.r, end.r);
        assertEq(start.s, end.s);
    }

    function testProperty_CompactEncoding_SerializationLoop(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        Signature memory start = sk.sign(message);
        Signature memory end =
            ECDSA.signatureFromCompactEncoded(start.toCompactEncoded());

        assertEq(start.v, end.v);
        assertEq(start.r, end.r);
        assertEq(start.s, end.s);
    }
}
