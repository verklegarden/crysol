// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";

/**
 * @notice ECDSA Property Tests
 */
contract ECDSAPropertiesTest is Test {
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    using Secp256k1 for SecretKey;

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

    function testProperty_Bytes_SerializationLoop(Signature memory sig)
        public
    {
        Signature memory got = ECDSA.signatureFromBytes(sig.toBytes());

        assertEq(got.v, sig.v);
        assertEq(got.r, sig.r);
        assertEq(got.s, sig.s);
    }

    function testProperty_CompactBytes_SerializationLoop(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        Signature memory want = sk.sign(message);
        Signature memory got =
            ECDSA.signatureFromCompactBytes(want.toCompactBytes());

        assertEq(got.v, want.v);
        assertEq(got.r, want.r);
        assertEq(got.s, want.s);
    }
}
