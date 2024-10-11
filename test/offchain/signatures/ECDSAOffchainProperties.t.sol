// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";

import {ECDSAOffchain} from "offchain/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

/**
 * @notice ECDSAOffchain Property Tests
 */
contract ECDSAOffchainPropertiesTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;

    using ECDSAOffchain for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    //--------------------------------------------------------------------------
    // Properties: Signature Creation

    // -- sign

    function testProperty_sign_CreatesVerifiableSignatures(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(sk.isValid());

        bytes32 m = ECDSA.constructMessageHash(digest);

        Signature memory sig = sk.sign(digest);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testProperty_sign_CreatesDeterministicSignatures(
        SecretKey sk,
        bytes32 digest
    ) public pure {
        vm.assume(sk.isValid());

        Signature memory sig1 = sk.sign(digest);
        Signature memory sig2 = sk.sign(digest);

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);
    }

    function testProperty_sign_CreatesNonMalleableSignatures(
        SecretKey sk,
        bytes32 digest
    ) public pure {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(digest);

        assertFalse(sig.isMalleable());
    }

    // -- signRaw

    function testProperty_signRaw_CreatesVerifiableSignatures(
        SecretKey sk,
        bytes32 m
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.signRaw(m);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testProperty_signRaw_CreatesDeterministicSignatures(
        SecretKey sk,
        bytes32 m
    ) public pure {
        vm.assume(sk.isValid());

        Signature memory sig1 = sk.signRaw(m);
        Signature memory sig2 = sk.signRaw(m);

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);
    }

    function testProperty_signRaw_CreatesNonMalleableSignatures(
        SecretKey sk,
        bytes32 m
    ) public pure {
        vm.assume(sk.isValid());

        Signature memory sig = sk.signRaw(m);

        assertFalse(sig.isMalleable());
    }
}
