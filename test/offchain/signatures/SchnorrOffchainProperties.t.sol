// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";
import {Points, Point} from "src/arithmetic/Points.sol";

import {SchnorrOffchain} from "offchain/signatures/SchnorrOffchain.sol";
import {Schnorr, Signature} from "src/signatures/Schnorr.sol";

/**
 * @notice SchnorrOffchain Property Tests
 */
contract SchnorrOffchainPropertiesTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using SchnorrOffchain for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    //--------------------------------------------------------------------------
    // Properties: Signature Creation

    // -- sign

    function testProperty_sign_CreatesVerifiableSignatures(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(sk.isValid());

        bytes32 m = Schnorr.constructMessageHash(digest);

        Signature memory sig = sk.sign(digest);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testProperty_sign_CreatesNonDeterministicSignatures(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig1 = sk.sign(digest);
        Signature memory sig2 = sk.sign(digest);

        assertNotEq(sig1.s, sig2.s);
        assertFalse(sig1.r.eq(sig2.r));
    }

    function testProperty_sign_CreatesSaneSignatures(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(sk.isValid());

        assertTrue(sk.sign(digest).isSane());
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

    function testProperty_signRaw_CreatesNonDeterministicSignatures(
        SecretKey sk,
        bytes32 m
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig1 = sk.sign(m);
        Signature memory sig2 = sk.sign(m);

        assertNotEq(sig1.s, sig2.s);
        assertFalse(sig1.r.eq(sig2.r));
    }

    function testProperty_signRaw_CreatesSaneSignatures(SecretKey sk, bytes32 m)
        public
    {
        vm.assume(sk.isValid());

        assertTrue(sk.signRaw(m).isSane());
    }

    // -- signRaw with rand

    function testProperty_signRaw_WithRand_CreatesVerifiableSignatures(
        SecretKey sk,
        bytes32 m,
        bytes32 rand
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.signRaw(m, rand);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testProperty_signRaw_WithRand_CreatesDeterministicSignatures(
        SecretKey sk,
        bytes32 m,
        bytes32 rand
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig1 = sk.signRaw(m, rand);
        Signature memory sig2 = sk.signRaw(m, rand);

        assertEq(sig1.s, sig2.s);
        assertTrue(sig1.r.eq(sig2.r));
    }

    function testProperty_signRaw_WithRand_CreatesSaneSignatures(
        SecretKey sk,
        bytes32 m,
        bytes32 rand
    ) public {
        vm.assume(sk.isValid());

        assertTrue(sk.signRaw(m, rand).isSane());
    }
}
