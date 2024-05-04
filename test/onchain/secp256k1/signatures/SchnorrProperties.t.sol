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

import {
    Schnorr, Signature
} from "src/onchain/secp256k1/signatures/Schnorr.sol";
import {SchnorrOffchain} from
    "src/offchain/secp256k1/signatures/SchnorrOffchain.sol";

/**
 * @notice Schnorr Property Tests
 */
contract SchnorrPropertiesTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;

    using SchnorrOffchain for SecretKey;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

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

        assertEq(sig1.signature, sig2.signature);
        assertEq(sig1.commitment, sig2.commitment);
    }

    function testProperty_sign_CreatesNonMalleableSignatures(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        assertFalse(sk.sign(message).isMalleable());
    }

    //--------------------------------------------------------------------------
    // Properties: (De)Serialization
    //
    // TODO: Schnorr (De)Serialization Property tests once serialization defined.
}
