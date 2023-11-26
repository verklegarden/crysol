// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Schnorr, Signature} from "src/signatures/Schnorr.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

/**
 * @notice Schnorr Property Tests
 */
contract SchnorrPropertiesTest is Test {
    using Schnorr for PrivateKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    using Secp256k1 for PrivateKey;

    //--------------------------------------------------------------------------
    // Properties: Signature

    function testProperty_CreatedSignaturesAreVerifiable(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();

        assertTrue(pubKey.verify(message, privKey.sign(message)));
    }

    function testProperty_CreatedSignaturesAreDeterministic(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        Signature memory sig1 = privKey.sign(message);
        Signature memory sig2 = privKey.sign(message);

        assertEq(sig1.signature, sig2.signature);
        assertEq(sig1.commitment, sig2.commitment);
    }

    function testProperty_CreatedSignaturesAreNonMalleable(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        assertFalse(privKey.sign(message).isMalleable());
    }

    //--------------------------------------------------------------------------
    // Properties: (De)Serialization
}
