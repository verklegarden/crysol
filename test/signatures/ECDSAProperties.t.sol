// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";

import {ECDSAOffchain} from "offchain/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

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
    // Properties: (De)Serialization

    // TODO: Property tests: (de)serialization reverts if malleable

    function testProperty_Signature_Encoding_SerializationLoop(
        Signature memory start
    ) public pure {
        vm.assume(!start.isMalleable());

        Signature memory end = ECDSA.signatureFromEncoded(start.toEncoded());

        assertEq(start.v, end.v);
        assertEq(start.r, end.r);
        assertEq(start.s, end.s);
    }

    function testProperty_Signature_CompactEncoding_SerializationLoop(
        SecretKey sk,
        bytes32 digest
    ) public pure {
        vm.assume(sk.isValid());

        Signature memory start = sk.sign(digest);
        Signature memory end =
            ECDSA.signatureFromCompactEncoded(start.toCompactEncoded());

        assertEq(start.v, end.v);
        assertEq(start.r, end.r);
        assertEq(start.s, end.s);
    }
}
