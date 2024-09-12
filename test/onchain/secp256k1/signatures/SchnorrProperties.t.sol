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
    Schnorr,
    Signature,
    SignatureCompressed
} from "src/onchain/secp256k1/signatures/Schnorr.sol";
import {SchnorrOffchain} from
    "src/offchain/secp256k1/signatures/SchnorrOffchain.sol";

/**
 * @notice Schnorr Property Tests
 */
contract SchnorrPropertiesTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using SchnorrOffchain for SecretKey;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;
    using Schnorr for SignatureCompressed;

    //--------------------------------------------------------------------------
    // Properties: (De)Serialization

    // TODO: Property tests: (de)serialization reverts if malleable

    function testProperty_Signature_Encoding_SerializationLoop(
        SecretKey sk,
        bytes32 d
    ) public {
        vm.assume(sk.isValid());

        Signature memory start = sk.sign(d);
        Signature memory end = Schnorr.signatureFromEncoded(start.toEncoded());

        assertEq(start.s, end.s);
        assertTrue(start.r.eq(end.r));
    }

    function testProperty_SignatureCompressed_CompressedEncoding_SerializationLoop(
        SecretKey sk,
        bytes32 d
    ) public {
        vm.assume(sk.isValid());

        SignatureCompressed memory start = sk.sign(d).intoCompressed();
        SignatureCompressed memory end =
            Schnorr.signatureFromCompressedEncoded(start.toCompressedEncoded());

        assertEq(start.s, end.s);
        assertEq(start.rAddr, end.rAddr);
    }
}
