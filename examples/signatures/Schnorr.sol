// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/Secp256k1.sol";

import {SchnorrOffchain} from
    "offchain/signatures/SchnorrOffchain.sol";
import {
    Schnorr,
    Signature,
    SignatureCompressed
} from "src/signatures/Schnorr.sol";

/**
 * @title SchnorrExample
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/secp256k1/signatures/Schnorr.sol:SchnorrExample -vvvv
 *      ```
 */
contract SchnorrExample is Script {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1Offchain for PublicKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using SchnorrOffchain for SecretKey;
    using SchnorrOffchain for PublicKey;
    using SchnorrOffchain for Signature;
    using SchnorrOffchain for SignatureCompressed;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;
    using Schnorr for SignatureCompressed;

    function run() public {
        // Create new cryptographically sound secret key and respective
        // public key.
        SecretKey sk = Secp256k1Offchain.newSecretKey();
        PublicKey memory pk = sk.toPublicKey();

        // Create digest of the message to sign.
        //
        // crysol's sign() functions only accept bytes32 digests to enforce
        // static payload size.
        bytes32 digest = keccak256(bytes("crysol <3"));

        // Note that crysol's sign() function domain separates input digests.
        // The actual message being signed can be constructed via:
        bytes32 m = Schnorr.constructMessageHash(digest);

        // Sign digest via Schnorr.
        Signature memory sig = sk.sign(digest);
        console.log("Signed message via Schnorr, signature:");
        console.log(sig.toString());
        console.log("");

        // Note that Schnorr signatures can be compressed too.
        SignatureCompressed memory sigComp = sig.toCompressed();
        console.log("Compressed Schnorr signature:");
        console.log(sigComp.toString());
        console.log("");

        // It's also possible to use the low-level signRaw() function to not
        // domain separate the input digest.
        // However, usage is discouraged.
        Signature memory sig2 = sk.signRaw(m);

        // Note that crysol uses random nonces to construct Schnorr signatures.
        // Therefore, the two signatures are expected to not be equal.
        assert(sig.s != sig2.s);
        assert(!sig.r.eq(sig2.r));

        // Verify signature via public key.
        assert(pk.verify(m, sig));

        // Default serialization (96 bytes).
        console.log("Default encoded signature:");
        console.logBytes(sig.toEncoded());
        console.log("");

        // Compressed serialization (52 bytes).
        console.log("Compressed Schnorr signature:");
        console.logBytes(sig.toCompressedEncoded());
        console.log("");
    }
}
