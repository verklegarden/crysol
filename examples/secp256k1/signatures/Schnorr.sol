// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "src/offchain/secp256k1/Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256k1/Secp256k1.sol";

import {SchnorrOffchain} from
    "src/offchain/secp256k1/signatures/SchnorrOffchain.sol";
import {
    Schnorr, Signature
} from "src/onchain/secp256k1/signatures/Schnorr.sol";

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

    using SchnorrOffchain for Signature;
    using SchnorrOffchain for SecretKey;
    using SchnorrOffchain for PublicKey;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    function run() public {
        bytes memory message = bytes("crysol <3");

        // Create a cryptographically secure secret key.
        SecretKey sk = Secp256k1Offchain.newSecretKey();
        // assert(sk.isValid());

        // Create Schnorr signature.
        Signature memory sig = sk.sign(message);
        // assert(!sig.isMalleable());
        console.log("Signed message via Schnorr, signature:");
        console.log(sig.toString());
        console.log("");

        // Verify signature.
        // assert(sk.toPublicKey().verify(message, sig));
    }
}
