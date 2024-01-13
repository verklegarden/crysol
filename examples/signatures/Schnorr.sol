// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";

import {Schnorr, Signature} from "src/signatures/Schnorr.sol";

contract SchnorrExample is Script {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    function run() public {
        bytes memory message = bytes("crysol <3");

        // Create a cryptographically secure secret key.
        SecretKey sk = Secp256k1.newSecretKey();
        assert(sk.isValid());

        // Create Schnorr signature.
        Signature memory sig = sk.sign(message);
        assert(!sig.isMalleable());

        // Verify signature.
        PublicKey memory pk = sk.toPublicKey();
        require(pk.verify(message, sig), "Could not verify own signature");

        // Print signature to stdout.
        console.log(sig.toString());
    }
}
