// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

import {Schnorr, Signature} from "src/signatures/Schnorr.sol";

contract SchnorrExample is Script {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    using Schnorr for PrivateKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    function signAndVerify() public {
        bytes memory message = bytes("crysol <3");

        // Create a cryptographically secure private key.
        PrivateKey privKey = Secp256k1.newPrivateKey();

        // Sign message via Schnorr.
        Signature memory sig = privKey.sign(message);

        // Verify signature.
        PublicKey memory pubKey = privKey.toPublicKey();
        require(pubKey.verify(message, sig), "Signature invalid");

        // Print signature to stdout.
        console.log(sig.toString());
    }
}
