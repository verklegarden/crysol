// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/Secp256k1.sol";

import {ECDSA, Signature} from "src/ECDSA.sol";

contract Example_ECDSA is Script {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    function signAndVerify() public {
        bytes memory message = bytes("crysol <3");

        // Create a cryptographically secure private key.
        PrivateKey privKey = Secp256k1.newPrivateKey();

        // Sign message via ECDSA.
        Signature memory sig = privKey.sign(message);

        // Verify signature verifies message.
        require(privKey.toPublicKey().verify(message, sig), "Signature invalid");

        // Print signature to stdout.
        console.log(sig.toString());
    }
}
