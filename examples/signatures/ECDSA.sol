// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

contract ECDSAExample is Script {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    using ECDSA for address;
    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    function signAndVerify() public {
        bytes memory message = bytes("crysol <3");

        // Create a cryptographically secure private key.
        PrivateKey privKey = Secp256k1.newPrivateKey();

        // Sign message via ECDSA.
        Signature memory sig = privKey.sign(message);

        // Verify signature via public key or address.
        PublicKey memory pubKey = privKey.toPublicKey();
        address addr = pubKey.toAddress();
        require(pubKey.verify(message, sig), "Signature invalid");
        require(addr.verify(message, sig), "Signature invalid");

        // Print signature to stdout.
        console.log(sig.toString());

        // Serialization.
        bytes memory blob = sig.toBytes();
        sig = ECDSA.signatureFromBytes(blob);
        bytes memory blob2 = sig.toCompactBytes(); // See EIP-2098
        sig = ECDSA.signatureFromCompactBytes(blob2);
    }
}
