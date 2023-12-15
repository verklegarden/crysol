// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

contract ECDSAExample is Script {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using ECDSA for address;
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    function signAndVerify() public {
        bytes memory message = bytes("crysol <3");

        // Create new cryptographically sound secret key.
        SecretKey sk = Secp256k1.newSecretKey();
        assert(sk.isValid());

        // Sign message via ECDSA.
        Signature memory sig = sk.sign(message);

        // Verify signature via public key or address.
        PublicKey memory pk = sk.toPublicKey();
        require(sk.toPublicKey().verify(message, sig), "Signature invalid");
        address addr = pk.toAddress();
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
