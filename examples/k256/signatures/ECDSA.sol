// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {K256, SecretKey, PublicKey} from "src/k256/K256.sol";

import {ECDSA, Signature} from "src/k256/signatures/ECDSA.sol";

/**
 * @title ECDSAExample
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/k256/signatures/ECDSA.sol:ECDSAExample -vvvv
 *      ```
 */
contract ECDSAExample is Script {
    using K256 for SecretKey;
    using K256 for PublicKey;

    using ECDSA for address;
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    function run() public {
        bytes memory message = bytes("crysol <3");

        // Create new cryptographically sound secret key.
        SecretKey sk = K256.newSecretKey();
        assert(sk.isValid());

        // Sign message via ECDSA.
        Signature memory sig = sk.sign(message);
        console.log("Signed message via ECDSA, signature:");
        console.log(sig.toString());
        console.log("");

        // Verify signature via public key or address.
        PublicKey memory pk = sk.toPublicKey();
        require(sk.toPublicKey().verify(message, sig), "Signature invalid");
        address addr = pk.toAddress();
        require(addr.verify(message, sig), "Signature invalid");

        // Default serialization (65 bytes).
        console.log("Default encoded signature:");
        console.logBytes(sig.toEncoded());
        console.log("");

        // EIP-2098 serialization (64 bytes).
        console.log("EIP-2098 (compact) encoded signature:");
        console.logBytes(sig.toCompactEncoded());
    }
}
