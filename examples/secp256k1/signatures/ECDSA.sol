// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/secp256k1/Secp256k1Offchain.sol";
import {ECDSAOffchain} from "offchain/secp256k1/signatures/ECDSAOffchain.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/secp256k1/Secp256k1.sol";

import {ECDSA, Signature} from "src/secp256k1/signatures/ECDSA.sol";

/**
 * @title ECDSAExample
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/secp256k1/signatures/ECDSA.sol:ECDSAExample -vvvv
 *      ```
 */
contract ECDSAExample is Script {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1Offchain for PublicKey;

    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using ECDSAOffchain for SecretKey;
    using ECDSAOffchain for Signature;

    using ECDSA for address;
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    function run() public {
        bytes memory message = bytes("crysol <3");

        // Create new cryptographically sound secret key.
        SecretKey sk = Secp256k1Offchain.newSecretKey();
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
