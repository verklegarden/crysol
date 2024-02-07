// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {K256, SecretKey, PublicKey} from "src/k256/K256.sol";

import {Schnorr, Signature} from "src/k256/signatures/Schnorr.sol";

/**
 * @title SchnorrExample
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/k256/signatures/Schnorr.sol:SchnorrExample -vvvv
 *      ```
 */
contract SchnorrExample is Script {
    using K256 for SecretKey;
    using K256 for PublicKey;

    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    function run() public {
        bytes memory message = bytes("crysol <3");

        // Create a cryptographically secure secret key.
        SecretKey sk = K256.newSecretKey();
        assert(sk.isValid());

        // Create Schnorr signature.
        Signature memory sig = sk.sign(message);
        assert(!sig.isMalleable());
        console.log("Signed message via Schnorr, signature:");
        console.log(sig.toString());
        console.log("");

        // Verify signature.
        PublicKey memory pk = sk.toPublicKey();
        require(pk.verify(message, sig), "Could not verify own signature");
    }
}
