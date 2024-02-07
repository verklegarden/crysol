// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {K256, SecretKey, PublicKey} from "src/k256/K256.sol";
import {
    K256Arithmetic, Point, ProjectivePoint
} from "src/k256/K256Arithmetic.sol";

/**
 * @title K256Example
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/k256/K256.sol:K256Example -vvvv
 *      ```
 *
 * @dev Note that some code is commented out to reduce compiler warnings
 *      regarding unused variables.
 */
contract K256Example is Script {
    using K256 for SecretKey;
    using K256 for PublicKey;

    using K256Arithmetic for Point;

    function run() public {
        // Create new cryptographically sound secret key.
        SecretKey sk = K256.newSecretKey();
        assert(sk.isValid());
        console.log("Created new secret key:");
        console.log(sk.asUint());
        console.log("");

        // Derive public key.
        PublicKey memory pk = sk.toPublicKey();
        assert(pk.isValid());
        console.log("Derived public key:");
        console.log(pk.toString());
        console.log("");

        // Arithmetic types.
        // into___() -> overwrites memory, no allocation / memory expansion cost
        // to___()   -> allocates new memory, may has expansion cost
        /*
        Point memory point = pk.intoPoint();
        ProjectivePoint memory jPoint = pk.toProjectivePoint();
        */

        // Derive common constructs.
        address addr = pk.toAddress();
        /*
        bytes32 digest = pk.toHash();
        uint yParity = pk.yParity();
        */
        console.log("Derived address:");
        console.log(addr);
        console.log("");

        // Serialization.
        console.log("ABI serialized public key:");
        console.logBytes(pk.toBytes());
        console.log("");

        console.log("SEC encoded public key:");
        console.logBytes(pk.intoPoint().toEncoded());
        console.log("");

        console.log("SEC compressed encoded public key:");
        console.logBytes(pk.intoPoint().toCompressedEncoded());
        console.log("");
    }
}
