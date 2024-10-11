// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";
import {
    PointArithmetic,
    Point,
    ProjectivePoint
} from "src/arithmetic/PointArithmetic.sol";

/**
 * @title Secp256k1Example
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/Secp256k1.sol:Secp256k1Example -vvvv
 *      ```
 *
 * @dev Note that some code is commented out to reduce compiler warnings
 *      regarding unused variables.
 */
contract Secp256k1Example is Script {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1Offchain for PublicKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using PointArithmetic for Point;

    function run() public {
        // Create new cryptographically sound secret key.
        SecretKey sk = Secp256k1Offchain.newSecretKey();
        // assert(sk.isValid());
        console.log("Created new secret key:");
        console.log(sk.asUint());
        console.log("");

        // Derive public key.
        PublicKey memory pk = sk.toPublicKey();
        // assert(pk.isValid());
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
        address addr1 = sk.toAddress();
        address addr2 = pk.toAddress();
        assert(addr1 == addr2);
        /*
        bytes32 digest = pk.toHash();
        uint yParity = pk.yParity();
        */
        console.log("Derived address:");
        console.log(addr1);
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
