// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";
import {Secp256k1Arithmetic, Point, JacobianPoint} from "src/curves/Secp256k1Arithmetic.sol";

contract Secp256k1Example is Script {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    function run() public {
        // Create new cryptographically sound private key.
        PrivateKey privKey = Secp256k1.newPrivateKey();

        // Derive public key.
        PublicKey memory pubKey = privKey.toPublicKey();

        // Arithmetic types.
        // into() -> no memory allocation, to() -> new memory allocation
        Point memory point = pubKey.intoPoint();
        JacobianPoint memory jacPoint = pubKey.toJacobianPoint();

        // Print some stuff.
        console.log("Address", pubKey.toAddress());
        console.log("Parity", pubKey.yParity());
        console.logBytes32(pubKey.toHash());
        console.log("Valid", pubKey.isValid());

        // Serialization.
        privKey = Secp256k1.privateKeyFromBytes(privKey.toBytes());
        pubKey = Secp256k1.publicKeyFromBytes(pubKey.toBytes());
    }
}
