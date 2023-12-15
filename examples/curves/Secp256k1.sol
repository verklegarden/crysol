// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";
import {Secp256k1Arithmetic, Point, ProjectivePoint} from 
    "src/curves/Secp256k1Arithmetic.sol";

contract Secp256k1Example is Script {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    function run() public {
        // Create new cryptographically sound secret key.
        SecretKey sk = Secp256k1.newSecretKey();
        assert(sk.isValid());

        // Derive public key.
        PublicKey memory pk = sk.toPublicKey();
        assert(pk.isValid());

        // Arithmetic types.
        // into***() -> no memory allocation
        // to***() -> new memory allocation
        Point memory point = pk.intoPoint();
        ProjectivePoint memory jPoint = pk.toProjectivePoint();

        // Derive common constructs.
        address addr = pk.toAddress();
        bytes32 digest = pk.toHash();
        uint yParity = pk.yParity();

        // ABI serialization.
        sk = Secp256k1.secretKeyFromBytes(sk.toBytes());
        pk = Secp256k1.publicKeyFromBytes(pk.toBytes());

        // SEC1 serialization.
        pk = Secp256k1.publicKeyFromEncoded(pk.toEncoded());
    }
}
