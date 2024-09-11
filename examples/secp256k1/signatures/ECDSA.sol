// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "src/offchain/secp256k1/Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256k1/Secp256k1.sol";

import {ECDSAOffchain} from
    "src/offchain/secp256k1/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/onchain/secp256k1/signatures/ECDSA.sol";

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
        // Create new cryptographically sound secret key and respective
        // public key and address.
        SecretKey sk = Secp256k1Offchain.newSecretKey();
        PublicKey memory pk = sk.toPublicKey();
        address addr = pk.toAddress();

        // Create digest of the message to sign.
        //
        // crysol's sign() functions only accept bytes32 digests to enforce
        // static payload size.
        bytes32 digest = keccak256(bytes("crysol <3"));

        // Note that crysol's sign() function domain separates input digests.
        // The actual message being signed can be constructed via:
        bytes32 m = ECDSA.constructMessageHash(digest);

        // Sign digest via ECDSA.
        Signature memory sig = sk.sign(digest);
        console.log("Signed message via ECDSA, signature:");
        console.log(sig.toString());
        console.log("");

        // It's also possible to use the low-level signRaw() function to not
        // domain separate the input digest.
        // However, usage is discouraged.
        Signature memory sig2 = sk.signRaw(m);

        // Note that crysol uses RFC-6979 to construct deterministic ECDSA
        // nonces and thereby signatures. Therefore, the two signatures are
        // expected to be equal.
        assert(sig.v == sig2.v);
        assert(sig.r == sig2.r);
        assert(sig.s == sig2.s);

        // Verify signature via public key or address.
        assert(pk.verify(m, sig));
        assert(addr.verify(m, sig));

        // Default serialization (65 bytes).
        console.log("Default encoded signature:");
        console.logBytes(sig.toEncoded());
        console.log("");

        // EIP-2098 serialization (64 bytes).
        console.log("EIP-2098 (compact) encoded signature:");
        console.logBytes(sig.toCompactEncoded());
        console.log("");
    }
}
