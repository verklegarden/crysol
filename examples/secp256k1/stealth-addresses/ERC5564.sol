// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";
import {StdStyle} from "forge-std/StdStyle.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/secp256k1/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "src/secp256k1/Secp256k1.sol";

import {
    ERC5564,
    StealthMetaAddress,
    StealthAddress
} from "src/secp256k1/stealth-addresses/ERC5564.sol";

/**
 * @title ERC5564Example
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/secp256k1/stealth-addresses/ERC5564.sol:ERC5564Example -vvvv
 *      ```
 */
contract ERC5564Example is Script {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using ERC5564 for SecretKey;
    using ERC5564 for StealthMetaAddress;

    function run() public {
        // Alice creates a key pair funded with 1 ETH.
        SecretKey aliceSk = Secp256k1.newSecretKey();
        PublicKey memory alicePk = aliceSk.toPublicKey();
        vm.deal(alicePk.toAddress(), 1 ether);
        logAlice("Created new address funded with 1 ETH");

        // Bob creates two key pairs for their stealth meta address,
        // the spend key pair and the view key pair.
        SecretKey bobSpendSk = Secp256k1.newSecretKey();
        PublicKey memory bobSpendPk = bobSpendSk.toPublicKey();
        SecretKey bobViewSk = Secp256k1.newSecretKey();
        PublicKey memory bobViewPk = bobViewSk.toPublicKey();
        logBob("Created two key pairs for their stealth meta address");

        // Bob creates their stealth meta address and publishes it via some
        // known channel, eg an ERC-5564 Registry contract.
        StealthMetaAddress memory bobStealthMeta =
            StealthMetaAddress({spendPk: bobSpendPk, viewPk: bobViewPk});
        logBob(
            string.concat(
                "Created and published stealth meta address: ",
                bobStealthMeta.toString("eth")
            )
        );

        // Alice creates a new stealth address from Bob's publicly known stealth
        // meta address.
        StealthAddress memory stealth = bobStealthMeta.generateStealthAddress();
        logAlice("Generated stealth address from Bob stealth meta address");

        // Alice sends 1 ETH to the stealth address only accessible by Bob and
        // publishes the stealth address via some know channel, eg an ERC-5564
        // Announcer contract.
        vm.prank(alicePk.toAddress());
        (bool ok,) = stealth.addr.call{value: 1 ether}("");
        assert(ok);
        logAlice(
            "Send 1 ETH to stealth address and published the stealth address"
        );

        // Bob checks whether the announced stealth address belongs to them.
        bool found = bobViewSk.checkStealthAddress(bobSpendPk, stealth);
        assert(found);
        logBob("Found out the stealth address belongs to them");

        // Bob computes the stealth address' secret key.
        SecretKey stealthSk =
            bobSpendSk.computeStealthSecretKey(bobViewSk, stealth);
        logBob("Computed the stealth address' secret key");

        // Verify secret key is correct:
        assert(stealthSk.toPublicKey().toAddress() == stealth.addr);
    }

    function logAlice(string memory message) internal pure {
        console.log(string.concat(StdStyle.yellow("[ALICE] "), message));
    }

    function logBob(string memory message) internal pure {
        console.log(string.concat(StdStyle.blue("[BOB]   "), message));
    }
}
