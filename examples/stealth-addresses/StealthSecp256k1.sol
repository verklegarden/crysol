// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {
    StealthSecp256k1,
    StealthAddress,
    StealthMetaAddress,
    SCHEME_ID
} from "src/stealth-addresses/StealthSecp256k1.sol";
import {
    IERC5564Announcer,
    ERC5564Announcer
} from "src/stealth-addresses/ERC5564Announcer.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

contract StealthSecp256k1Example is Script {
    using StealthSecp256k1 for PrivateKey;
    using StealthSecp256k1 for StealthAddress;
    using StealthSecp256k1 for StealthMetaAddress;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    function run() public {
        // Sender key pair.
        console.log("Sender: Creates key pair");
        PrivateKey senderPrivKey = Secp256k1.newPrivateKey();
        PublicKey memory senderPubKey = senderPrivKey.toPublicKey();

        // Receiver key pairs consist of spending and viewing key pairs.
        console.log("Receiver: Creates key pairs");
        PrivateKey receiverSpendingPrivKey = Secp256k1.newPrivateKey();
        PublicKey memory receiverSpendingPubKey =
            receiverSpendingPrivKey.toPublicKey();
        PrivateKey receiverViewPrivKey = Secp256k1.newPrivateKey();
        PublicKey memory receiverViewPubKey = receiverViewPrivKey.toPublicKey();

        // There exists an ERC5564Announcer instance.
        IERC5564Announcer announcer = IERC5564Announcer(new ERC5564Announcer());

        // Receiver creates their stealth meta address.
        // TODO: Note that these addresses need to be published somehow.
        console.log("Receiver: Creates stealth meta address");
        StealthMetaAddress memory receiverStealthMeta;
        receiverStealthMeta = StealthMetaAddress({
            spendingPubKey: receiverSpendingPubKey,
            viewingPubKey: receiverViewPubKey
        });

        // Sender creates stealth address from receiver's stealth meta address.
        console.log(
            "Sender: Creates stealth address based on receiver's meta address"
        );
        StealthAddress memory stealth = receiverStealthMeta.newStealthAddress();

        // Sender sends ETH to stealth.
        console.log("Sender: Sends ETH to receiver's stealth address");
        vm.deal(senderPubKey.toAddress(), 1 ether);
        vm.prank(senderPubKey.toAddress());
        (bool ok, ) = stealth.recipient.call{value: 1 ether}("");
        require(ok, "Sender: ETH transfer failed");

        // Sender announces tx via ERC5564Announcer.
        console.log("Sender: Announces tx via ERC5564Announcer");
        vm.prank(senderPubKey.toAddress());
        announcer.announce({
            schemeId: SCHEME_ID,
            stealthAddress: stealth.recipient,
            ephemeralPubKey: stealth.ephemeralPubKey.toBytes(),
            // See ERC5564Announcer.sol for more info.
            metadata: abi.encodePacked(
                stealth.viewTag,
                hex"eeeeeeee",
                hex"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                uint(1 ether)
                )
        });

        // Receiver checks announces stealth address.
        console.log("Receiver: Verifies tx is based on own meta address");
        require(
            receiverViewPrivKey.checkStealthAddress(
                receiverSpendingPubKey, stealth
            ),
            "Check failed"
        );

        // Receiver computed stealth's private key.
        console.log("Receiver: Computes private key for stealth address");
        PrivateKey stealthPrivKey = receiverSpendingPrivKey
            .computeStealthPrivateKey(receiverViewPrivKey, stealth);

        // Verify computed private key's address matches stealth's recipient
        // address.
        console.log("Receiver: Verifies access on stealth address");
        require(
            stealthPrivKey.toPublicKey().toAddress() == stealth.recipient,
            "Private key computation failed"
        );
    }
}
