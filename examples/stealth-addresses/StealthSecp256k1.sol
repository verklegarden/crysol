// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {StdStyle} from "forge-std/StdStyle.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";

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

contract StealthSecp256k1Example is Script {
    using StealthSecp256k1 for SecretKey;
    using StealthSecp256k1 for StealthAddress;
    using StealthSecp256k1 for StealthMetaAddress;

    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    function run() public {
        // Sender key pair.
        SecretKey senderSk = Secp256k1.newSecretKey();
        PublicKey memory senderPk = senderSk.toPublicKey();
        logSender("Created key pair");

        // Receiver key pairs consist of spending and viewing key pairs.
        SecretKey receiverSpendSk = Secp256k1.newSecretKey();
        PublicKey memory receiverSpendPk = receiverSpendSk.toPublicKey();
        SecretKey receiverViewSk = Secp256k1.newSecretKey();
        PublicKey memory receiverViewPk = receiverViewSk.toPublicKey();
        logReceiver("Created key pair");

        // There exists an ERC5564Announcer instance.
        IERC5564Announcer announcer = IERC5564Announcer(new ERC5564Announcer());

        // Receiver creates their stealth meta address.
        // TODO: Note that these addresses need to be published somehow.
        StealthMetaAddress memory receiverSma = StealthMetaAddress({
            spendPk: receiverSpendPk,
            viewPk: receiverViewPk
        });
        logReceiver(
            string.concat(
                "Created Ethereum stealth meta address: ", receiverSma.toString("eth")
            )
        );

        // Sender creates stealth address from receiver's stealth meta address.
        // TODO: receiver's stealh address must be argument for function, not 
        //       an object to call a function on.
        StealthAddress memory stealth = receiverSma.newStealthAddress();
        logSender("Created stealth address from receiver's stealth meta address");

        // Sender sends ETH to stealth.
        vm.deal(senderPk.toAddress(), 1 ether);
        vm.prank(senderPk.toAddress());
        (bool ok, ) = stealth.recipient.call{value: 1 ether}("");
        require(ok, "Sender: ETH transfer failed");
        logSender("Send 1 ETH to stealth address");

        // Sender announces tx via ERC5564Announcer.
        vm.prank(senderPk.toAddress());
        announcer.announce({
            schemeId: SCHEME_ID,
            stealthAddress: stealth.recipient,
            ephemeralPubKey: stealth.ephPk.toBytes(),
            // See ERC5564Announcer.sol for more info.
            metadata: abi.encodePacked(
                stealth.viewTag,
                hex"eeeeeeee",
                hex"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                uint(1 ether)
            )
        });
        logSender("Announced tx via ERC-5564 announcer");

        // Receiver checks announces stealth address.
        require(
            receiverViewSk.checkStealthAddress(receiverSpendPk, stealth),
            "Check failed"
        );
        logReceiver("Verfied tx is based on own stealth meta address");

        // Receiver computed stealth's private key.
        console.log("Receiver: Computes private key for stealth address");
        SecretKey stealthSk = receiverSpendSk
            .computeStealthSecretKey(receiverViewSk, stealth);

        // Verify computed private key's address matches stealth's recipient
        // address.
        console.log("Receiver: Verifies access on stealth address");
        require(
            stealthSk.toPublicKey().toAddress() == stealth.recipient,
            "Private key computation failed"
        );
    }

    function logSender(string memory message) internal {
        console.log(
            string.concat(StdStyle.yellow("[SENDER]   "), message)
        );
    }

    function logReceiver(string memory message) internal {
        console.log(
            string.concat(StdStyle.blue("[RECEIVER] "), message)
        );
    }
}
