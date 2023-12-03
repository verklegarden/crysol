/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

import {Secp256k1, PrivateKey, PublicKey} from "../curves/Secp256k1.sol";
import {Secp256k1Arithmetic, Point} from "../curves/Secp256k1Arithmetic.sol";

uint constant SCHEME_ID = 1;

struct StealthMetaAddress {
    PublicKey spendingPubKey;
    PublicKey viewingPubKey;
}

struct StealthAddress {
    address recipient;
    PublicKey ephemeralPubKey;
    uint8 viewTag;
}

// TODO: Differentiate between EIPs and ERCs.

/**
 * @title StealthSecp256k1
 *
 * @notice Stealth Addresses for secp256k1 following [EIP-5564]
 *
 * @dev
 *
 * @custom:references
 *      - [EIP-5564]: https://eips.ethereum.org/EIPS/eip-5564
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library StealthSecp256k1 {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;
    using Secp256k1Arithmetic for Point;

    // Stealth Meta Addresses

    // TODO: See https://eips.ethereum.org/EIPS/eip-5564#stealth-meta-address-format.
    //
    //       st:eth:0x<spendingKey><viewingKey>
    function toBytes(
        StealthMetaAddress memory stealthMetaAddress,
        string memory chainShortName
    ) internal pure returns (bytes memory) {
        bytes memory prefix =
            abi.encodePacked(bytes("st:"), bytes(chainShortName), bytes(":0x"));

        bytes memory pubKeys = abi.encodePacked(
            stealthMetaAddress.spendingPubKey.toBytes(),
            stealthMetaAddress.viewingPubKey.toBytes()
        );

        return abi.encodePacked(prefix, pubKeys);
    }

    // Stealth Address

    // TODO: See https://eips.ethereum.org/EIPS/eip-5564#generation---generate-stealth-address-from-stealth-meta-address.
    function newStealthAddress(StealthMetaAddress memory sma)
        internal
        returns (StealthAddress memory)
    {
        // Create ephemeral key pair.
        PrivateKey ephemeralPrivKey = Secp256k1.newPrivateKey();
        PublicKey memory ephemeralPubKey = ephemeralPrivKey.toPublicKey();

        // Compute shared secret.
        // forgefmt: disable-next-item
        PublicKey memory sharedPubKey = sma.viewingPubKey
                                            .intoPoint()
                                            .mul(ephemeralPrivKey.asUint())
                                            .intoPublicKey();

        // TODO: EIP not exact: sharedSecret must be bounded to field.
        // TODO: If sharedSecret is zero, loop with new ephemeral key!
        //       Currently reverts.
        PrivateKey sharedSecretPrivKey = Secp256k1.privateKeyFromUint(
            uint(sharedPubKey.toHash()) % Secp256k1.Q
        );

        // Extract view tag from shared secret.
        uint8 viewTag = uint8(sharedSecretPrivKey.asUint() >> 152);

        // Compute public key from shared secret private key.
        PublicKey memory sharedSecretPubKey = sharedSecretPrivKey.toPublicKey();

        // Compute recipients public key.
        // forgefmt: disable-next-item
        PublicKey memory recipientPubKey = sma.spendingPubKey
                                                .intoPoint()
                                                .add(sharedSecretPubKey
                                                        .intoPoint())
                                                .intoPublicKey();

        // Derive recipients address from their public key.
        address recipientAddr = recipientPubKey.toAddress();

        return StealthAddress(recipientAddr, ephemeralPubKey, viewTag);
    }

    /// @custom:invariant Shared secret private key is not zero.
    ///     ∀ (viewPrivKey, ephPubKey) ∊ (PrivateKey, PublicKey):
    ///         ([viewPrivKey]ephPubKey).toHash() != 0 (mod Q)
    function checkStealthAddress(
        PrivateKey viewingPrivKey,
        PublicKey memory spendingPubKey,
        StealthAddress memory stealthAddress
    ) internal returns (bool) {
        // Compute shared secret.
        // forgefmt: disable-next-item
        PublicKey memory sharedPubKey = stealthAddress.ephemeralPubKey
                                            .intoPoint()
                                            .mul(viewingPrivKey.asUint())
                                            .intoPublicKey();

        // TODO: EIP not exact: sharedSecret must be bound to field.
        PrivateKey sharedSecretPrivKey = Secp256k1.privateKeyFromUint(
            uint(sharedPubKey.toHash()) % Secp256k1.Q
        );

        // Extract view tag from shared secret.
        uint8 viewTag = uint8(sharedSecretPrivKey.asUint() >> 152);

        // Return early if view tags do not match.
        if (viewTag != stealthAddress.viewTag) {
            return false;
        }

        // Compute public key from shared secret private key.
        PublicKey memory sharedSecretPubKey = sharedSecretPrivKey.toPublicKey();

        // Compute recipients public key.
        // forgefmt: disable-next-item
        PublicKey memory recipientPubKey = spendingPubKey
                                                .intoPoint()
                                                .add(sharedSecretPubKey
                                                        .intoPoint())
                                                .intoPublicKey();

        // Derive recipients address from their public key.
        address recipientAddr = recipientPubKey.toAddress();

        // Return true if stealth address' address matches computed recipients
        // address.
        return recipientAddr == stealthAddress.recipient;
    }

    // Private Key

    function computeStealthPrivateKey(
        PrivateKey spendingPrivKey,
        PrivateKey viewingPrivKey,
        StealthAddress memory stealthAddress
    ) internal returns (PrivateKey) {
        // Compute shared secret.
        // forgefmt: disable-next-item
        PublicKey memory sharedPubKey = stealthAddress.ephemeralPubKey
                                            .intoPoint()
                                            .mul(viewingPrivKey.asUint())
                                            .intoPublicKey();

        // TODO: EIP not exact: sharedSecret must be bounded to field.
        // TODO: If sharedSecret is zero, loop with new ephemeral key!
        //       Currently reverts.
        PrivateKey sharedSecretPrivKey = Secp256k1.privateKeyFromUint(
            uint(sharedPubKey.toHash()) % Secp256k1.Q
        );

        // Compute stealth private key.
        PrivateKey stealthPrivKey = Secp256k1.privateKeyFromUint(
            addmod(
                spendingPrivKey.asUint(),
                sharedSecretPrivKey.asUint(),
                Secp256k1.Q
            )
        );

        return stealthPrivKey;
    }
}
