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

library StealthSecp256k1 {
    // Stealth Meta Addresses

    // TODO: See https://eips.ethereum.org/EIPS/eip-5564#stealth-meta-address-format.
    function toBytes(StealthAddress memory stealthMetaAddress)
        internal
        pure
        returns (bytes memory)
    {
        return bytes("");
    }

    // Stealth Address

    // TODO: See https://eips.ethereum.org/EIPS/eip-5564#generation---generate-stealth-address-from-stealth-meta-address.
    function newStealthAddress(StealthMetaAddress memory sma)
        internal
        returns (StealthAddress memory)
    {
        // TODO: Functionality missing in Secp256k1(Arithmetic):
        //       - [scalar]PublicKey
        //       - PublicKey + PublicKey

        // Create ephemeral key pair.
        PrivateKey ephemeralPrivKey = Secp256k1.newPrivateKey();
        PublicKey memory ephemeralPubKey = ephemeralPrivKey.toPublicKey();

        // Compute shared secret.
        // forgefmt: disable-next-item
        PublicKey memory sharedPubKey = sma.viewingPubKey
                                            .intoAffinePoint()
                                            .mul(ephemeralPrivKey);

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
        PublicKey memory recipientPubKey =
            sma.spendingPubKey.add(sharedSecretPubKey);

        // Derive recipients address from their public key.
        address recipientAddr = recipientPubKey.toAddress();

        return StealthAddress(recipientAddr, ephemeralPubKey, viewTag);
    }

    /// @custom:invariant Shared secret private key is not zero.
    ///     ∀ (viewPrivKey, ephPubKey) ∊ (PrivateKey, PublicKey):
    ///         ([viewPrivKey]ephPubKey).toHash() != 0 (mod Q)
    function checkStealthAddress(
        PrivateKey viewingPrivKey,
        PublicKey spendingPubKey,
        StealthAddress memory stealthAddress
    ) internal returns (bool) {
        // Compute shared secret.
        PublicKey memory sharedPubKey =
            stealthAddress.ephemeralPubKey.mul(viewingPrivKey);
        // TODO: EIP not exact: sharedSecret must be bounded to field.
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
        PublicKey memory recipientPubKey =
            sma.spendingPubKey.add(sharedSecretPubKey);

        // Derive recipients address from their public key.
        address recipientAddr = recipientPubKey.toAddress();

        // Return true if stealth address' address matches computed recipients
        // address.
        return recipientAddr == stealthAddress.recipientAddr;
    }

    // Private Key

    function computeStealthPrivateKey(
        PrivateKey spendingPrivKey,
        PrivateKey viewingPrivKey,
        StealthAddress memory stealthAddress
    ) internal returns (PrivateKey) {
        // Compute shared secret.
        PublicKey memory sharedPubKey =
            stealthAddress.ephemeralPubKey.mul(viewingPrivKey);
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
