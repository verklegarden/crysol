/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

// TODO: During dev:
import {console2 as console} from "forge-std/console2.sol";

import {Vm} from "forge-std/Vm.sol";

import {Secp256k1, SecretKey, PublicKey} from "../curves/Secp256k1.sol";
import {Secp256k1Arithmetic, Point} from "../curves/Secp256k1Arithmetic.sol";

uint constant SCHEME_ID = 1;

/// @custom:field spendPk The spending public key
/// @custom:field viewPk The viewing public key
struct StealthMetaAddress {
    PublicKey spendPk;
    PublicKey viewPk;
}

/// @custom:field recipient
/// @custom:field ephPk The ephemeral public key
/// @custom:field viewTag
struct StealthAddress {
    address recipient;
    PublicKey ephPk;
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
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;
    using Secp256k1Arithmetic for Point;

    // ~~~~~~~ Prelude ~~~~~~~
    // forgefmt: disable-start
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));
    modifier vmed() {
        if (block.chainid != 31337) revert("requireVm");
        _;
    }
    // forgefmt: disable-end
    // ~~~~~~~~~~~~~~~~~~~~~~~

    // Stealth Meta Addresses

    // TODO: See https://eips.ethereum.org/EIPS/eip-5564#stealth-meta-address-format.
    //
    //       st:eth:0x<spendingKey><viewingKey>

    /// @dev Returns the string representation of stealth meta address `sma` for
    ///      chain `chain`.
    ///
    /// @dev Note that `chain` should be the chain's short name as defined via
    ///      https://github.com/ethereum-lists/chains.
    ///
    /// @dev A stealth meta address' string representation is defined as:
    ///         `st:<chain>:0x<spendingKey><viewingKey>`
    ///
    /// @custom:vm vm.toString(bytes)
    function toString(StealthMetaAddress memory sma, string memory chain)
        internal
        vmed
        returns (string memory)
    {
        string memory prefix = string.concat("st:", chain, ":0x");

        bytes memory spendingKey;
        bytes memory viewingKey;

        string memory key;
        key = vm.toString(abi.encodePacked(sma.spendPk.x, sma.spendPk.y));
        spendingKey = new bytes(bytes(key).length - 2);
        for (uint i = 2; i < bytes(key).length; i++) {
            spendingKey[i - 2] = bytes(key)[i];
        }

        key = vm.toString(abi.encodePacked(sma.viewPk.x, sma.viewPk.y));
        viewingKey = new bytes(bytes(key).length - 2);
        for (uint i = 2; i < bytes(key).length; i++) {
            viewingKey[i - 2] = bytes(key)[i];
        }

        return string.concat(prefix, string(spendingKey), string(viewingKey));
    }

    /// @dev Returns stealth meta address `stealthMetaAddress` for chain `chain`
    ///      as bytes.
    ///
    /// @dev Note that `chain` should be the chain's short name as defined via
    ///      https://github.com/ethereum-lists/chains.
    ///
    /// @dev Provides following encoding:
    ///         `st:<chain>:0x<spendingKey><viewingKey>`
    function toBytes(StealthMetaAddress memory sma, string memory chain)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(bytes("st:"), bytes(chain), bytes(":0x"));

        bytes memory prefix = bytes(string.concat("st:", chain, ":0x"));

        bytes memory keys =
            bytes.concat(sma.spendPk.toBytes(), sma.viewPk.toBytes());

        return bytes.concat(prefix, keys);
        //bytes.concat(bytes("st:"), bytes(chain));
        //bytes memory prefix =
        //    abi.encodePacked(bytes("st:"), bytes(chain), bytes(":0x"));

        //bytes memory pubKeys = abi.encodePacked(
        //    stealthMetaAddress.spendingPubKey.toBytes(),
        //    stealthMetaAddress.viewingPubKey.toBytes()
        //);

        //return abi.encodePacked(prefix, pubKeys);
    }

    // Stealth Address

    // TODO: See https://eips.ethereum.org/EIPS/eip-5564#generation---generate-stealth-address-from-stealth-meta-address.
    function newStealthAddress(StealthMetaAddress memory sma)
        internal
        returns (StealthAddress memory)
    {
        // Create ephemeral key pair.
        SecretKey ephSk = Secp256k1.newSecretKey();
        PublicKey memory ephPk = ephSk.toPublicKey();

        console.log("[internal] newStealthAddress: Ephemeral key pair created");

        // Compute shared secret.
        // forgefmt: disable-next-item
        PublicKey memory sharedPk = sma.viewPk.intoPoint()
                                              .mul(ephSk.asUint())
                                              .intoPublicKey();

        console.log(
            "[internal] newStealthAddress: Shared secret based public key computed"
        );

        // TODO: EIP not exact: sharedSecret must be bounded to field.
        // TODO: If sharedSecret is zero, loop with new ephemeral key!
        //       Currently reverts.
        SecretKey sharedSecretSk =
            Secp256k1.secretKeyFromUint(uint(sharedPk.toHash()) % Secp256k1.Q);

        // Extract view tag from shared secret.
        uint8 viewTag = uint8(sharedSecretSk.asUint() >> 152);

        // Compute public key from shared secret secret key.
        PublicKey memory sharedSecretPk = sharedSecretSk.toPublicKey();

        // Compute recipients public key.
        // forgefmt: disable-next-item
        PublicKey memory recipientPk = sma.spendPk
                                          .intoPoint()
                                          .add(sharedSecretPk.intoPoint())
                                          .intoPublicKey();

        // Derive recipients address from their public key.
        address recipientAddr = recipientPk.toAddress();

        return StealthAddress(recipientAddr, ephPk, viewTag);
    }

    /// @custom:invariant Shared secret private key is not zero.
    ///     ∀ (viewSk, ephPk) ∊ (SecretKey, PublicKey):
    ///         ([viewSk]ephPk).toHash() != 0 (mod Q)
    function checkStealthAddress(
        SecretKey viewSk,
        PublicKey memory spendPk,
        StealthAddress memory sa
    ) internal returns (bool) {
        // Compute shared public key.
        // forgefmt: disable-next-item
        PublicKey memory sharedPk = sa.ephPk
                                      .intoPoint()
                                      .mul(viewSk.asUint())
                                      .intoPublicKey();

        // TODO: EIP not exact: sharedSecret must be bound to field.
        SecretKey sharedSecretSk =
            Secp256k1.secretKeyFromUint(uint(sharedPk.toHash()) % Secp256k1.Q);

        // Extract view tag from shared secret.
        uint8 viewTag = uint8(sharedSecretSk.asUint() >> 152);

        // Return early if view tags do not match.
        if (viewTag != sa.viewTag) {
            return false;
        }

        // Compute public key from shared secret secret key.
        PublicKey memory sharedSecretPk = sharedSecretSk.toPublicKey();

        // Compute recipients public key.
        // forgefmt: disable-next-item
        PublicKey memory recipientPk = spendPk.intoPoint()
                                              .add(sharedSecretPk.intoPoint())
                                              .intoPublicKey();

        // Derive recipients address from their public key.
        address recipientAddr = recipientPk.toAddress();

        // Return true if stealth address' address matches computed recipients
        // address.
        return recipientAddr == sa.recipient;
    }

    // Private Key

    function computeStealthSecretKey(
        SecretKey spendSk,
        SecretKey viewSk,
        StealthAddress memory sa
    ) internal returns (SecretKey) {
        // Compute shared secret public key.
        // forgefmt: disable-next-item
        PublicKey memory sharedPk = sa.ephPk.intoPoint()
                                            .mul(viewSk.asUint())
                                            .intoPublicKey();

        // TODO: EIP not exact: sharedSecret must be bounded to field.
        // TODO: If sharedSecret is zero, loop with new ephemeral key!
        //       Currently reverts.
        SecretKey sharedSecretSk =
            Secp256k1.secretKeyFromUint(uint(sharedPk.toHash()) % Secp256k1.Q);

        // Compute stealth private key.
        SecretKey stealthSk = Secp256k1.secretKeyFromUint(
            addmod(spendSk.asUint(), sharedSecretSk.asUint(), Secp256k1.Q)
        );

        return stealthSk;
    }
}
