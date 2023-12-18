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
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "../curves/Secp256k1Arithmetic.sol";

uint constant SCHEME_ID = 1;

/// @notice
///
/// @custom:field spendPk The spending public key
/// @custom:field viewPk The viewing public key

/**
 * @notice StealthMetaAddress encapsulates a receiver's spending and viewing
 *         public keys from which a [StealthAddress] can be computed.
 *
 * @dev Stealth meta addresses offer TODO...
 *
 * @dev Secret keys for stealth addresses derived from a stealth meta address
 *      can be computed via the spending secret key. The viewing secret key
 *      can be used to determine whether a tx belongs to the stealth meta
 *      address.
 *
 * @custom:example Generate a stealth meta address:
 *
 *      ```solidity
 *      import {Secp256k1, SecretKey, PublicKey} from "crysol/curves/Secp256k1.sol";
 *      import {StealthSecp256k1, StealthMetaAddress} from "crysol/stealth-addresses/StealthSecp256k1.sol";
 *      contract Example {
 *          using Secp256k1 for SecretKey;
 *
 *          // Create spending and viewing secret keys.
 *          SecretKey spendSk = Secp256k1.newSecretKey();
 *          SecretKey viewSk = Secp256k1.newSecretKey();
 *
 *          // Stealth meta address is their set of public keys.
 *          StealthMetaAddress memory sma = StealthMetaAddress({
 *              spendPk: spendSk.toPublicKey(),
 *              viewPk: viewSk.toPublicKey()
 *          })
 *      }
 *      ```
 */
struct StealthMetaAddress {
    PublicKey spendPk;
    PublicKey viewPk;
}

/**
 * @notice StealthAddress
 *
 *
 * @custom:example Generate a stealth meta address:
 *
 *      ```solidity
 *      import {Secp256k1, SecretKey, PublicKey} from "crysol/curves/Secp256k1.sol";
 *      import {StealthSecp256k1, StealthMetaAddress} from "crysol/stealth-addresses/StealthSecp256k1.sol";
 *      contract Example {
 *          using Secp256k1 for SecretKey;
 *
 *          // Create spending and viewing secret keys.
 *          SecretKey spendSk = Secp256k1.newSecretKey();
 *          SecretKey viewSk = Secp256k1.newSecretKey();
 *
 *          // Stealth meta address is their set of public keys.
 *          StealthMetaAddress memory sma = StealthMetaAddress({
 *              spendPk: spendSk.toPublicKey(),
 *              viewPk: viewSk.toPublicKey()
 *          })
 *      }
 *      ```
 */
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
    using Secp256k1Arithmetic for ProjectivePoint;

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
    ///         `st:<chain>:0x<spendPk><viewPk>`
    ///
    /// @custom:vm vm.toString(bytes)
    function toString(StealthMetaAddress memory sma, string memory chain)
        internal
        vmed
        returns (string memory)
    {
        string memory prefix = string.concat("st:", chain, ":0x");

        bytes memory spendPkBytes;
        bytes memory viewPkBytes;

        string memory buffer;

        // Note to remove "0x" prefix.
        buffer = vm.toString(sma.spendPk.toBytes());
        spendPkBytes = new bytes(bytes(buffer).length - 2);
        for (uint i = 2; i < bytes(buffer).length; i++) {
            spendPkBytes[i - 2] = bytes(buffer)[i];
        }

        // Note to remove "0x" prefix.
        buffer = vm.toString(sma.viewPk.toBytes());
        viewPkBytes = new bytes(bytes(buffer).length - 2);
        for (uint i = 2; i < bytes(buffer).length; i++) {
            viewPkBytes[i - 2] = bytes(buffer)[i];
        }

        return string.concat(prefix, string(spendPkBytes), string(viewPkBytes));
    }

    // Stealth Address

    // TODO: See https://eips.ethereum.org/EIPS/eip-5564#generation---generate-stealth-address-from-stealth-meta-address.
    // TODO: Rename to derive?
    function newStealthAddress(StealthMetaAddress memory sma)
        internal
        returns (StealthAddress memory)
    {
        // Create ephemeral key pair.
        SecretKey ephSk = Secp256k1.newSecretKey();
        PublicKey memory ephPk = ephSk.toPublicKey();

        console.log("[INTERNAL] newStealthAddress: Created ephemeral key pair");

        // TODO: Move sharedPk stuff into own function?
        //       Otherwise naming overload.

        // Compute shared secret = [ephSk]viewPk.
        // forgefmt: disable-next-item
        PublicKey memory sharedPk = sma.viewPk.intoPoint()
                                              .mul(ephSk.asUint())
                                              .intoPublicKey();

        console.log(
            "[INTERNAL] newStealthAddress: Computed shared secret's public key"
        );

        // TODO: EIP not exact: sharedSecret must be bounded to field.
        // TODO: If sharedSecret is zero, loop with new ephemeral key!
        //       Currently reverts.
        //       => Should be negligible propability though.
        SecretKey sharedSecretSk =
            Secp256k1.secretKeyFromUint(uint(sharedPk.toHash()) % Secp256k1.Q);

        // Extract view tag from shared secret.
        uint8 viewTag = uint8(sharedSecretSk.asUint() >> 152);

        // Compute public key from shared secret secret key.
        PublicKey memory sharedSecretPk = sharedSecretSk.toPublicKey();

        // Compute recipients public key.
        // forgefmt: disable-next-item
        PublicKey memory recipientPk = sma.spendPk
                                          .toProjectivePoint()
                                          .add(sharedSecretPk.toProjectivePoint())
                                          .intoPoint()
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
