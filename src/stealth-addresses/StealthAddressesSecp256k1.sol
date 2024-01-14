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

import {Secp256k1, SecretKey, PublicKey} from "../curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "../curves/Secp256k1Arithmetic.sol";

/**
 * @notice StealthMetaAddress encapsulates a receiver's spending and viewing
 *         public keys from which a [StealthAddress] can be computed
 *
 * @dev Stealth meta addresses offer TODO...
 *
 * @dev A stealth address' secret key is computed via the spending secret key.
 *      The viewing secret key is used to determine whether a tx belongs to its
 *      stealth meta address.
 *
 * @custom:example Generate a stealth meta address:
 *
 *      ```solidity
 *      import {Secp256k1, SecretKey, PublicKey} from "crysol/curves/Secp256k1.sol";
 *      import {StealthAdressesSecp256k1, StealthMetaAddress} from "crysol/stealth-addresses/StealthAdressesSecp256k1.sol";
 *      contract Example {
 *          using Secp256k1 for SecretKey;
 *
 *          // Create spending and viewing secret keys.
 *          SecretKey spendSk = Secp256k1.newSecretKey();
 *          SecretKey viewSk = Secp256k1.newSecretKey();
 *
 *          // Stealth meta address is the tuple of public keys.
 *          StealthMetaAddress memory sma = StealthMetaAddress({
 *              spendPk: spendSk.toPublicKey(),
 *              viewPk: viewSk.toPublicKey()
 *          });
 *      }
 *      ```
 */
struct StealthMetaAddress {
    PublicKey spendPk;
    PublicKey viewPk;
}

/**
 * @notice StealthAddress
 */
struct StealthAddress {
    address addr;
    PublicKey ephPk;
    uint8 viewTag;
}

/**
 * @title StealthAddressesSecp256k1
 *
 * @notice [ERC-5564] conforming stealth addresses for the secp256k1 curve
 *
 * @custom:references
 *      - [ERC-5564]: https://eips.ethereum.org/EIPS/eip-5564
 *      - [ERC-5564 Scheme Ids]: https://eips.ethereum.org/assets/eip-5564/scheme_ids
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library StealthAddressesSecp256k1 {
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

    //--------------------------------------------------------------------------
    // Constants

    /// @dev Identifies the stealth address scheme, see [ERC-5564 Scheme Ids].
    uint internal constant SCHEME_ID = 0;

    //--------------------------------------------------------------------------
    // Sender

    /// @dev Returns a randomly generated stealth address derived from stealth
    ///      meta address `stealthMeta`.
    ///
    /// @custom:vm Secp256k1::newSecretKey()
    function generateStealthAddress(StealthMetaAddress memory stealthMeta)
        internal
        vmed
        returns (StealthAddress memory)
    {
        // Create ephemeral secret key.
        SecretKey ephSk = Secp256k1.newSecretKey();

        return generateStealthAddressGivenEphKey(stealthMeta, ephSk);
    }

    /// @dev Returns a stealth address derived via ephemeral secret key `ephSk`
    ///      from stealth meta address `stealthMeta`.
    ///
    /// @dev Note that the ephemeral secret key MUST be kept private to not leak
    ///      the stealth address' owner!
    ///
    /// @dev Reverts if:
    ///        Ephemeral secret key invalid
    ///
    /// @custom:vm Secp256k1::SecretKey.toPublicKey()
    /// @custom:invariant A public key's keccak256 image is never zero:
    ///     ∀ pk ∊ PublicKey: keccak256(pk) != 0
    function generateStealthAddressGivenEphKey(
        StealthMetaAddress memory stealthMeta,
        SecretKey ephSk
    ) internal vmed returns (StealthAddress memory) {
        if (!ephSk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        PublicKey memory ephPk = ephSk.toPublicKey();

        // Compute shared secret key from ephemeral secret key and stealthMeta's
        // view public key.
        SecretKey sharedSk = _deriveSharedSecret(ephSk, stealthMeta.viewPk);

        // Extract view tag from shared secret key.
        uint8 viewTag = _extractViewTag(sharedSk);

        // Derive shared secret key's public key.
        PublicKey memory sharedPk = sharedSk.toPublicKey();

        // Compute stealth address' public key.
        // forgefmt: disable-next-item
        PublicKey memory stealthPk = stealthMeta.spendPk
                                                .toProjectivePoint()
                                                .add(sharedPk.toProjectivePoint())
                                                .intoPoint()
                                                .intoPublicKey();

        // Return stealth address.
        return StealthAddress({
            addr: stealthPk.toAddress(),
            ephPk: ephPk,
            viewTag: viewTag
        });
    }

    //--------------------------------------------------------------------------
    // Receiver

    /// @dev Returns whether stealth address `stealth` belongs to the view secret
    ///      key `viewSk` and spend public key `spendPk`.
    ///
    /// @dev Note that `stealth`'s view tag MUST be correct in order for the check
    ///      to succeed.
    ///
    /// @custom:vm Secp256k1::PublicKey.toPublicKey()
    /// @custom:invariant A public key's keccak256 image is never zero:
    ///     ∀ pk ∊ PublicKey: keccak256(pk) != 0
    function checkStealthAddress(
        SecretKey viewSk,
        PublicKey memory spendPk,
        StealthAddress memory stealth
    ) internal vmed returns (bool) {
        // Compute shared secret key from view secret key and ephemeral public
        // key.
        SecretKey sharedSk = _deriveSharedSecret(viewSk, stealth.ephPk);

        // Extract view tag from shared secret key.
        uint8 viewTag = _extractViewTag(sharedSk);

        // Return early if view tags do not match.
        if (viewTag != stealth.viewTag) {
            return false;
        }

        // Derive shared secret key's public key.
        PublicKey memory sharedPk = sharedSk.toPublicKey();

        // Compute stealth address' public key.
        // forgefmt: disable-next-item
        PublicKey memory stealthPk = spendPk.toProjectivePoint()
                                            .add(sharedPk.toProjectivePoint())
                                            .intoPoint()
                                            .intoPublicKey();

        // Return true if computed address matches stealth address' address.
        return stealthPk.toAddress() == stealth.addr;
    }

    /// @dev Computes the secret key for stealth address `stealth` from the
    ///      spend and view secret keys.
    ///
    /// @dev Note that the stealth address MUST belong to the spend and view
    ///      secret keys!
    ///
    /// @custom:invariant A public key's keccak256 image is never zero:
    ///     ∀ pk ∊ PublicKey: keccak256(pk) != 0
    function computeStealthSecretKey(
        SecretKey spendSk,
        SecretKey viewSk,
        StealthAddress memory stealth
    ) internal view returns (SecretKey) {
        // Compute shared secret key from view secret key and ephemeral public
        // key.
        SecretKey sharedSk = _deriveSharedSecret(viewSk, stealth.ephPk);

        // Compute stealth secret key.
        SecretKey stealthSk = Secp256k1.secretKeyFromUint(
            addmod(spendSk.asUint(), sharedSk.asUint(), Secp256k1.Q)
        );

        return stealthSk;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns the string representation of stealth meta address
    ///      `stealthMeta` for chain `chain`.
    ///
    /// @dev Note that `chain` should be the chain's short name as defined via
    ///      https://github.com/ethereum-lists/chains.
    ///
    /// @dev A stealth meta address' string representation is defined as:
    ///         `st:<chain>:0x<compressed spendPk><compressed  viewPk>`
    ///
    /// @custom:vm vm.toString(bytes)(string)
    function toString(StealthMetaAddress memory sma, string memory chain)
        internal
        view
        vmed
        returns (string memory)
    {
        string memory prefix = string.concat("st:", chain, ":0x");

        // Use hex string of 0x-removed compressed public key encoding.
        bytes memory spendPk;
        bytes memory viewPk;

        string memory buffer;

        buffer = vm.toString(sma.spendPk.intoPoint().toCompressedEncoded());
        spendPk = new bytes(bytes(buffer).length - 2);
        for (uint i = 2; i < bytes(buffer).length; i++) {
            spendPk[i - 2] = bytes(buffer)[i];
        }

        buffer = vm.toString(sma.viewPk.intoPoint().toCompressedEncoded());
        viewPk = new bytes(bytes(buffer).length - 2);
        for (uint i = 2; i < bytes(buffer).length; i++) {
            viewPk[i - 2] = bytes(buffer)[i];
        }

        return string.concat(prefix, string(spendPk), string(viewPk));
    }

    //--------------------------------------------------------------------------
    // Private Helpers

    /// @dev Returns a shared secret derived from secret key `sk` and public key
    ///      `pk`.
    ///
    /// @custom:invariant A public key's keccak256 image is never zero:
    ///     ∀ pk ∊ PublicKey: keccak256(pk) != 0
    function _deriveSharedSecret(SecretKey sk, PublicKey memory pk)
        private
        view
        returns (SecretKey)
    {
        // Compute shared public key.
        // forgefmt: disable-next-item
        PublicKey memory sharedPk = pk.toProjectivePoint()
                                      .mul(sk.asUint())
                                      .intoPoint()
                                      .intoPublicKey();

        // Derive secret key from hashed public key.
        bytes32 digest = sharedPk.toHash();

        // Note to bound digest to secp256k1's order in order to use it as
        // secret key.
        uint scalar = uint(digest) % Secp256k1.Q;
        assert(scalar != 0); // Has negligible probability.

        return Secp256k1.secretKeyFromUint(scalar);
    }

    /// @dev Returns the view tag of shared secret key `sharedSk`.
    ///
    /// @dev Note that the view tag is defined as the highest-order byte.
    function _extractViewTag(SecretKey sharedSk) private pure returns (uint8) {
        return uint8(sharedSk.asUint() >> 248);
    }
}
