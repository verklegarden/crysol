/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

import {Random} from "../common/Random.sol";

import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/secp256k1/Secp256k1.sol";

import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "src/secp256k1/Secp256k1Arithmetic.sol";

/**
 * @title Secp256k1Offchain
 *
 * @notice Providing common cryptography-related functionality for the secp256k1
 *         elliptic curve
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library Secp256k1Offchain {
    using Secp256k1Offchain for SecretKey;

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

    //--------------------------------------------------------------------------
    // Secret Key

    /// @dev Returns a new cryptographically secure secret key.
    ///
    /// @custom:vm Random::readUint()(uint)
    function newSecretKey() internal vmed returns (SecretKey) {
        uint scalar;
        while (scalar == 0 || scalar >= Secp256k1Arithmetic.Q) {
            // Note to not introduce potential bias via bounding operation.
            scalar = Random.readUint();
        }
        return Secp256k1.secretKeyFromUint(scalar);
    }

    /// @dev Returns the public key of secret key `sk`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm vm.createWallet(uint)
    function toPublicKey(SecretKey sk)
        internal
        vmed
        returns (PublicKey memory)
    {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        // Use vm to compute pk = [sk]G.
        Vm.Wallet memory wallet = vm.createWallet(sk.asUint());
        return PublicKey(wallet.publicKeyX, wallet.publicKeyY);
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Returns a string representation of public key `pk`.
    ///
    /// @custom:vm vm.toString(uint)
    function toString(PublicKey memory pk)
        internal
        view
        vmed
        returns (string memory)
    {
        string memory str = "Secp256k1::PublicKey({";
        str = string.concat(str, " x: ", vm.toString(pk.x), ",");
        str = string.concat(str, " y: ", vm.toString(pk.y));
        str = string.concat(str, " })");
        return str;
    }
}

