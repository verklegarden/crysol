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

import {CSPRNG} from "./CSPRNG.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";
import {
    PointArithmetic,
    Point,
    ProjectivePoint
} from "src/arithmetic/PointArithmetic.sol";
import {FieldArithmetic, Felt} from "src/arithmetic/FieldArithmetic.sol";

/**
 * @title Secp256k1Offchain
 *
 * @notice Providing offchain cryptography-related functionality for the secp256k1
 *         elliptic curve
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Secp256k1Offchain {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;
    using PointArithmetic for Point;
    using FieldArithmetic for Felt;

    // forgefmt: disable-next-item
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));

    //--------------------------------------------------------------------------
    // Secret Key

    /// @dev Returns a new cryptographically secure secret key.
    function newSecretKey() internal returns (SecretKey) {
        SecretKey sk;
        bool ok;
        while (!ok) {
            (sk, ok) = Secp256k1.trySecretKeyFromUint(CSPRNG.readUint());
        }

        return sk;
    }

    /// @dev Returns the public key of secret key `sk`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function toPublicKey(SecretKey sk)
        internal
        returns (PublicKey memory)
    {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        // Use vm to compute pk = [sk]G.
        Vm.Wallet memory wallet = vm.createWallet(sk.asUint());

        (PublicKey memory pk, bool ok) = Secp256k1.tryPublicKeyFromUints(wallet.publicKeyX, wallet.publicKeyY);
        assert(ok);

        return pk;
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Returns a string representation of public key `pk`.
    function toString(PublicKey memory pk)
        internal
        pure
        returns (string memory)
    {
        string memory str = "PublicKey({";
        str = string.concat(str, " x: ", vm.toString(pk.x.asUint()), ",");
        str = string.concat(str, " y: ", vm.toString(pk.y.asUint()));
        str = string.concat(str, " })");
        return str;
    }
}
