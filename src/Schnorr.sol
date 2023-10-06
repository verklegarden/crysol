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

import {Secp256k1, PrivateKey, PublicKey} from "./Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    AffinePoint,
    JacobianPoint
} from "./Secp256k1Arithmetic.sol";

/**
 * @notice Signature is a Schnorr signature.
 */
struct Signature {
    bytes32 sig;
    address commitment;
}

/**
 * @title Schnorr
 *
 * @notice Schnorr signature functionality for secp256k1
 *
 * @dev ...
 */
library Schnorr {
    using Schnorr for address;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    using Secp256k1 for PublicKey;
    using Secp256k1 for AffinePoint;
    using Secp256k1Arithmetic for AffinePoint;
    using Secp256k1Arithmetic for JacobianPoint;

    Vm private constant vm =
        Vm(address(uint160(uint(keccak256("hevm cheat code")))));

    //--------------------------------------------------------------------------
    // Signature Verification
    //
    // @todo Note that malleable signatures are deemed invalid.

    function verify(
        PublicKey memory pubKey,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        if (!pubKey.isValid()) revert("PublicKeyInvalid()");

        bytes32 digest = keccak256(message);

        return pubKey.toAddress().verify(digest, sig);
    }

    function verify(
        PublicKey[] memory pubKeys,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        if (pubKeys.length == 0) revert("NoPublicKeys()");

        bytes32 digest = keccak256(message);

        // Aggregate pubKeys.
        JacobianPoint memory jac = pubKeys[0].toJacobianPoint();
        for (uint i = 1; i < pubKeys.length; i++) {
            jac.intoAddAffinePoint(pubKeys[i].intoAffinePoint());
        }
        PublicKey memory aggPubKey = jac.intoAffinePoint().intoPublicKey();

        return aggPubKey.toAddress().verify(digest, sig);
    }

    function verify(address signer, bytes memory message, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        bytes32 digest = keccak256(message);

        return signer.verify(digest, sig);
    }

    function verify(address signer, bytes32 digest, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        if (signer == address(0)) revert("SignerIsZeroAddress()");

        // Fail if signature is malleable to enforce signature uniqueness.
        if (sig.isMalleable()) revert("SignatureIsMalleable()");

        // @todo xD
        return false;
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether signature `self` is malleable.
    ///
    /// @dev A signature is malleable if @todo
    function isMalleable(Signature memory self) internal pure returns (bool) {
        return true;
    }

    /// @dev Returns a string representation of signature `self`.
    function toString(Signature memory self)
        internal
        pure
        returns (string memory)
    {
        // forgefmt: disable-start
        string memory str = string.concat(
            "Schnorr::Signature { \n",
            "    signature : ", vm.toString(self.sig), ",\n",
            "    commitment: ", vm.toString(self.commitment), ",\n",
            "  }"
        );
        // forgefmt: disable-end
        return str;
    }
}
