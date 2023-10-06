/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Secp256k1, PrivateKey, PublicKey} from "./Secp256k1.sol";
import {Secp256k1Arithmetic} from "./Secp256k1Arithmetic.sol";
import {ECDSA, Signature} from "./ECDSA.sol";

/**
 * @title ECDSAExtended
 *
 * @notice Library providing extended ECDSA functionality
 *
 * @dev
 */
library ECDSAExtended {
    using Secp256k1 for PrivateKey;
    using ECDSA for Signature;
    using ECDSAExtended for PrivateKey;

    /// @dev Mutates signature `self` to be malleable.
    function intoMalleable(Signature memory self)
        internal
        pure
        returns (Signature memory)
    {
        if (self.isMalleable()) return self;

        // Flip self.s to Secp256k1.Q - self.s.
        self.s = bytes32(Secp256k1.Q - uint(self.s));

        // Flip v.
        self.v = self.v == 27 ? 28 : 27;

        return self;
    }

    /// @dev Mutates signature `self` to be non-malleable.
    function intoNonMalleable(Signature memory self)
        internal
        pure
        returns (Signature memory)
    {
        if (!self.isMalleable()) return self;

        // Flip self.s to Secp256k1.Q - self.s.
        self.s = bytes32(Secp256k1.Q - uint(self.s));

        // Flip v.
        self.v = self.v == 27 ? 28 : 27;

        return self;
    }

    // @todo Figure out, and implement, how foundry derives nonce.

    /// @dev Recovers the nonce `k` used during the creation of signature `sig`
    ///      signing message `message`.
    ///
    /// @dev Nonce `k` is recoverable via:
    ///         k = sig.s⁻¹ * (H(message) + (privKey * sig.r)) (mod P)
    ///
    ///      Note that sig.s⁻¹ is the modular inverse of sig.s.
    function recoverNonce(
        PrivateKey privKey,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (PrivateKey) {
        bytes32 digest = keccak256(message);

        return privKey.recoverNonce(digest, sig);
    }

    /// @dev Recovers the nonce `k` used during the creation of signature `sig`
    ///      signing keccak256 digest `digest`.
    ///
    /// @dev Nonce `k` is recoverable via:
    ///         k = sig.s⁻¹ * (digest + (privKey * sig.r)) (mod P)
    ///
    ///      Note that `sig.s`⁻¹ is the modular inverse of `sig.s`.
    function recoverNonce(
        PrivateKey privKey,
        bytes32 digest,
        Signature memory sig
    ) internal pure returns (PrivateKey) {
        uint sInv = Secp256k1Arithmetic.modularInverseOf(uint(sig.s));
        uint P = Secp256k1Arithmetic.P;

        uint k = mulmod(
            sInv,
            addmod(uint(digest), mulmod(privKey.asUint(), uint(sig.r), P), P),
            P
        );

        return Secp256k1.privateKeyFromUint(k);
    }

    /*
    // If two sigs (with different messages) use same nonce, the `r` value is
    // equal.
    function tryRecoverPrivateKey(
        Signature[] memory sigs,
        bytes32[] memory digests,
        PublicKey memory pubKey
    ) internal pure returns (bool, PrivateKey) {
        // Search for signatures with same r value.
        for (uint i; i < sigs.length; i++) {
            for (uint j = i + 1; j < sigs.length; j++) {
                if (sigs[i].r == sigs[j].r) {
                    //console.log("Found same r value");
                }
            }
        }

        return (false, PrivateKey.wrap(0));
    }
    */
}
