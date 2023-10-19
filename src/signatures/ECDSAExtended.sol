/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {ECDSA, Signature} from "./ECDSA.sol";

import {Secp256k1, PrivateKey, PublicKey} from "../curves/Secp256k1.sol";
import {Secp256k1Arithmetic} from "../curves/Secp256k1Arithmetic.sol";

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
        if (self.isMalleable()) {
            return self;
        }

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
        if (!self.isMalleable()) {
            return self;
        }

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

    // @todo Implement and check whether correct.
    // @todo Everything (mod P)
    // See
    //      https://web.archive.org/web/20160308014317/http://www.nilsschneider.net/2013/01/28/recovering-bitcoin-private-keys.html
    //      https://web.archive.org/web/20150627235425/https://events.ccc.de/congress/2010/Fahrplan/attachments/1780_27c3_console_hacking_2010.pdf
    /// @dev Tries to recover the private key from public key `pubKey` which
    ///      signs via signatures `sigs` digests `digests`.
    ///
    /// @dev Note that the private key is recoverable iff at least two
    ///      signatures used the same nonce `k` during signing.
    ///
    ///      A private key is recoverable from a pair of signatures using
    ///      the same nonce `k` via:
    ///
    ///      Let sig1 be:                   Let sig2 be:
    ///        P_k = [k]G                     P_k = [k]G
    ///        r   = (P_k)_x                  r   = (P_k)_x
    ///        s_1 = (e_1 + (r * x)) / k      s_2 = (e_1 + (r * x)) / k
    ///
    ///                     (e_1 + r * x) - (e_2 + r * x)   (e_1 - e_2)
    ///      => s_1 - s_2 = ----------------------------- = -----------
    ///                                   k                      k
    ///
    ///             e_1 - e_2
    ///      => k = ---------
    ///             s_1 - s_2
    ///
    ///               (e_1 + r * x)
    ///      => s_1 = -------------
    ///                    k
    ///
    ///      => s_1 * k         = e_1 + r * x
    ///      => (s_1 * k) - e_1 = r * x
    ///
    ///             (s_1 * k) - e_1
    ///      => x = ---------------
    ///                    k
    function tryRecoverPrivateKey(
        PublicKey memory pubKey,
        Signature[] memory sigs,
        bytes32[] memory digests
    ) internal pure returns (bool, PrivateKey) {
        // Search for first signatures with same r-value.
        bool found = false;
        uint index1;
        uint index2;
        for (uint i; i < sigs.length && !found; i++) {
            for (uint j = i + 1; j < sigs.length; j++) {
                if (sigs[i].r == sigs[j].r) {
                    found = true;
                    index1 = i;
                    index2 = j;
                    break;
                }
            }
        }

        // Fail if no signatures with same r-value found.
        if (!found) {
            return (false, PrivateKey.wrap(0));
        }

        // @todo Recover private key.
        uint k = 0;
        return (false, PrivateKey.wrap(0));
    }
}
