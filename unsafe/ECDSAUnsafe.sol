/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {
    ECDSA, Signature
} from "../../../onchain/secp256k1/signatures/ECDSA.sol";

import {Secp256k1} from "../../../onchain/secp256k1/Secp256k1.sol";
import {Secp256k1Arithmetic} from
    "../../../onchain/secp256k1/Secp256k1Arithmetic.sol";

/**
 * @title ECDSAUnsafe
 *
 * @notice Library providing unsafe ECDSA functionality
 *
 * @dev WARNING
 *
 *      This library MUST only be used for testing, experimenting and
 *      researching.
 *
 *      Under no circumstances should unsafe/ code be used in production!
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library ECDSAUnsafe {
    using ECDSA for Signature;

    /// @dev Mutates signature `sig` to be malleable.
    function intoMalleable(Signature memory sig)
        internal
        pure
        returns (Signature memory)
    {
        if (sig.isMalleable()) {
            return sig;
        }

        // Flip sig.s to Secp256k1.Q - sig.s.
        sig.s = bytes32(Secp256k1.Q - uint(sig.s));

        // Flip v.
        sig.v = sig.v == 27 ? 28 : 27;

        return sig;
    }

    /// @dev Mutates signature `sig` to be non-malleable.
    function intoNonMalleable(Signature memory sig)
        internal
        pure
        returns (Signature memory)
    {
        if (!sig.isMalleable()) {
            return sig;
        }

        // Flip sig.s to Secp256k1.Q - sig.s.
        sig.s = bytes32(Secp256k1.Q - uint(sig.s));

        // Flip v.
        sig.v = sig.v == 27 ? 28 : 27;

        return sig;
    }
}
