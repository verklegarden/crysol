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

import {K256} from "../K256.sol";
import {K256Arithmetic} from "../K256Arithmetic.sol";

/**
 * @title ECDSAUnsafe
 *
 * @notice Library providing unsafe ECDSA functionality
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
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

        // Flip sig.s to K256.Q - sig.s.
        sig.s = bytes32(K256.Q - uint(sig.s));

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

        // Flip sig.s to K256.Q - sig.s.
        sig.s = bytes32(K256.Q - uint(sig.s));

        // Flip v.
        sig.v = sig.v == 27 ? 28 : 27;

        return sig;
    }
}
