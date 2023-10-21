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
 * @title ECDSAUnsafe
 *
 * @notice Library providing unsafe ECDSA functionality
 *
 * @dev             .oO WARNING Oo.
 */
library ECDSAUnsafe {
    using ECDSA for Signature;
    using ECDSAUnsafe for PrivateKey;

    using Secp256k1 for PrivateKey;

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
}
