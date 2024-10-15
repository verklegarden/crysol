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

import {Secp256k1Offchain} from "../Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

/**
 * @title ECDSAOffchain
 *
 * @notice Provides offchain ECDSA signature functionality
 *
 * @custom:references
 *      - [eth_sign]: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library ECDSAOffchain {
    using Secp256k1 for SecretKey;

    using ECDSAOffchain for SecretKey;

    // forgefmt: disable-next-item
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));

    //--------------------------------------------------------------------------
    // Signature Creation

    /// @dev Returns an ECDSA signature signed by secret key `sk` signing
    ///      hash digest `digest`.
    ///
    /// @dev Note that the actual message being signed is a domain separated
    ///      "Ethereum Signed Message" as specified via [eth_sign]. This ensures
    ///      a signed message is never deemed valid in a different context.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function sign(SecretKey sk, bytes32 digest)
        internal
        pure
        returns (Signature memory)
    {
        bytes32 m = ECDSA.constructMessageHash(digest);

        return sk.signRaw(m);
    }

    /// @dev Returns an ECDSA signature signed by secret key `sk` signing
    ///      message `m`.
    ///
    /// @dev Note that this is a low-level function and SHOULD NOT be used
    ///      directly! Instead, use `sign(SecretKey,bytes32)(Signature)` to
    ///      ensure the message is domain separated.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function signRaw(SecretKey sk, bytes32 m)
        internal
        pure
        returns (Signature memory)
    {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        // Note that foundry's vm uses RFC-6979 for nonce derivation, ie
        // signatures are deterministic.
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(sk.asUint(), m);

        Signature memory sig = Signature(v, r, s);
        // assert(!sig.isMalleable());

        return sig;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns a string representation of signature `sig`.
    function toString(Signature memory sig)
        internal
        pure
        returns (string memory)
    {
        string memory str = "ECDSA({";
        str = string.concat(str, " v: ", vm.toString(sig.v), ",");
        str = string.concat(str, " r: ", vm.toString(sig.r), ",");
        str = string.concat(str, " s: ", vm.toString(sig.s));
        str = string.concat(str, " })");
        return str;
    }
}
