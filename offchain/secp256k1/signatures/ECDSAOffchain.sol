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

import {Message} from "src/common/Message.sol";

import {
    Secp256k1Offchain
} from "../Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/secp256k1/Secp256k1.sol";

import {
    ECDSA,
    Signature
} from "src/secp256k1/signatures/ECDSA.sol";

/**
 * @title ECDSAOffchain
 *
 * @notice Provides offchain ECDSA signature functionality
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library ECDSAOffchain {
    using Secp256k1 for SecretKey;

    using ECDSAOffchain for SecretKey;

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
    // Signature Creation

    /// @dev Returns an ECDSA signature signed by secret key `sk` signing
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm vm.sign(uint,bytes32)
    /// @custom:invariant Created signature is non-malleable.
    function sign(SecretKey sk, bytes memory message)
        internal
        view
        vmed
        returns (Signature memory)
    {
        bytes32 digest = keccak256(message);

        return sk.sign(digest);
    }

    /// @dev Returns an ECDSA signature signed by secret key `sk` signing hash
    ///      digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm vm.sign(uint,bytes32)
    /// @custom:invariant Created signature is non-malleable.
    function sign(SecretKey sk, bytes32 digest)
        internal
        view
        vmed
        returns (Signature memory)
    {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(sk.asUint(), digest);

        Signature memory sig = Signature(v, r, s);
        // assert(!sig.isMalleable());

        return sig;
    }

    /// @dev Returns an ECDSA signature signed by secret key `sk` singing
    ///      message `message`'s keccak256 digest as Ethereum Signed Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm vm.sign(uint,bytes32)
    /// @custom:invariant Created signature is non-malleable.
    function signEthereumSignedMessageHash(SecretKey sk, bytes memory message)
        internal
        view
        vmed
        returns (Signature memory)
    {
        bytes32 digest = Message.deriveEthereumSignedMessageHash(message);

        return sk.sign(digest);
    }

    /// @dev Returns an ECDSA signature signed by secret key `sk` singing hash
    ///      digest `digest` as Ethereum Signed Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm vm.sign(uint,bytes32)
    /// @custom:invariant Created signature is non-malleable.
    function signEthereumSignedMessageHash(SecretKey sk, bytes32 digest)
        internal
        view
        vmed
        returns (Signature memory)
    {
        bytes32 digest2 = Message.deriveEthereumSignedMessageHash(digest);

        return sk.sign(digest2);
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns a string representation of signature `sig`.
    ///
    /// @custom:vm vm.toString(uint)
    function toString(Signature memory sig)
        internal
        view
        vmed
        returns (string memory)
    {
        string memory str = "ECDSA::Signature({";
        str = string.concat(str, " v: ", vm.toString(sig.v), ",");
        str = string.concat(str, " r: ", vm.toString(sig.r), ",");
        str = string.concat(str, " s: ", vm.toString(sig.s));
        str = string.concat(str, " })");
        return str;
    }
}

