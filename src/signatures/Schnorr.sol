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

import {Message} from "../Message.sol";

import {Secp256k1, PrivateKey, PublicKey} from "../curves/Secp256k1.sol";

/**
 * @notice Signature is a Schnorr signature
 */
struct Signature {
    bytes32 signature;
    address commitment;
}

/**
 * @title Schnorr
 *
 * @notice Library providing common Schnorr functionality
 *
 * @dev ...
 */
library Schnorr {
    using Schnorr for address;
    using Schnorr for Signature;
    using Schnorr for PrivateKey;
    using Schnorr for PublicKey;
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

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
    // Signature Verification

    function verify(
        PublicKey memory pubKey,
        bytes32 digest,
        Signature memory sig
    ) internal pure returns (bool) {
        if (!pubKey.isValid()) {
            revert("PublicKeyInvalid()");
        }

        if (sig.isMalleable()) {
            revert("SignatureIsMalleable()");
        }

        // Revert if signature is trivial
        if (sig.signature == 0 || sig.commitment == address(0)) {
            revert("TrivialSignature()");
        }

        // Construct challenge = H(Pₓ ‖ Pₚ ‖ m ‖ Rₑ) mod Q
        uint challenge = uint(
            keccak256(
                abi.encodePacked(
                    pubKey.x, uint8(pubKey.yParity()), digest, sig.commitment
                )
            )
        ) % Secp256k1.Q;

        // Compute msgHash = -sig * Pₓ      (mod Q)
        //                 = Q - (sig * Pₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        uint msgHash;
        unchecked {
            msgHash =
                Secp256k1.Q - mulmod(uint(sig.signature), pubKey.x, Secp256k1.Q);
        }

        // Compute v = Pₚ + 27
        //
        // Unchecked because pubKey.yParity() ∊ {0, 1} which cannot overflow
        // by adding 27.
        uint v;
        unchecked {
            v = pubKey.yParity() + 27;
        }

        // Set r = Pₓ
        uint r = pubKey.x;

        // Compute s = Q - (e * Pₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        uint s;
        unchecked {
            s = Secp256k1.Q - mulmod(challenge, pubKey.x, Secp256k1.Q);
        }

        // Compute ([s]G - [e]P)ₑ via ecrecover.
        address recovered =
            ecrecover(bytes32(msgHash), uint8(v), bytes32(r), bytes32(s));

        // Verification succeeds iff ([s]G - [e]P)ₑ = Rₑ.
        //
        // Note that commitment is guaranteed to not be zero.
        return sig.commitment == recovered;
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    function sign(PrivateKey privKey, bytes memory message)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest = keccak256(message);

        return privKey.sign(digest);
    }

    function sign(PrivateKey privKey, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        PublicKey memory pubKey = privKey.toPublicKey();

        PrivateKey nonce = Secp256k1.newPrivateKey();
        PublicKey memory noncePubKey = nonce.toPublicKey();

        address commitment = noncePubKey.toAddress();

        bytes32 challenge = bytes32(
            uint(
                keccak256(
                    abi.encodePacked(
                        pubKey.x, uint8(pubKey.yParity()), digest, commitment
                    )
                )
            ) % Secp256k1.Q
        );

        bytes32 signature = bytes32(
            addmod(
                nonce.asUint(),
                mulmod(uint(challenge), privKey.asUint(), Secp256k1.Q),
                Secp256k1.Q
            )
        );

        return Signature(signature, commitment);
    }

    //--------------------------------------------------------------------------
    // Utils

    function isMalleable(Signature memory sig) internal pure returns (bool) {
        return uint(sig.signature) >= Secp256k1.Q;
    }
}
