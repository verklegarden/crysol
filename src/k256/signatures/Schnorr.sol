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

import {Message} from "../../common/Message.sol";
import {Nonce} from "../../common/Nonce.sol";

import {K256, SecretKey, PublicKey} from "../K256.sol";

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
 * @notice Provides Schnorr signature functionality
 *
 * @dev Provides a Schnorr signature implementation in combination with the
 *      secp256k1 elliptic curve and keccak256 hash function.
 *
 * @custom:docs docs/signatures/Schnorr.md
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 * @author Inspired by Chronicle Protocol's Scribe (https://github.com/chronicleprotocol/scribe)
 */
library Schnorr {
    using K256 for SecretKey;
    using K256 for PublicKey;

    using Nonce for SecretKey;

    using Schnorr for address;
    using Schnorr for Signature;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;

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

    /// @dev Returns whether public key `pk` signs via Schnorr signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature malleable
    ///      ∨ Schnorr signature trivial
    function verify(
        PublicKey memory pk,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        bytes32 digest = keccak256(message);

        return pk.verify(digest, sig);
    }

    /// @dev Returns whether public key `pk` signs via Schnorr signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature trivial
    ///      ∨ Schnorr signature malleable
    function verify(PublicKey memory pk, bytes32 digest, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        if (sig.signature == 0 || sig.commitment == address(0)) {
            revert("SignatureTrivial()");
        }

        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        // Construct challenge = H(Pkₓ ‖ Pkₚ ‖ m ‖ Rₑ) (mod Q)
        uint challenge = uint(
            keccak256(
                abi.encodePacked(
                    pk.x, uint8(pk.yParity()), digest, sig.commitment
                )
            )
        ) % K256.Q;

        // Compute ecrecover_msgHash = -sig * Pkₓ      (mod Q)
        //                           = Q - (sig * Pkₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_msgHash;
        unchecked {
            ecrecover_msgHash =
                bytes32(K256.Q - mulmod(uint(sig.signature), pk.x, K256.Q));
        }

        // Compute ecrecover_v = Pkₚ + 27
        //
        // Unchecked because pk.yParity() ∊ {0, 1} which cannot overflow by
        // adding 27.
        uint8 ecrecover_v;
        unchecked {
            ecrecover_v = uint8(pk.yParity() + 27);
        }

        // Set ecrecover_r = Pkₓ
        bytes32 ecrecover_r = bytes32(pk.x);

        // Compute ecrecover_s = Q - (e * Pkₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_s;
        unchecked {
            ecrecover_s = bytes32(K256.Q - mulmod(challenge, pk.x, K256.Q));
        }

        // Compute ([sig]G - [e]Pk)ₑ via ecrecover.
        // forgefmt: disable-next-item
        address recovered = ecrecover(
            ecrecover_msgHash,
            ecrecover_v,
            ecrecover_r,
            ecrecover_s
        );

        // Verification succeeds iff ([sig]G - [e]Pk)ₑ = Rₑ.
        //
        // Note that commitment is guaranteed to not be zero.
        return sig.commitment == recovered;
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    /// @dev Returns a Schnorr signature signed by secret key `sk` signing
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm sign(SecretKey, bytes32)
    function sign(SecretKey sk, bytes memory message)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest = keccak256(message);

        return sk.sign(digest);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` signing
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm curves/Secp256k1::toPublicKey(SecretKey)(PublicKey)
    function sign(SecretKey sk, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        // Note that public key derivation fails if secret key is invalid.
        PublicKey memory pk = sk.toPublicKey();

        // Derive deterministic nonce ∊ [1, Q).
        uint nonce = Nonce.deriveNonceFrom(sk.asUint(), digest) % K256.Q;
        assert(nonce != 0); // TODO: Revisit once nonce derived via RFC 6979.

        // Compute nonce's public key.
        PublicKey memory noncePk = K256.secretKeyFromUint(nonce).toPublicKey();

        // Derive commitment from nonce's public key.
        address commitment = noncePk.toAddress();

        // Construct challenge = H(Pkₓ ‖ Pkₚ ‖ m ‖ Rₑ) (mod Q)
        bytes32 challenge = bytes32(
            uint(
                keccak256(
                    abi.encodePacked(
                        pk.x, uint8(pk.yParity()), digest, commitment
                    )
                )
            ) % K256.Q
        );

        // Compute signature = k + (e * sk) (mod Q)
        bytes32 signature = bytes32(
            addmod(nonce, mulmod(uint(challenge), sk.asUint(), K256.Q), K256.Q)
        );

        return Signature(signature, commitment);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` singing
    ///      message `message`'s keccak256 digest as Ethereum Signed Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm sign(SecretKey, bytes32)
    function signEthereumSignedMessageHash(SecretKey sk, bytes memory message)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest = Message.deriveEthereumSignedMessageHash(message);

        return sk.sign(digest);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` singing
    ///      hash digest `digest` as Ethereum Signed Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm sign(SecretKey, bytes32)
    function signEthereumSignedMessageHash(SecretKey sk, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest2 = Message.deriveEthereumSignedMessageHash(digest);

        return sk.sign(digest2);
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether signature `sig` is malleable.
    ///
    /// @dev Note that Schnorr signatures are non-malleable if constructed
    ///      correctly. A signature is only malleable if `sig.signature` is not
    ///      an secp256k1 field element.
    function isMalleable(Signature memory sig) internal pure returns (bool) {
        return uint(sig.signature) >= K256.Q;
    }

    /// @dev Returns a string representation of signature `sig`.
    ///
    /// @custom:vm vm.toString(uint)
    function toString(Signature memory sig)
        internal
        view
        vmed
        returns (string memory)
    {
        // forgefmt: disable-start
        string memory str = "Schnorr::Signature({";
        str = string.concat(str, " signature: ", vm.toString(sig.signature), ",");
        str = string.concat(str, " commitment: ", vm.toString(sig.commitment));
        str = string.concat(str, " })");
        return str;
        // forgefmt: disable-end
    }

    //--------------------------------------------------------------------------
    // (De)Serialization
    //
    // TODO: Schnorr Serde defined via BIP-340.
}
