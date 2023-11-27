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

import {Nonce} from "./utils/Nonce.sol";

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
    using Schnorr for address;
    using Schnorr for Signature;
    using Schnorr for PrivateKey;
    using Schnorr for PublicKey;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    using Nonce for PrivateKey;

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

    /// @dev Returns whether public key `pubKey` signs via Schnorr signature
    ///      `sig` hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///      - Public key invalid
    ///      - Schnorr signature malleable
    ///      - Schnorr signature trivial
    function verify(
        PublicKey memory pubKey,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        bytes32 digest = keccak256(message);

        return pubKey.verify(digest, sig);
    }

    /// @dev Returns whether public key `pubKey` signs via Schnorr signature
    ///      `sig` hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///      - Public key invalid
    ///      - Schnorr signature malleable
    ///      - Schnorr signature trivial
    function verify(
        PublicKey memory pubKey,
        bytes32 digest,
        Signature memory sig
    ) internal pure returns (bool) {
        if (!pubKey.isValid()) {
            revert("PublicKeyInvalid()");
        }

        if (sig.signature == 0 || sig.commitment == address(0)) {
            revert("SignatureTrivial()");
        }

        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        // Construct challenge = H(Pₓ ‖ Pₚ ‖ m ‖ Rₑ) (mod Q)
        uint challenge = uint(
            keccak256(
                abi.encodePacked(
                    pubKey.x, uint8(pubKey.yParity()), digest, sig.commitment
                )
            )
        ) % Secp256k1.Q;

        // Compute ecrecover_msgHash = -sig * Pₓ      (mod Q)
        //                           = Q - (sig * Pₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_msgHash;
        unchecked {
            ecrecover_msgHash = bytes32(
                Secp256k1.Q - mulmod(uint(sig.signature), pubKey.x, Secp256k1.Q)
            );
        }

        // Compute ecrecover_v = Pₚ + 27
        //
        // Unchecked because pubKey.yParity() ∊ {0, 1} which cannot overflow
        // by adding 27.
        uint8 ecrecover_v;
        unchecked {
            ecrecover_v = uint8(pubKey.yParity() + 27);
        }

        // Set ecrecover_r = Pₓ
        bytes32 ecrecover_r = bytes32(pubKey.x);

        // Compute ecrecover_s = Q - (e * Pₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_s;
        unchecked {
            ecrecover_s =
                bytes32(Secp256k1.Q - mulmod(challenge, pubKey.x, Secp256k1.Q));
        }

        // Compute ([sig]G - [e]P)ₑ via ecrecover.
        // forgefmt: disable-next-item
        address recovered = ecrecover(
            ecrecover_msgHash,
            ecrecover_v,
            ecrecover_r,
            ecrecover_s
        );

        // Verification succeeds iff ([sig]G - [e]P)ₑ = Rₑ.
        //
        // Note that commitment is guaranteed to not be zero.
        return sig.commitment == recovered;
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    /// @dev Returns a Schnorr signature signed by private key `privKey` signing
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm sign(PrivateKey, bytes32)
    function sign(PrivateKey privKey, bytes memory message)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest = keccak256(message);

        return privKey.sign(digest);
    }

    /// @dev Returns a Schnorr signature signed by private key `privKey` signing
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm curves/Secp256k1::toPublicKey(PrivateKey)(PublicKey)
    function sign(PrivateKey privKey, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        PublicKey memory pubKey = privKey.toPublicKey();

        // Derive deterministic nonce ∊ [1, Q).
        uint nonce = privKey.deriveNonce(digest) % Secp256k1.Q;
        // assert(nonce != 0); // TODO: Revisit once nonce derived via RFC 6979.

        // Compute nonce's public key.
        PublicKey memory noncePubKey =
            Secp256k1.privateKeyFromUint(nonce).toPublicKey();

        // Derive commitment from nonce's public key.
        address commitment = noncePubKey.toAddress();

        // Construct challenge = H(Pₓ ‖ Pₚ ‖ m ‖ Rₑ) (mod Q)
        bytes32 challenge = bytes32(
            uint(
                keccak256(
                    abi.encodePacked(
                        pubKey.x, uint8(pubKey.yParity()), digest, commitment
                    )
                )
            ) % Secp256k1.Q
        );

        // Compute signature = k + (e * x) (mod Q)
        bytes32 signature = bytes32(
            addmod(
                nonce,
                mulmod(uint(challenge), privKey.asUint(), Secp256k1.Q),
                Secp256k1.Q
            )
        );

        return Signature(signature, commitment);
    }

    /// @dev Returns a Schnorr signature signed by private key `privKey` singing
    ///      message `message`'s keccak256 digest as Ethereum Signed Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm sign(PrivateKey, bytes32)
    function signEthereumSignedMessageHash(
        PrivateKey privKey,
        bytes memory message
    ) internal vmed returns (Signature memory) {
        bytes32 digest = Message.deriveEthereumSignedMessageHash(message);

        return privKey.sign(digest);
    }

    /// @dev Returns a Schnorr signature signed by private key `privKey` singing
    ///      hash digest `digest` as Ethereum Signed Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm sign(PrivateKey, bytes32)
    function signEthereumSignedMessageHash(PrivateKey privKey, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest2 = Message.deriveEthereumSignedMessageHash(digest);

        return privKey.sign(digest2);
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether signature `sig` is malleable.
    ///
    /// @dev Note that Schnorr signatures are non-malleable if constructed
    ///      correctly. A signature is only malleable if `sig.signature` is not
    ///      an secp256k1 field element.
    function isMalleable(Signature memory sig) internal pure returns (bool) {
        return uint(sig.signature) >= Secp256k1.Q;
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
        string memory str = "Schnorr::Signature {\n";
        str = string.concat(str, "    signature: ", vm.toString(sig.signature), ",\n");
        str = string.concat(str, "    commitment: ", vm.toString(sig.commitment), "\n");
        str = string.concat(str, "  }");
        return str;
        // forgefmt: disable-end
    }

    //--------------------------------------------------------------------------
    // (De)Serialization
    //
    // TODO: Schnorr Serde
    //       Any other standard except BIP-340?
}
