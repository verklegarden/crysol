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

// TODO: Define ₓ, ₚ, and ₑ as functions. See ECDSA.
// TODO: Don't use signature and commitment as terms.
//       Stay in sync with ECDSA and use s and r. Note though that
//       r is here the address of the public key, not the x coordinate.
/**
 * @title Schnorr
 *
 * @notice Provides Schnorr signature functionality
 *
 * @dev Provides a Schnorr signature implementation in combination with the
 *      secp256k1 elliptic curve and keccak256 hash function.
 *
 * @dev Schnorr Signature Specification
 *
 *      Terminology
 *      ~~~~~~~~~~~
 *
 *      - H()       Keccak256 hash function
 *      - ‖         Concatenation operator defined via `abi.encodePacked()`
 *      - G         Generator of secp256k1
 *      - Q         Order of secp256k1
 *      - x         The signer's private key as type uint256
 *      - P         The signer's public key, ie [x]G, as type (uint256, uint256)
 *      - Pₓ        P's x coordinate as type uint256
 *      - Pₚ        Parity of P's y coordinate, ie 0 if even and 1 if odd, as type uint256
 *      - m         Keccak256 hash of message as type bytes32
 *      - k         Nonce as type uint256
 *
 *
 *      Signature Creation
 *      ~~~~~~~~~~~~~~~~~~
 *
 *      1. Select a cryptographically secure nonce
 *          k ∊ [1, Q)
 *
 *      2. Compute nonce's public key
 *          R = [k]G
 *
 *      3. Compute commitment being the Ethereum address of the nonce's public key
 *          Rₑ = ethereum_address_of(R)
 *
 *      4. Construct challenge
 *          e = H(Pₓ ‖ Pₚ ‖ m ‖ Rₑ)
 *
 *      5. Compute signature
 *          s = k + (e * x) (mod Q)
 *
 *      => Let tuple (s, Rₑ) be the Schnorr signature
 *
 *
 *      Signature Verification
 *      ~~~~~~~~~~~~~~~~~~~~~~
 *
 *      Input : (P, m, s, Rₑ)
 *      Output: True if signature verification succeeds, false otherwise
 *
 *      1. Construct challenge
 *          e = H(Pₓ ‖ Pₚ ‖ m ‖ Rₑ)
 *
 *      2. Compute commitment
 *            [s]G - [e]P               | s = k + (e * x)
 *          = [k + (e * x)]G - [e]P     | P = [x]G
 *          = [k + (e * x)]G - [e * x]G | Distributive Law
 *          = [k + (e * x) - (e * x)]G  | (e * x) - (e * x) = 0
 *          = [k]G                      | R = [k]G
 *          = R                         | Let ()ₑ be the Ethereum address of a Point
 *          → Rₑ
 *
 *      3. Verification succeeds iff ([s]G - [e]P)ₑ = Rₑ
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

        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        if (sig.signature == 0 || sig.commitment == address(0)) {
            revert("SignatureTrivial()");
        }

        // Construct challenge = H(Pₓ ‖ Pₚ ‖ m ‖ Rₑ) (mod Q)
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

    /// @dev Returns a Schnorr signature signed by private key `privKey` signing
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
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
    function sign(PrivateKey privKey, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        PublicKey memory pubKey = privKey.toPublicKey();

        // Select nonce and compute nonce's public key.
        PrivateKey nonce = Secp256k1.newPrivateKey();
        PublicKey memory noncePubKey = nonce.toPublicKey();

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
                nonce.asUint(),
                mulmod(uint(challenge), privKey.asUint(), Secp256k1.Q),
                Secp256k1.Q
            )
        );

        return Signature(signature, commitment);
    }

    // @todo Docs signEthereumSignedMessage
    function signEthereumSignedMessage(PrivateKey privKey, bytes memory message)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest = Message.deriveEthereumMessageHash(message);

        return privKey.sign(digest);
    }

    // @todo Docs signEthereumSignedMessageHash
    function signEthereumSignedMessageHash(PrivateKey privKey, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest2 = Message.deriveEthereumMessageHash(digest);

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
        str = string.concat(str, "    signature : ", vm.toString(sig.signature), ",\n");
        str = string.concat(str, "    commitment: ", vm.toString(sig.commitment), ",\n");
        str = string.concat(str, "  }");
        return str;
        // forgefmt: disable-end
    }
}
