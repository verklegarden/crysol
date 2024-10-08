/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Secp256k1, SecretKey, PublicKey} from "../Secp256k1.sol";
import {FieldArithmetic, Felt} from "../arithmetic/FieldArithmetic.sol";

/**
 * @notice Signature is an [ERC-XXX] Schnorr signature
 */
struct Signature {
    bytes32 s;
    PublicKey r;
}

/**
 * @notice SignatureCompressed is an [ERC-XXX] compressed Schnorr signature
 */
struct SignatureCompressed {
    bytes32 s;
    address rAddr;
}

/**
 * @title Schnorr
 *
 * @notice Provides [ERC-XXX] compatible Schnorr signature functionality
 *
 * @custom:references
 *      - [ERC-XXX]: ...
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Schnorr {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using FieldArithmetic for Felt;

    using Schnorr for address;
    using Schnorr for Signature;
    using Schnorr for SignatureCompressed;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;

    //--------------------------------------------------------------------------
    // Private Constants

    uint private constant _ADDRESS_MASK =
        0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    //--------------------------------------------------------------------------
    // ERC-XXX Constants

    /// @dev The context string containing the scheme and ciphersuite.
    ///
    /// @dev The context string is used to domain separate hash functions and
    ///      ensures a Schnorr signed message is never deemed valid in a
    ///      different context.
    string internal constant CONTEXT = "ETHEREUM-SCHNORR-SECP256K1-KECCAK256";

    //--------------------------------------------------------------------------
    // Signature Verification

    /// @dev Returns whether public key `pk` signs via Schnorr signature `sig`
    ///      message `m`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Signature insane
    function verify(PublicKey memory pk, bytes32 m, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        // Note that checking whether signature's r value is a valid public key
        // is waived. Exploiting this behaviour would require knowledge of a
        // preimage non-equal to pk for the signer's Ethereum address.
        SignatureCompressed memory sigCompressed = sig.toCompressed();

        return pk.verify(m, sigCompressed);
    }

    /// @dev Returns whether public key `pk` signs via compressed Schnorr
    ///      signature `sig` message `m`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Signature insane
    function verify(
        PublicKey memory pk,
        bytes32 m,
        SignatureCompressed memory sig
    ) internal pure returns (bool) {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        // Construct challenge = H₂(Pkₓ ‖ Pkₚ ‖ m ‖ Rₑ) (mod Q)
        uint challenge = uint(
            keccak256(
                abi.encodePacked(
                    CONTEXT,
                    "challenge",
                    pk.x,
                    uint8(pk.yParity()),
                    m,
                    sig.rAddr
                )
            )
        ) % Secp256k1.Q;

        // Compute ecrecover_msgHash = -s * Pkₓ      (mod Q)
        //                           = Q - (s * Pkₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_msgHash;
        unchecked {
            ecrecover_msgHash = bytes32(
                Secp256k1.Q - mulmod(uint(sig.s), pk.x.asUint(), Secp256k1.Q)
            );
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
        bytes32 ecrecover_r = bytes32(pk.x.asUint());

        // Compute ecrecover_s = Q - (e * Pkₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_s;
        unchecked {
            ecrecover_s = bytes32(
                Secp256k1.Q - mulmod(challenge, pk.x.asUint(), Secp256k1.Q)
            );
        }

        // Compute ([s]G - [e]Pk)ₑ via ecrecover.
        // forgefmt: disable-next-item
        address recovered = ecrecover(
            ecrecover_msgHash,
            ecrecover_v,
            ecrecover_r,
            ecrecover_s
        );

        // Verification succeeds iff ([s]G - [e]Pk)ₑ = Rₑ.
        return recovered == sig.rAddr;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns an [ERC-XXX] compatible Schnorr message hash from digest
    ///      `digest`.
    function constructMessageHash(bytes32 digest)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(CONTEXT, "message", digest));
    }

    /// @dev Returns whether Schnorr signature `sig` is sane.
    ///
    /// @dev A Schnorr signature is deemed insane for any of:
    ///      - Schnorr signature's s value is zero
    ///      - Schnorr signature's s value not in [1, Q)
    ///      - Schnorr signature's r value is not a valid public key
    function isSane(Signature memory sig) internal pure returns (bool) {
        if (sig.s == 0 || uint(sig.s) >= Secp256k1.Q || !sig.r.isValid()) {
            return false;
        }

        return true;
    }

    /// @dev Returns whether compressed Schnorr signature `sig` is sane.
    ///
    /// @dev A compressed Schnorr signature is deemed insane for any of:
    ///      - Schnorr signature's s value is zero
    ///      - Schnorr signature's s value not in [1, Q)
    ///      - Schnorr signature's rAddr value is zero
    function isSane(SignatureCompressed memory sig)
        internal
        pure
        returns (bool)
    {
        // forgefmt: disable-next-item
        if (
            sig.s == 0                 ||
            uint(sig.s) >= Secp256k1.Q ||
            sig.rAddr == address(0)
           )
        {
            return false;
        }

        return true;
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    /// @dev Mutates signature `sig` to a compressed signature.
    function intoCompressed(Signature memory sig)
        internal
        pure
        returns (SignatureCompressed memory)
    {
        SignatureCompressed memory sigCompressed;

        address rAddr = sig.r.toAddress();
        // assert(rAddr != address(0));

        assembly ("memory-safe") {
            // Store r's address in r's x coordinate slot.
            // Note to clean dirty upper bits and r's y coordinate slot.
            mstore(add(sig, 0x20), and(rAddr, _ADDRESS_MASK))
            mstore(add(sig, 0x40), 0x00)

            sigCompressed := sig
        }

        return sigCompressed;
    }

    /// @dev Returns a compressed signature from signature `sig`.
    function toCompressed(Signature memory sig)
        internal
        pure
        returns (SignatureCompressed memory)
    {
        address rAddr = sig.r.toAddress();
        // assert(rAddr != address(0));

        return SignatureCompressed(sig.s, rAddr);
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    /// @dev Decodes signature from [ERC-XXX] encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 96 bytes
    ///      ∨ Deserialized Schnorr signature insane
    ///
    /// @dev Expects 96 bytes encoding:
    ///         [32 bytes s value][64 bytes r public key]
    function signatureFromEncoded(bytes memory blob)
        internal
        pure
        returns (Signature memory)
    {
        if (blob.length != 96) {
            revert("LengthInvalid()");
        }

        bytes32 s;
        uint rx;
        uint ry;
        assembly ("memory-safe") {
            s := mload(add(blob, 0x20))
            rx := mload(add(blob, 0x40))
            ry := mload(add(blob, 0x60))
        }

        bool ok;
        Felt rx_;
        Felt ry_;
        (rx_, ok) = FieldArithmetic.tryFeltFromUint(rx);
        if (!ok) {
            revert("SignatureInsane()");
        }
        (ry_, ok) = FieldArithmetic.tryFeltFromUint(ry);
        if (!ok) {
            revert("SignatureInsane()");
        }

        Signature memory sig = Signature(s, PublicKey(rx_, ry_));

        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        return sig;
    }

    /// @dev Encodes Schnorr signature `sig` as [ERC-XXX] encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Schnorr signature insane
    ///
    /// @dev Provides 96 bytes encoding:
    ///         [32 bytes s value][64 bytes r public key]
    function toEncoded(Signature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        return abi.encodePacked(sig.s, sig.r.x, sig.r.y);
    }

    /// @dev Encodes Schnorr signature `sig` as [ERC-XXX] compressed encoded
    ///      bytes.
    ///
    /// @dev Reverts if:
    ///        Schnorr signature insane
    ///
    /// @dev Provides 52 bytes encoding:
    ///         [32 bytes s value][20 bytes r's address]
    ///
    ///      See [ERC-XXX].
    function toCompressedEncoded(Signature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        return sig.toCompressed().toCompressedEncoded();
    }

    /// @dev Decodes compressed Schnorr signature from [ERC-XXX] compressed
    ///      encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Deserialized Schnorr signature insane
    ///
    /// @dev Provides 52 bytes encoding:
    ///         [32 bytes s value][20 bytes r's address]
    ///
    ///      See [ERC-XXX].
    function signatureFromCompressedEncoded(bytes memory blob)
        internal
        pure
        returns (SignatureCompressed memory)
    {
        if (blob.length != 52) {
            revert("LengthInvalid()");
        }

        bytes32 s;
        address rAddr;
        assembly ("memory-safe") {
            s := mload(add(blob, 0x20))
            rAddr := shr(96, mload(add(blob, 0x40)))
        }

        SignatureCompressed memory sig = SignatureCompressed(s, rAddr);

        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        return sig;
    }

    /// @dev Encodes compact Schnorr signature `sig` as [ERC-XXX] compact
    ///      encoded bytes.
    ///
    /// @dev Reverts if:
    ///         Schnorr signature insane
    ///
    /// @dev Provides 52 bytes encoding:
    ///         [32 bytes s value][20 bytes r's address]
    ///
    ///      See [ERC-XXX].
    function toCompressedEncoded(SignatureCompressed memory sig)
        internal
        pure
        returns (bytes memory)
    {
        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        return abi.encodePacked(sig.s, sig.rAddr);
    }
}
