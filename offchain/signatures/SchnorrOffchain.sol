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

import {RandomOffchain} from "../RandomOffchain.sol";

import {Secp256k1Offchain} from "../Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";

import {
    Schnorr,
    Signature,
    SignatureCompressed
} from "src/signatures/Schnorr.sol";

/**
 * @title SchnorrOffchain
 *
 * @notice Provides offchain Schnorr signature functionality
 *
 * @dev
 *
 * @custom:references
 *      - [ERC-XXX]: ...
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library SchnorrOffchain {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1Offchain for PublicKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using SchnorrOffchain for SecretKey;

    // forgefmt: disable-next-item
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));

    //--------------------------------------------------------------------------
    // Signature Creation

    /// @dev Returns an [ERC-XXX] compatible Schnorr signature signed by secret
    ///      key `sk` signing hash digest `digest`.
    ///
    /// @dev Note that the actual message being signed is the domain separated
    ///      hash digest of `digest` as specified in [ERC-XXX]. This ensures a
    ///      signed message is never deemed valid in a different context.
    function sign(SecretKey sk, bytes32 digest)
        internal
        returns (Signature memory)
    {
        bytes32 m = Schnorr.constructMessageHash(digest);

        return sk.signRaw(m);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` signing
    ///      message `m`.
    ///
    /// @dev Note that this is a low-level function and SHOULD NOT be used
    ///      directly! Instead, use `sign(SecretKey,bytes32)(Signature)` to
    ///      ensure the produced signature is [ERC-XXX] compatible and the
    ///      message domain separated.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function signRaw(SecretKey sk, bytes32 m)
        internal
        returns (Signature memory)
    {
        // Source 32 bytes of secure randomness.
        bytes32 rand = bytes32(RandomOffchain.readUint());

        return sk.signRaw(m, rand);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` signing
    ///      message `m` using auxiliary random data `rand`.
    ///
    /// @dev Note that this is a low-level function and SHOULD NOT be used
    ///      directly! Instead, use `sign(SecretKey,bytes32)(Signature)` to
    ///      ensure the produced signature is [ERC-XXX] compatible and the
    ///      message domain separated.
    ///
    /// @dev The auxiliary random data SHOULD be fresh randomness and MUST NOT
    ///      be used more than once.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function signRaw(SecretKey sk, bytes32 m, bytes32 rand)
        internal
        returns (Signature memory)
    {
        // Note that public key derivation fails if secret key is invalid.
        PublicKey memory pk = sk.toPublicKey();
        // assert(sk.isValid());

        // Derive nonce = H₃(rand ‖ sk) (mod Q)
        uint nonce = uint(
            keccak256(
                abi.encodePacked(Schnorr.CONTEXT, "nonce", rand, sk.asUint())
            )
        ) % Secp256k1.Q;

        // Compute nonce's public key R.
        PublicKey memory r = Secp256k1.secretKeyFromUint(nonce).toPublicKey();

        // Construct challenge = H₂(Pkₓ ‖ Pkₚ ‖ m ‖ Rₑ) (mod Q)
        uint challenge = uint(
            keccak256(
                abi.encodePacked(
                    Schnorr.CONTEXT,
                    "challenge",
                    pk.x,
                    uint8(pk.yParity()),
                    m,
                    r.toAddress()
                )
            )
        ) % Secp256k1.Q;

        // Compute s = k + (e * sk) (mod Q).
        bytes32 s = bytes32(
            addmod(
                nonce,
                mulmod(uint(challenge), sk.asUint(), Secp256k1.Q),
                Secp256k1.Q
            )
        );

        return Signature(s, r);
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns a string representation of signature `sig`.
    function toString(Signature memory sig)
        internal
        pure
        returns (string memory)
    {
        string memory str = "Schnorr({";
        str = string.concat(str, " s: ", vm.toString(sig.s), ",");
        str = string.concat(str, " r: ", sig.r.toString());
        str = string.concat(str, " })");
        return str;
    }

    /// @dev Returns a string representation of compressed signature `sig`.
    ///
    /// @custom:vm vm.toString(uint)(string)
    /// @custom:vm vm.toString(address)(string)
    function toString(SignatureCompressed memory sig)
        internal
        pure
        returns (string memory)
    {
        string memory str = "SchnorrCompressed({";
        str = string.concat(str, " s: ", vm.toString(sig.s), ",");
        str = string.concat(str, " rAddr: ", vm.toString(sig.rAddr));
        str = string.concat(str, " })");
        return str;
    }
}
