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
 * @notice Signature is an ECDSA signature
 */
struct Signature {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

// TODO: Specification not complete nor correct!!!!
//       Everything still WIP!
/**
 * @title ECDSA
 *
 * @notice Provides ECDSA signature functionality
 *
 * @dev Provides an Elliptic Curve Digital Signature Algorithm (ECDSA)
 *      implementation as defined in [SEC 1 v2] in combination with the
 *      secp256k1 elliptic curve and keccak256 hash function.
 *
 * @dev Note about ECDSA Malleability
 *
 *      Note that ECDSA signatures are malleable, meaning every valid ECDSA
 *      signature has two distinct representations. Furthermore, computing the
 *      second valid signature can be done without knowledge of the signer's
 *      private key. This weakness has lead to numerous bugs in smart contract
 *      systems.
 *
 *      Therefore, this library only creates and accepts signatures in one of
 *      these representations. Signatures in the second representation are deemed
 *      invalid. For more info, see function `isMalleable(Signature)(bool)`.
 *
 *      This behaviour is sync with the broader Ethereum ecosystem as a general
 *      defensive mechanism against ECDSA's weakness.
 *      For more info, see eg [EIP-2].
 *
 *
 * @dev ECDSA Signature Specification
 *
 *      Terminology
 *      ~~~~~~~~~~~
 *
 *      - H()       Keccak256 hash function
 *      - G         Generator of secp256k1
 *      - Q         Order of secp256k1
 *      - x         The signer's private key as type uint256
 *      - m         Keccak256 hash of message as type bytes32
 *      - k         Nonce as type uint256
 *      - R         The nonce's public key, ie [k]G, as type (uint256, uint256)
 *      - ()ₓ       Function returning a public key's x coordinate as type uint256
 *      - ()ₚ       Function returning a public key's y coordinate's parity, ie 0 if even and 1 if odd, as type uint256
 *      - ()ₑ       Function returning a public key's Ethereum address as type address
 *
 *
 *      Signature Creation
 *      ~~~~~~~~~~~~~~~~~~
 *
 *      1. Select cryptographically secure nonce
 *          k ∊ [1, Q)
 *
 *      2. Compute nonce's public key
 *          R = [k]G
 *
 *      3. Compute r
 *          r = Rₓ (mod Q)
 *
 *      4. If r = 0
 *          Return to step 1
 *
 *      5. Compute s
 *          s = k⁻¹ * (m + (x * Rₓ)) (mod Q)
 *
 *      6. If s = 0
 *          Return to step 1
 *
 *      7. If s > Q/2
 *          s = Q - s
 *
 *      8. Compute s's public key
 *          S = [s]G
 *
 *      9. Compute v
 *          v = 27 + Sₚ
 *
 *      => Let triplet (r, s, v) be the ECDSA signature
 *
 *
 *      Signature Verification
 *      ~~~~~~~~~~~~~~~~~~~~~~
 *
 *      Input : (Pₑ, m, r, s, v)
 *      Output: True if signature verification succeeds, false otherwise
 *
 *      1. If not r ∊ [1, Q)
 *          Return false
 *
 *      2. If not s ∊ [1, Q/2]
 *          Return false
 *
 *      3. Compute u₁ and u₂
 *          u₁ = m * s⁻¹ (mod Q)
 *          u₂ = r * s⁻¹ (mod Q)
 *
 *      4. Compute public key R
 *          R = [u₁]G + [u₂]P           TODO: Error. Where does P come from?
 *
 *      5. If R is point at infinity
 *          Return false
 *
 *      6. Verification succeeds iff Rₓ == r (mod Q)
 *
 *
 * @custom:references
 *      - [SEC 1 v2]: https://www.secg.org/sec1-v2.pdf
 *      - [EIP-2]: https://eips.ethereum.org/EIPS/eip-2
 *      - [EIP-2098]: https://eips.ethereum.org/EIPS/eip-2098
 */
library ECDSA {
    using ECDSA for address;
    using ECDSA for Signature;
    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    // @todo Docs about prelude.
    // ~~~~~~~ Prelude ~~~~~~~
    // forgefmt: disable-start
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));
    modifier vmed() {
        if (block.chainid != 31337) revert("requireVm");
        _;
    }
    // forgefmt: disable-end
    // ~~~~~~~~~~~~~~~~~~~~~~~

    /// @dev Mask to receive an ECDSA's s value from an EIP-2098 compact
    ///      signature representation.
    ///
    ///      Equals `(1 << 255) - 1`.
    bytes32 private constant _EIP2098_MASK =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    //--------------------------------------------------------------------------
    // Signature Verification
    //
    // Note that malleable signatures are deemed invalid.

    /// @dev Returns whether public key `pubKey` signs via ECDSA signature
    ///      `sig` message `message`.
    ///
    /// @dev Reverts if:
    ///      - Public key invalid
    ///      - Signature malleable
    ///
    /// @custom:invariant No valid public key's address is zero.
    ///     ∀ pubKey ∊ PublicKey: pubKey.isValid() → pubKey.toAddress() != address(0)
    function verify(
        PublicKey memory pubKey,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        if (!pubKey.isValid()) {
            revert("PublicKeyInvalid()");
        }

        bytes32 digest = keccak256(message);

        return pubKey.toAddress().verify(digest, sig);
    }

    /// @dev Returns whether public key `pubKey` signs via ECDSA signature
    ///      `sig` hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///      - Public key invalid
    ///      - Signature malleable
    ///
    /// @custom:invariant No valid public key's address is zero.
    ///     ∀ pubKey ∊ PublicKey: pubKey.isValid() → pubKey.toAddress() != address(0)
    function verify(
        PublicKey memory pubKey,
        bytes32 digest,
        Signature memory sig
    ) internal pure returns (bool) {
        if (!pubKey.isValid()) {
            revert("PublicKeyInvalid()");
        }

        return pubKey.toAddress().verify(digest, sig);
    }

    /// @dev Returns whether address `signer` signs via ECDSA signature `sig`
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///      - Signer zero address
    ///      - Signature malleable
    function verify(address signer, bytes memory message, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        bytes32 digest = keccak256(message);

        return signer.verify(digest, sig);
    }

    /// @dev Returns whether address `signer` signs via ECDSA signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///      - Signer zero address
    ///      - Signature malleable
    function verify(address signer, bytes32 digest, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        if (signer == address(0)) {
            revert("SignerZeroAddress()");
        }

        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        // Note that checking whether v ∊ {27, 28} is waived.
        // For more info, see https://github.com/ethereum/yellowpaper/pull/860.

        return signer == ecrecover(digest, sig.v, sig.r, sig.s);
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    /// @dev Returns an ECDSA signature signed by private key `privKey` signing
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm vm.sign(uint,bytes32)
    /// @custom:invariant Returned signature is non-malleable.
    function sign(PrivateKey privKey, bytes memory message)
        internal
        view
        vmed
        returns (Signature memory)
    {
        bytes32 digest = keccak256(message);

        return privKey.sign(digest);
    }

    /// @dev Returns an ECDSA signature signed by private key `privKey` signing
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm vm.sign(uint,bytes32)
    /// @custom:invariant Returned signature is non-malleable.
    function sign(PrivateKey privKey, bytes32 digest)
        internal
        view
        vmed
        returns (Signature memory)
    {
        if (!privKey.isValid()) {
            revert("PrivateKeyInvalid()");
        }

        // @todo Should revert if digest is zero?

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        Signature memory sig = Signature(v, r, s);
        // assert(!sig.isMalleable());

        return sig;
    }

    // @todo Docs signEthereumSignedMessage
    /// @custom:invariant Returned signature is non-malleable.
    function signEthereumSignedMessage(PrivateKey privKey, bytes memory message)
        internal
        view
        vmed
        returns (Signature memory)
    {
        bytes32 digest = Message.deriveEthereumMessageHash(message);

        return privKey.sign(digest);
    }

    // @todo Docs signEthereumSignedMessageHash
    /// @custom:invariant Returned signature is non-malleable.
    function signEthereumSignedMessageHash(PrivateKey privKey, bytes32 digest)
        internal
        view
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
    /// @dev A signature is malleable if `sig.s > Secp256k1.Q / 2`.
    function isMalleable(Signature memory sig) internal pure returns (bool) {
        return sig.s
            > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
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
        string memory str = "ECDSA::Signature { \n";
        str = string.concat(str, "    v: ", vm.toString(sig.v), ",\n");
        str = string.concat(str, "    r: ", vm.toString(sig.r), ",\n");
        str = string.concat(str, "    s: ", vm.toString(sig.s), "\n");
        str = string.concat(str, "  }");
        return str;
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    /// @dev Returns signature `sig` as bytes.
    ///
    /// @dev Provides following encoding:
    ///         [256-bit r value][256-bit s value][8-bit v value]
    function toBytes(Signature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory blob;

        // @todo Use direct access in assembly.
        uint8 v = sig.v; // @todo Does this use one word or a single byte?
        bytes32 r = sig.r;
        bytes32 s = sig.s;
        assembly ("memory-safe") {
            // Signature consists of two words and one byte.
            mstore(blob, 0x41)

            mstore(add(blob, 0x20), r)
            mstore(add(blob, 0x40), s)
            // Note to shift v to highest-order byte.
            mstore(add(blob, 0x60), shl(248, v))
        }
        return blob;
    }

    /// @dev Returns Signature from bytes `blob`.
    ///
    /// @dev Reverts if:
    ///      - Blob not exactly 65 bytes
    ///
    /// @dev Expects following encoding:
    ///         [256-bit r value][256-bit s value][8-bit v value]
    function signatureFromBytes(bytes memory blob)
        internal
        pure
        returns (Signature memory)
    {
        if (blob.length != 65) {
            revert("InvalidLength()");
        }

        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := mload(blob)
            s := mload(add(blob, 0x20))
            v := byte(0, mload(add(blob, 0x40)))
        }

        return Signature(v, r, s);
    }

    /// @dev Returns signature `sig` as bytes in compact signature encoding
    ///      defined via EIP-2098.
    ///
    /// @dev Provides following encoding:
    ///         [256-bit r value][1-bit yParity value][255-bit s value]
    function toCompactBytes(Signature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory blob;

        // @todo Use direct access in assembly.
        uint8 v = sig.v;
        bytes32 r = sig.r;
        bytes32 s = sig.s;
        assembly ("memory-safe") {
            // Signature consists of two words.
            mstore(blob, 0x40)

            // yParity is 0 or 1, normalized from the canonical 27 or 28.
            let yParity := sub(v, 27)
            // yParityAndS is (yParity << 255) | s.
            let yParityAndS := or(shl(255, yParity), s)

            mstore(add(blob, 0x20), r)
            mstore(add(blob, 0x40), yParityAndS)
        }

        return blob;
    }

    /// @dev Returns Signature from bytes `blob`.
    ///      Expects `blob` to be compact signature encoded defined via EIP-2098.
    ///
    /// @dev Reverts if:
    ///      - Blob not exactly 64 bytes
    ///
    /// @dev Expects following encoding:
    ///         [256-bit r value][1-bit yParity value][255-bit s value]
    function signatureFromCompactBytes(bytes memory blob)
        internal
        pure
        returns (Signature memory)
    {
        if (blob.length != 64) {
            revert("InvalidLength()");
        }

        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := mload(blob)
            let yParityAndS := mload(add(blob, 0x20))

            // Receive s via masking yParityAndS with EIP-2098 mask.
            s := and(yParityAndS, _EIP2098_MASK)

            // Receive v via reading yParity, encoded in the last bit, and
            // adding 27.
            //
            // Note that yParity ∊ {0, 1} which cannot overflow by adding 27.
            v := add(shr(255, yParityAndS), 27)
        }

        return Signature(v, r, s);
    }
}
