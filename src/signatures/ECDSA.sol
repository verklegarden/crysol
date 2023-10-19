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

/*
ECDSA sig (r, s):

r = ([k]G)_x

s = (H(m) + [p+k]G) / k

where:
k   = nonce
m   = message
H() = keccak256
P   = public key
p   = private key
G   = generator
_x  = x coordinate of point
*/

/**
 * @title ECDSA
 *
 * @notice Library providing common ECDSA functionality
 *
 * @dev Provides common functionality for the Elliptic Curve Digital Signature
 *      Algorithm (ECDSA) as defined in [SEC 1 v2] in combination with the
 *      secp256k1 elliptic curve and keccak256 hash function.
 *
 *      ...
 *
 *
 * @custom:references
 *      - [SEC 1 v2]: https://www.secg.org/sec1-v2.pdf
 *      - [EIP-2098]: https://eips.ethereum.org/EIPS/eip-2098
 */
library ECDSA {
    using ECDSA for address;
    using ECDSA for Signature;
    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    Vm private constant vm =
        Vm(address(uint160(uint(keccak256("hevm cheat code")))));

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
    ///     ∀x pubKey ∊ (Uint, Uint): pubKey.isValid() → pubKey.toAddress() != address(0)
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
    ///     ∀x pubKey ∊ (Uint, Uint): pubKey.isValid() → pubKey.toAddress() != address(0)
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
            revert("SignerIsZeroAddress()");
        }

        // Fail if signature is malleable.
        if (sig.isMalleable()) {
            revert("SignatureIsMalleable()");
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
    function sign(PrivateKey privKey, bytes memory message)
        internal
        pure
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
    function sign(PrivateKey privKey, bytes32 digest)
        internal
        pure
        returns (Signature memory)
    {
        if (!privKey.isValid()) {
            revert("InvalidPrivateKey()");
        }

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        Signature memory sig = Signature(v, r, s);
        assert(!sig.isMalleable());

        return sig;
    }

    function signEthereumSignedMessage(PrivateKey privKey, bytes memory message)
        internal
        pure
        returns (Signature memory)
    {
        bytes32 digest = Message.deriveEthereumSignedMessage(message);

        return privKey.sign(digest);
    }

    function signEthereumSignedMessageHash(PrivateKey privKey, bytes32 digest)
        internal
        pure
        returns (Signature memory)
    {
        bytes32 digest2 = Message.deriveEthereumSignedMessageHash(digest);

        return privKey.sign(digest2);
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether signature `self` is malleable.
    ///
    /// @dev A signature is malleable if `self.s > Secp256k1.Q / 2`.
    function isMalleable(Signature memory self) internal pure returns (bool) {
        return self.s
            > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    }

    /// @dev Returns a string representation of signature `self`.
    ///
    /// @custom:vm vm.toString(uint)
    function toString(Signature memory self)
        internal
        pure
        returns (string memory)
    {
        string memory str = "ECDSA::Signature { \n";
        str = string.concat(str, "    v: ", vm.toString(self.v), ",\n");
        str = string.concat(str, "    r: ", vm.toString(self.r), ",\n");
        str = string.concat(str, "    s: ", vm.toString(self.s), "\n");
        str = string.concat(str, "  }");
        return str;
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    /// @dev Returns signature `self` as bytes.
    ///
    ///      Format: [256-bit r value][256-bit s value][8-bit v value]
    function toBytes(Signature memory self)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory blob;

        // @todo Use direct access in assembly.
        uint8 v = self.v;
        bytes32 r = self.r;
        bytes32 s = self.s;
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

    /// @dev Returns Signature deserialized from bytes `blob`.
    ///
    /// @dev Expected format: [256-bit r value][256-bit s value][8-bit v value]
    ///
    /// @dev Reverts if:
    ///      - Blob not exactly 65 bytes
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

    /// @dev Returns signature `self` as bytes in compact signature
    ///      representation as defined in EIP-2098.
    ///
    ///      Format: [256-bit r value][1-bit yParity value][255-bit s value]
    function toCompactBytes(Signature memory self)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory blob;

        // @todo Use direct access in assembly.
        uint8 v = self.v;
        bytes32 r = self.r;
        bytes32 s = self.s;
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

    /// @dev Returns Signature deserialized from bytes `blob`.
    ///      Expects `blob` to be a compact signature representation as defined
    ///      in EIP-2098.
    ///
    /// @dev Expected format: [256-bit r value][1-bit yParity value][255-bit s value]
    ///
    /// @dev Reverts if:
    ///      - Blob not exactly 64 bytes
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
