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

import {
    Secp256k1Arithmetic,
    AffinePoint,
    JacobianPoint
} from "./Secp256k1Arithmetic.sol";

import {Random} from "../Random.sol";

/**
 * @notice PrivateKey is a secret scalar
 *
 * @dev Note that a private key MUST be a field element,
 *      ie private key ∊ [1, Q).
 *
 * @dev Note that a private key MUST be created cryptographically secure!
 *      Generally, this means via randomness sourced from an CSPRNG.
 *
 * @custom:example Generating a secure private key:
 *
 *      ```solidity
 *      import {Secp256k1, PrivateKey} from "crysol/curves/Secp256k1.sol";
 *      using Secp256k1 for PrivateKey;
 *
 *      PrivateKey privKey = Secp256k1.newPrivateKey();
 *      assert(privKey.isValid());
 *      ```
 */
type PrivateKey is uint;

/**
 * @notice PublicKey is a private key's public identifier
 *
 * @dev A public key is a point on the secp256k1 curve computed via [privKey]G.
 *
 * @custom:example Deriving a public key from a private key:
 *
 *      ```solidity
 *      import {Secp256k1, PrivateKey, PublicKey} from "crysol/curves/Secp256k1.sol";
 *      using Secp256k1 for PrivateKey;
 *      using Secp256k1 for PublicKey;
 *
 *      PrivateKey privKey = Secp256k1.newPrivateKey();
 *
 *      PublicKey memory pubKey = privKey.toPublicKey();
 *      assert(pubKey.isValid());
 *
 *      address addr = pubKey.toAddress();
 *      ```
 */
struct PublicKey {
    uint x;
    uint y;
}

/**
 * @title Secp256k1
 *
 * @notice Library providing common cryptography-related functionality for the
 *         secp256k1 elliptic curve
 *
 * @dev ...
 */
library Secp256k1 {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for AffinePoint;
    using Secp256k1Arithmetic for AffinePoint;

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
    // Private Constants

    uint private constant _ADDRESS_MASK =
        0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    //--------------------------------------------------------------------------
    // Secp256k1 Constants
    //
    // Reimported from Secp256k1Arithmetic.

    /// @dev The generator G as PublicKey.
    function G() internal pure returns (PublicKey memory) {
        AffinePoint memory g = Secp256k1Arithmetic.G();

        return PublicKey(g.x, g.y);
    }

    /// @dev The order of the group generated via generator G.
    uint internal constant Q = Secp256k1Arithmetic.Q;

    //--------------------------------------------------------------------------
    // Private Key

    /// @dev Returns a new cryptographically secure private key.
    ///
    /// @custom:vm Random::readUint()(uint)
    function newPrivateKey() internal vmed returns (PrivateKey) {
        uint scalar = Random.readUint();
        while (scalar == 0 || scalar >= Secp256k1.Q) {
            // Note to not introduce potential bias via bounding operation.
            scalar = Random.readUint();
        }
        return privateKeyFromUint(scalar);
    }

    /// @dev Returns whether private key `privKey` is valid.
    ///
    /// @dev A valid secp256k1 private key ∊ [1, Q).
    function isValid(PrivateKey privKey) internal pure returns (bool) {
        return privKey.asUint() != 0 && privKey.asUint() < Secp256k1Arithmetic.Q;
    }

    /// @dev Returns the public key of private key `privKey`.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm vm.createWallet(uint)
    function toPublicKey(PrivateKey privKey)
        internal
        vmed
        returns (PublicKey memory)
    {
        if (!privKey.isValid()) {
            revert("PrivateKeyInvalid()");
        }

        // Compute pubKey = [privKey]G via vm.
        Vm.Wallet memory wallet = vm.createWallet(privKey.asUint());
        return PublicKey(wallet.publicKeyX, wallet.publicKeyY);
    }

    /// @dev Returns uint `scalar` as private key.
    ///
    /// @dev Reverts if:
    ///      - Scalar not in [1, Q)
    function privateKeyFromUint(uint scalar)
        internal
        pure
        returns (PrivateKey)
    {
        if (scalar == 0 || scalar >= Q) {
            revert("InvalidScalar()");
        }

        return PrivateKey.wrap(scalar);
    }

    /// @dev Returns private key `privKey` as uint.
    function asUint(PrivateKey privKey) internal pure returns (uint) {
        return PrivateKey.unwrap(privKey);
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Returns the address of public key `pubKey`.
    ///
    /// @dev An Ethereum address is defined as the rightmost 160 bits of the
    ///      keccak256 hash of the concatenation of the hex-encoded x and y
    ///      coordinates of the corresponding ECDSA public key.
    ///
    ///      See "Appendix F: Signing Transactions" §134 in the Yellow Paper.
    function toAddress(PublicKey memory pubKey)
        internal
        pure
        returns (address)
    {
        bytes32 digest = pubKey.toHash();

        address addr;
        assembly ("memory-safe") {
            addr := and(digest, _ADDRESS_MASK)
        }
        return addr;
    }

    /// @dev Returns the keccak256 hash of public key `pubKey`.
    function toHash(PublicKey memory pubKey) internal pure returns (bytes32) {
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(pubKey, 0x40)
        }
        return digest;
    }

    /// @dev Returns whether public key `pubKey` is a valid secp256k1 public key.
    function isValid(PublicKey memory pubKey) internal pure returns (bool) {
        return pubKey.intoAffinePoint().isOnCurve();
    }

    /// @dev Returns the y parity of public key `pubKey`.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in the Yellow Paper.
    function yParity(PublicKey memory pubKey) internal pure returns (uint) {
        return pubKey.intoAffinePoint().yParity();
    }

    /// @dev Mutates public key `pubKey` to Affine Point.
    function intoAffinePoint(PublicKey memory pubKey)
        internal
        pure
        returns (AffinePoint memory)
    {
        AffinePoint memory point;
        assembly ("memory-safe") {
            point := pubKey
        }
        return point;
    }

    /// @dev Mutates Affine point `point` to Public Key.
    function intoPublicKey(AffinePoint memory point)
        internal
        pure
        returns (PublicKey memory)
    {
        PublicKey memory pubKey;
        assembly ("memory-safe") {
            pubKey := point
        }
        return pubKey;
    }

    /// @dev Returns public key `pubKey` as Jacobian Point.
    function toJacobianPoint(PublicKey memory pubKey)
        internal
        pure
        returns (JacobianPoint memory)
    {
        return JacobianPoint(pubKey.x, pubKey.y, 1);
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Private Key

    /// @dev Returns bytes `blob` as private key.
    ///
    /// @dev Reverts if:
    ///      - Length not 32 bytes
    ///      - Deserialized scalar not in [1, Q)
    function privateKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (PrivateKey)
    {
        if (blob.length != 32) {
            revert("InvalidLength()");
        }

        uint scalar;
        assembly ("memory-safe") {
            scalar := mload(add(blob, 0x20))
        }

        return privateKeyFromUint(scalar);
    }

    /// @dev Returns private key `privKey` as bytes.
    function toBytes(PrivateKey privKey) internal pure returns (bytes memory) {
        return abi.encodePacked(privKey.asUint());
    }

    //----------------------------------
    // Public Key

    /// @dev Returns public key from bytes `blob`.
    ///
    /// @dev Reverts if:
    ///      - Length not 65 bytes
    ///      - Prefix byte not 0x04
    ///      - Deserialized public key invalid
    ///
    /// @dev Expects uncompressed 65 bytes encoding:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    function publicKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (PublicKey memory)
    {
        // Revert if length not 65.
        if (blob.length != 65) {
            revert("InvalidLength()");
        }

        // Read prefix byte.
        bytes32 prefix;
        assembly ("memory-safe") {
            prefix := byte(0, mload(add(blob, 0x20)))
        }

        // Revert if prefix not 0x04.
        if (uint(prefix) != 0x04) {
            revert("InvalidPrefix()");
        }

        // Read x and y coordinates of public key.
        uint x;
        uint y;
        assembly ("memory-safe") {
            x := mload(add(blob, 0x21))
            y := mload(add(blob, 0x41))
        }

        // Make public key.
        PublicKey memory pubKey = PublicKey(x, y);

        // Revert if public key invalid.
        if (!pubKey.isValid()) {
            revert("InvalidPublicKey()");
        }

        return pubKey;
    }

    /// @dev Returns public key `pubKey` as bytes.
    ///
    /// @dev Provides uncompressed 65 bytes encoding:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    function toBytes(PublicKey memory pubKey)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(bytes1(0x04), pubKey.x, pubKey.y);
    }

    //--------------------------------------------------------------------------
    //------------------------  END  -------------------------------------------
    //--------------------------------------------------------------------------

    /*
    // --------- @todo Compressed Public Key Serde ----------

    // @todo compressed public keys are 33 bytes:
    //       (0x02 OR 0x03 prefix + 32 byte x-coordinate,
    //       where 0x02 means the y value is even, and 0x03 means it's odd
    function publicKeyFromCompressedBytes(bytes memory blob)
        internal
        pure
        returns (PublicKey memory)
    {
        // Revert if length not 33.
        if (blob.length != 33) {
            revert("InvalidLength()");
        }

        // Read prefix byte.
        bytes32 prefix;
        assembly ("memory-safe") {
            prefix := byte(0, mload(add(blob, 0x20)))
        }

        // Read x coordinate of public key.
        uint x;
        assembly ("memory-safe") {
            x := mload(add(blob, 0x21))
        }

        // Revert if prefix not 0x02 or 0x03.
        if (uint(prefix) != 0x02 && uint(prefix) != 0x03) {
            revert("InvalidPrefix()");
        }

        PublicKey memory pubKey;
        pubKey.x = x;
        // @todo Compute y coordinate.
        pubKey.y = uint(prefix) == 0x02 ? 0 : 1;

        return pubKey;
    }

    function asCompressedBytes(PublicKey memory self)
        internal
        pure
        returns (bytes memory)
    {
        uint yParity_ = self.yParity();

        bytes memory blob;
        assembly ("memory-safe") {
            mstore(blob, 33)

            let prefix := add(0x02, yParity_)
            mstore(add(blob, 0x20), prefix)

            let x := mload(self)
            mstore(add(blob, 0x21), x)
        }
        return blob;
    }
    */
}
