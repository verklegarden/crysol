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
 * @notice PrivateKey is the secret scalar
 *
 * @dev Note that a private key's MUST be a field element,
 *      ie private key ∊ [1, Q).
 *
 * @dev Note that a private key MUST be created cryptographically sound!
 *      Generally, this means via secure randomness.
 *
 * @custom:example Generating a secure private key.
 *
 *      ```solidity
 *      import {Secp256k1, PrivateKey} from "crysol/Secp256k1.sol";
 *      using Secp256k1 for PrivateKey;
 *
 *      PrivateKey privKey = Secp256k1.newPrivateKey();
 *      assert(privKey.isValid());
 *      ```
 */
type PrivateKey is uint;

/**
 * @notice PublicKey is a PrivateKey's public identifier
 *
 * @dev A public key is derived from a private key via [privKey]G.
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

    Vm private constant vm =
        Vm(address(uint160(uint(keccak256("hevm cheat code")))));

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
    function newPrivateKey() internal returns (PrivateKey) {
        // Let scalar ∊ [1, Q) sourced cryptographically secure.
        uint scalar = (Random.readUint() % (Secp256k1Arithmetic.Q - 1)) + 1;
        return PrivateKey.wrap(scalar);
    }

    /// @dev Returns whether private key `self` is valid.
    ///
    /// @dev A valid secp256k1 private key ∊ [1, Q).
    function isValid(PrivateKey self) internal pure returns (bool) {
        return self.asUint() != 0 && self.asUint() < Secp256k1Arithmetic.Q;
    }

    /// @dev Returns the public key of private key `self`.
    ///
    /// @dev Reverts if:
    ///      - Private key invalid
    ///
    /// @custom:vm vm.createWallet(uint)
    function toPublicKey(PrivateKey self) internal returns (PublicKey memory) {
        if (!self.isValid()) {
            revert("PrivateKeyInvalid()");
        }

        // Compute pubKey = [self]G via vm.
        Vm.Wallet memory wallet = vm.createWallet(self.asUint());
        return PublicKey(wallet.publicKeyX, wallet.publicKeyY);
    }

    //----------------------------------
    // Casting

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

    /// @dev Returns private key `self` as uint.
    function asUint(PrivateKey self) internal pure returns (uint) {
        return PrivateKey.unwrap(self);
    }

    /// @dev Returns bytes `blob` as private key.
    ///
    /// @dev Reverts if:
    ///      - Length invalid
    ///      - Encoded scalar not in [1, Q)
    function privateKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (PrivateKey)
    {
        if (blob.length != 0x20) {
            revert("InvalidLength()");
        }

        uint scalar;
        assembly ("memory-safe") {
            scalar := mload(add(blob, 0x20))
        }

        return privateKeyFromUint(scalar);
    }

    /// @dev Returns private key `self` as bytes.
    function asBytes(PrivateKey self) internal pure returns (bytes memory) {
        return abi.encodePacked(self.asUint());
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Returns the address of public key `self`.
    ///
    /// @dev An Ethereum address is defined as the rightmost 160 bits of the
    ///      keccak256 hash of the concatenation of the hex-encoded x and y
    ///      coordinates of the corresponding ECDSA public key.
    ///
    ///      See "Appendix F: Signing Transactions" §134 in the Yellow Paper.
    function toAddress(PublicKey memory self) internal pure returns (address) {
        bytes32 digest = self.toHash();

        address addr;
        assembly ("memory-safe") {
            addr := and(digest, _ADDRESS_MASK)
        }
        return addr;
    }

    /// @dev Returns the keccak256 hash of public key `self`.
    function toHash(PublicKey memory self) internal pure returns (bytes32) {
        bytes32 hash_;
        assembly ("memory-safe") {
            hash_ := keccak256(self, 0x40)
        }
        return hash_;
    }

    /// @dev Returns whether public key `self` is a valid secp256k1 public key.
    function isValid(PublicKey memory self) internal pure returns (bool) {
        return self.intoAffinePoint().isOnCurve();
    }

    /// @dev Returns the y parity of public key `self`.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in the Yellow Paper.
    function yParity(PublicKey memory self) internal pure returns (uint) {
        return self.intoAffinePoint().yParity();
    }

    //----------------------------------
    // Casting

    /// @dev ...
    ///
    /// @dev Reverts if:
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

        // Revert if prefix byte not 0x04.
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

        return PublicKey(x, y);
    }

    function asBytes(PublicKey memory self)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(bytes1(0x04), self.x, self.y);
    }

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

        // @todo Not nice :(
        // Compute y coordinate with even parity if prefix is 0x02.
        // Compute y coordinate with odd parity if prefix is 0x03.
        // Otherwise revert.
        if (uint(prefix) == 0x02) {
            uint y = 0; // @todo Compute y coordinate.
            return PublicKey(x, y);
        }
        if (uint(prefix) == 0x03) {
            uint y = 0; // @todo Compute y coordinate.
            return PublicKey(x, y);
        }

        revert("InvalidPrefix()");
    }

    function asCompressedBytes(PublicKey memory self)
        internal
        pure
        returns (bytes memory)
    {
        revert("asCompressedBytes()");
    }

    /// @dev Mutates public key `self` to Affine Point.
    function intoAffinePoint(PublicKey memory self)
        internal
        pure
        returns (AffinePoint memory)
    {
        AffinePoint memory point;
        assembly ("memory-safe") {
            point := self
        }
        return point;
    }

    function intoPublicKey(AffinePoint memory self)
        internal
        pure
        returns (PublicKey memory)
    {
        PublicKey memory pubKey;
        assembly ("memory-safe") {
            pubKey := self
        }
        return pubKey;
    }

    /// @dev Returns public key `self` as Jacobian Point.
    function toJacobianPoint(PublicKey memory self)
        internal
        pure
        returns (JacobianPoint memory)
    {
        return JacobianPoint(self.x, self.y, 1);
    }
}
