// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    AffinePoint,
    JacobianPoint
} from "src/curves/Secp256k1Arithmetic.sol";

/**
 * @title Secp256k1Wrapper
 *
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256k1Wrapper {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for AffinePoint;
    using Secp256k1Arithmetic for AffinePoint;

    //--------------------------------------------------------------------------
    // Constants

    function G() public view returns (PublicKey memory) {
        return Secp256k1.G();
    }

    //--------------------------------------------------------------------------
    // Private Key

    function newPrivateKey() public returns (PrivateKey) {
        return Secp256k1.newPrivateKey();
    }

    function isValid(PrivateKey privKey) public view returns (bool) {
        return privKey.isValid();
    }

    function toPublicKey(PrivateKey privKey)
        public
        returns (PublicKey memory)
    {
        return privKey.toPublicKey();
    }

    function privateKeyFromUint(uint scalar) public view returns (PrivateKey) {
        return Secp256k1.privateKeyFromUint(scalar);
    }

    function asUint(PrivateKey privKey) public view returns (uint) {
        return privKey.asUint();
    }

    //--------------------------------------------------------------------------
    // Public Key

    function toAddress(PublicKey memory pubKey) public view returns (address) {
        return pubKey.toAddress();
    }

    function toHash(PublicKey memory pubKey) public view returns (bytes32) {
        return pubKey.toHash();
    }

    function isValid(PublicKey memory pubKey) public view returns (bool) {
        return pubKey.isValid();
    }

    function yParity(PublicKey memory pubKey) public view returns (uint) {
        return pubKey.yParity();
    }

    function intoAffinePoint(PublicKey memory pubKey)
        public
        view
        returns (AffinePoint memory)
    {
        return pubKey.intoAffinePoint();
    }

    function intoPublicKey(AffinePoint memory point)
        public
        view
        returns (PublicKey memory)
    {
        return point.intoPublicKey();
    }

    function toJacobianPoint(PublicKey memory pubKey)
        public
        view
        returns (JacobianPoint memory)
    {
        return pubKey.toJacobianPoint();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Private Key

    function privateKeyFromBytes(bytes memory blob)
        public
        view
        returns (PrivateKey)
    {
        return Secp256k1.privateKeyFromBytes(blob);
    }

    function asBytes(PrivateKey privKey) public view returns (bytes memory) {
        return privKey.asBytes();
    }

    //----------------------------------
    // Public Key

    function publicKeyFromBytes(bytes memory blob)
        public
        view
        returns (PublicKey memory)
    {
        return Secp256k1.publicKeyFromBytes(blob);
    }

    function asBytes(PublicKey memory pubKey)
        public
        view
        returns (bytes memory)
    {
        return pubKey.asBytes();
    }
}
