// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    AffinePoint,
    JacobianPoint
} from "src/curves/Secp256k1Arithmetic.sol";

/**
 * @title Secp256k1ArithmeticWrapper
 *
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256k1ArithmeticWrapper {
    using Secp256k1Arithmetic for AffinePoint;
    using Secp256k1Arithmetic for JacobianPoint;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (AffinePoint memory) {
        return Secp256k1Arithmetic.G();
    }

    //--------------------------------------------------------------------------
    // Affine Point

    function ZeroPoint() public pure returns (AffinePoint memory) {
        return Secp256k1Arithmetic.ZeroPoint();
    }

    function isZeroPoint(AffinePoint memory point) public pure returns (bool) {
        return point.isZeroPoint();
    }

    function PointAtInfinity() public pure returns (AffinePoint memory) {
        return Secp256k1Arithmetic.PointAtInfinity();
    }

    function isPointAtInfinity(AffinePoint memory point)
        public
        pure
        returns (bool)
    {
        return point.isPointAtInfinity();
    }

    function isOnCurve(AffinePoint memory point) public pure returns (bool) {
        return point.isOnCurve();
    }

    function yParity(AffinePoint memory point) public pure returns (uint) {
        return point.yParity();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Affine Point

    function toJacobianPoint(AffinePoint memory point)
        public
        pure
        returns (JacobianPoint memory)
    {
        return point.toJacobianPoint();
    }

    //----------------------------------
    // Jacobian Point

    function intoAffinePoint(JacobianPoint memory jacPoint)
        public
        pure
        returns (AffinePoint memory)
    {
        return jacPoint.intoAffinePoint();
    }

    //--------------------------------------------------------------------------
    // Utils

    function modularInverseOf(uint x) public pure returns (uint) {
        return Secp256k1Arithmetic.modularInverseOf(x);
    }

    function areModularInverse(uint x, uint xInv) public pure returns (bool) {
        return Secp256k1Arithmetic.areModularInverse(x, xInv);
    }
}
