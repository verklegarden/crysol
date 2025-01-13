/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Secp256k1, PublicKey} from "../Secp256k1.sol";
import {Fp, Felt} from "./Fp.sol";

import "../Errors.sol" as Errors;

/**
 * @notice Point is a secp256k1 point in affine coordinates
 *
 * @dev The identity, aka point at infinity, is represented via:
 *          x = y = 0
 */
struct Point {
    Felt x;
    Felt y;
}

/**
 * @notice ProjectivePoint is a secp256k1 point in projective coordinates
 *
 * @dev A projective point represents an affine point (x, y) as (X, Y, Z)
 *      satisfying the following equations:
 *          x = X / Z
 *          y = Y / Z
 */
struct ProjectivePoint {
    Felt x;
    Felt y;
    Felt z;
}

/**
 * @title Points
 *
 * @notice Provides common arithmetic-related functionality for the secp256k1
 *         elliptic curve
 *
 * @custom:references
 *      - [SEC-1 v2]: https://www.secg.org/sec1-v2.pdf
 *      - [SEC-2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: https://github.com/ethereum/yellowpaper
 *      - [Renes-Costello-Batina 2015]: https://eprint.iacr.org/2015/1060.pdf
 *      - [Vitalik 2018]: https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Points {
    using Secp256k1 for PublicKey;
    using Fp for Felt;
    using Points for Point;
    using Points for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Optimization Constants

    /// @dev Used during projective point addition.
    uint private constant _B3 = mulmod(B, 3, P);

    /// @dev Used during compressed point decoding.
    ///
    /// @dev Note that the square root of an secp256k1 field element x can be
    ///      computed via x^{_SQUARE_ROOT_EXPONENT} (mod p).
    uint private constant _SQUARE_ROOT_EXPONENT = (P + 1) / 4;

    /// @dev Used as substitute for `Identity().intoPublicKey().toAddress()`.
    address private constant _IDENTITY_ADDRESS =
        0x3f17f1962B36e491b30A40b2405849e597Ba5FB5;

    //--------------------------------------------------------------------------
    // UNDEFINED Constants

    /// @dev The undefined point instance.
    ///
    ///      This point instantiation is used to indicate undefined behaviour.
    function _UNDEFINED_POINT() private pure returns (Point memory) {
        return Point(
            Fp.unsafeFromUint(type(uint).max), Fp.unsafeFromUint(type(uint).max)
        );
    }

    //--------------------------------------------------------------------------
    // Secp256k1 Constants
    //
    // Reimported from Secp256k1.

    uint internal constant B = Secp256k1.B;
    uint internal constant P = Secp256k1.P;
    uint internal constant Q = Secp256k1.Q;

    function G() internal pure returns (Point memory) {
        return Secp256k1.G().intoPoint();
    }

    //--------------------------------------------------------------------------
    // Point

    /// @dev Tries to instantiate a point from felt coordinates `x` and `y`.
    ///
    /// @dev Note that returned point is undefined if function fails to
    ///      instantiate point.
    function tryFromFelts(Felt x, Felt y)
        internal
        pure
        returns (Point memory, bool)
    {
        if (!x.isValid() || !y.isValid()) {
            return (_UNDEFINED_POINT(), false);
        }

        Point memory p = Point(x, y);
        if (!p.isOnCurve()) {
            return (_UNDEFINED_POINT(), false);
        }

        return (p, true);
    }

    /// @dev Instantiates point from felt coordinates `x` and `y`.
    ///
    /// @dev Reverts if:
    ///         Coordinate x not a valid felt
    ///       ∨ Coordinate y not a valid felt
    ///       ∨ Coordinates not on the curve
    function fromFelts(Felt x, Felt y) internal pure returns (Point memory) {
        (Point memory p, bool ok) = tryFromFelts(x, y);
        if (!ok) {
            revert Errors.CRYSOL_PointInvalid();
        }

        return p;
    }

    /// @dev Instantiates point from felt coordinates `x` and `y` without
    ///      performing safety checks.
    ///
    /// @dev This function is unsafe and may lead to undefined behaviour if
    ///      used incorrectly.
    function unsafeFromFelts(Felt x, Felt y)
        internal
        pure
        returns (Point memory)
    {
        return Point(x, y);
    }

    /// @dev Tries to instantiate a point from uint coordinates `x` and `y`.
    ///
    /// @dev Note that returned point is undefined if function fails to
    ///      instantiate point.
    function tryFromUints(uint x, uint y)
        internal
        pure
        returns (Point memory, bool)
    {
        return tryFromFelts(Fp.unsafeFromUint(x), Fp.unsafeFromUint(y));
    }

    /// @dev Instantiates point from uint coordinates `x` and `y`.
    ///
    /// @dev Reverts if:
    ///         Coordinate x not a felt
    ///       ∨ Coordinate y not a felt
    ///       ∨ Coordinates not on the curve
    function fromUints(uint x, uint y) internal pure returns (Point memory) {
        (Point memory p, bool ok) = tryFromUints(x, y);
        if (!ok) {
            revert Errors.CRYSOL_PointInvalid();
        }

        return p;
    }

    /// @dev Instantiates point from uint coordinates `x` and `y` without
    ///      performing safety checks.
    ///
    /// @dev This function is unsafe and may lead to undefined behaviour if
    ///      used incorrectly.
    function unsafeFromUints(uint x, uint y)
        internal
        pure
        returns (Point memory)
    {
        return Point(Fp.unsafeFromUint(x), Fp.unsafeFromUint(y));
    }

    /// @dev Returns the additive identity.
    ///
    /// @dev Note that the identity is represented via:
    ///         point.x = point.y = 0
    ///
    /// @dev Note that the identity is a valid point on the curve to enable
    ///      arithmetic functionality. However, the identity is not a valid
    ///      PublicKey and MUST NOT be used as cryptographic object.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function Identity() internal pure returns (Point memory) {
        return Point(Fp.ZERO, Fp.ZERO);
    }

    /// @dev Returns whether point `point` is the identity.
    function isIdentity(Point memory point) internal pure returns (bool) {
        return (point.x.asUint() | point.y.asUint()) == 0;
    }

    /// @dev Returns whether point `point` is on the curve.
    ///
    /// @dev Note that the identity is on the curve.
    function isOnCurve(Point memory point) internal pure returns (bool) {
        if (point.isIdentity()) {
            return true;
        }

        // Verify whether y² ≡ x³ + ax + b (mod p).
        // Note that adding a * x can be waived as ∀x: a * x = 0.
        // forgefmt: disable-start
        Felt left  = point.y
                          .mul(point.y);
        Felt right = point.x
                          .mul(point.x)
                          .mul(point.x)
                          .add(Fp.unsafeFromUint(B));
        // forgefmt: disable-end

        return left.asUint() == right.asUint();
    }

    /// @dev Returns the parity of point `point`'s y coordinate.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in [Yellow Paper].
    function yParity(Point memory point) internal pure returns (uint) {
        return point.y.parity();
    }

    /// @dev Returns whether point `point` equals point `other`.
    function eq(Point memory point, Point memory other)
        internal
        pure
        returns (bool)
    {
        return point.x.asUint() == other.x.asUint()
            && point.y.asUint() == other.y.asUint();
    }

    // TODO: Misses revert documentation?
    /// @dev Returns the product of point `point` and scalar `scalar` as
    ///      address.
    ///
    /// @dev Note that this function is substantially cheaper than
    ///      `mul(ProjectivePoint,uint)(ProjectivePoint)` with the caveat that
    ///      only the point's address is returned instead of the point itself.
    function mulToAddress(Point memory point, uint scalar)
        internal
        pure
        returns (address)
    {
        if (scalar >= Q) {
            revert Errors.CRYSOL_ScalarMalleable();
        }

        if (scalar == 0 || point.isIdentity()) {
            return _IDENTITY_ADDRESS;
        }

        // Note that ecrecover can be abused to perform an elliptic curve
        // multiplication with the caveat that the point's address is returned
        // instead of the point itself.
        //
        // For further details, see [Vitalik 2018] and [SEC-1 v2] section 4.1.6
        // "Public Key Recovery Operation".

        uint8 v;
        // Unchecked because point.yParity() ∊ {0, 1} which cannot overflow by
        // adding 27.
        unchecked {
            v = uint8(point.yParity() + 27);
        }
        // TODO BUG: Need to reduce % Q ?
        //uint r = point.x.asUint() % Q;
        uint r = point.x.asUint();
        uint s = mulmod(r, scalar, Q);

        return ecrecover(0, v, bytes32(r), bytes32(s));
    }

    //--------------------------------------------------------------------------
    // Projective Point

    /// @dev Returns the additive identity as projective point.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function ProjectiveIdentity()
        internal
        pure
        returns (ProjectivePoint memory)
    {
        return ProjectivePoint(Fp.ZERO, Fp.ONE, Fp.ZERO);
    }

    /// @dev Returns whether projective point `point` is the identity.
    ///
    /// @dev Note that the identity is also called point at infinity.
    function isIdentity(ProjectivePoint memory point)
        internal
        pure
        returns (bool)
    {
        return (point.x.asUint() | point.z.asUint()) == 0;
    }

    /// @dev DO NOT IMPORT!
    ///
    /// @dev This is an internal struct to circumvent stack-too-deep errors in
    ///      ProjectivePoint::add() during non --via-ir compilation.
    struct __addTempVars {
        Felt t0;
        Felt t1;
        Felt t2;
        Felt t3;
        Felt t4;
    }

    /// @dev Returns the sum of projective points `point` and `other` as
    ///      projective point.
    ///
    /// @dev Uses algorithm 7 from [Renes-Costello-Batina 2015] based on a
    ///      complete addition formula for Weierstrass curves with a = 0.
    function add(ProjectivePoint memory point, ProjectivePoint memory other)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        // Return early if addition with identity.
        if (point.isIdentity()) {
            return other;
        }
        if (other.isIdentity()) {
            return point;
        }

        // forgefmt: disable-start

        // Note that for optimization reasons native uint is used instead of Fp.

        // Inputs:
        // - P = (x1, y1, z1)
        uint x1 = point.x.asUint();
        uint y1 = point.y.asUint();
        uint z1 = point.z.asUint();
        // - Q = (x2, y2, z2)
        uint x2 = other.x.asUint();
        uint y2 = other.y.asUint();
        uint z2 = other.z.asUint();

        // Output:
        // - (x3, y3, z3) = P + Q
        uint x3; uint y3; uint z3;

        // Constants:
        // - _B3 = mulmod(B, 3, P)

        // Variables:
        uint t0; uint t1; uint t2; uint t3; uint t4;

        // Computations:
        // Note that x - y = x + (P - y) (mod P)
        t0 = mulmod(x1, x2, P);
        t1 = mulmod(y1, y2, P);
        t2 = mulmod(z1, z2, P);
        t3 = addmod(x1, y1, P);
        t4 = addmod(x2, y2, P);
        t3 = mulmod(t3, t4, P);
        t4 = addmod(t0, t1, P);
        unchecked { t3 = addmod(t3, P - t4, P); }
        t4 = addmod(y1, z1, P);
        x3 = addmod(y2, z2, P);
        t4 = mulmod(t4, x3, P);
        x3 = addmod(t1, t2, P);
        unchecked { t4 = addmod(t4, P - x3, P); }
        x3 = addmod(x1, z1, P);
        y3 = addmod(x2, z2, P);
        x3 = mulmod(x3, y3, P);
        y3 = addmod(t0, t2, P);
        unchecked { y3 = addmod(x3, P - y3, P); }
        x3 = addmod(t0, t0, P);
        t0 = addmod(x3, t0, P);
        t2 = mulmod(_B3, t2, P);
        z3 = addmod(t1, t2, P);
        unchecked { t1 = addmod(t1, P - t2, P); }
        y3 = mulmod(_B3, y3, P);
        x3 = mulmod(t4, y3, P);
        t2 = mulmod(t3, t1, P);
        unchecked { x3 = addmod(t2, P - x3, P); }
        y3 = mulmod(y3, t0, P);
        t1 = mulmod(t1, z3, P);
        y3 = addmod(t1, y3, P);
        t0 = mulmod(t0, t3, P);
        z3 = mulmod(z3, t4, P);
        z3 = addmod(z3, t0, P);
        // forgefmt: disable-end

        return ProjectivePoint(
            Fp.unsafeFromUint(x3), Fp.unsafeFromUint(y3), Fp.unsafeFromUint(z3)
        );
    }

    // TODO: Misses revert documentation?
    /// @dev Returns the product of projective point `point` and scalar `scalar`
    ///      as projective point.
    ///
    /// @dev Uses the repeated add-and-double algorithm.
    function mul(ProjectivePoint memory point, uint scalar)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        if (scalar >= Q) {
            revert Errors.CRYSOL_ScalarMalleable();
        }

        if (scalar == 0) {
            return ProjectiveIdentity();
        }

        ProjectivePoint memory copy = point;
        ProjectivePoint memory result = ProjectiveIdentity();

        // TODO: Can endomorphism be used?
        //       See Faster Point Multiplication on Elliptic Curves with
        //       Efficient Endomorphism from GLV.
        while (scalar != 0) {
            if (scalar & 1 == 1) {
                result = result.add(copy);
            }
            scalar >>= 1;
            copy = copy.add(copy);
        }

        return result;
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    //----------------------------------
    // Point

    /// @dev Returns point `point` as projective point.
    function toProjectivePoint(Point memory point)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        if (point.isIdentity()) {
            return ProjectiveIdentity();
        }

        return ProjectivePoint(point.x, point.y, Fp.ONE);
    }

    //----------------------------------
    // Projective Point

    /// @dev Mutates projective point `point` to affine point.
    function intoPoint(ProjectivePoint memory point)
        internal
        view
        returns (Point memory)
    {
        Point memory p;

        if (point.isIdentity()) {
            // Note to clean dirty p.z memory.
            point.z = Fp.ZERO;

            assembly ("memory-safe") {
                p := point
            }
            p.x = Fp.ZERO;
            p.y = Fp.ZERO;

            return p;
        }

        // Compute z⁻¹, i.e. the modular inverse of point.z.
        Felt zInv = point.z.inv();

        // Compute affine coordinates being x * z⁻¹ and y * z⁻¹, respectively.
        Felt x = point.x.mul(zInv);
        Felt y = point.y.mul(zInv);

        // Store x and y in point.
        assembly ("memory-safe") {
            mstore(point, x)
            mstore(add(point, 0x20), y)
        }

        // Return as Point(point.x, point.y).
        // Note to clean dirty p.z memory.
        point.z = Fp.ZERO;
        assembly ("memory-safe") {
            p := point
        }

        return p;
    }

    /// @dev Returns projective point `point` as affine point.
    function toPoint(ProjectivePoint memory point)
        internal
        view
        returns (Point memory)
    {
        if (point.isIdentity()) {
            return Identity();
        }

        // Compute z⁻¹, i.e. the modular inverse of point.z.
        Felt zInv = point.z.inv();

        // Compute affine coordinates being x * z⁻¹ and y * z⁻¹, respectively.
        Felt x = point.x.mul(zInv);
        Felt y = point.y.mul(zInv);

        // Return newly allocated point.
        return Point(x, y);
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    /// @dev Decodes point from [SEC-1 v2] encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///          Blob not 0x00
    ///        ∧ Length not 65 bytes
    ///          ∨ Prefix byte not 0x04
    ///      ∨ Deserialized point not on curve
    ///
    /// @dev Expects uncompressed 65 bytes encoding if point is not identity:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    ///
    ///      Expects single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function pointFromEncoded(bytes memory blob)
        internal
        pure
        returns (Point memory)
    {
        // Note to catch special encoding for identity.
        if (blob.length == 1 && bytes1(blob) == bytes1(0x00)) {
            return Identity();
        }

        // Revert if length not 65.
        if (blob.length != 65) {
            revert Errors.CRYSOL_LengthInvalid();
        }

        // Read prefix byte.
        uint prefix;
        assembly ("memory-safe") {
            prefix := byte(0, mload(add(blob, 0x20)))
        }

        // Revert if prefix not 0x04.
        if (prefix != 0x04) {
            revert Errors.CRYSOL_PrefixInvalid();
        }

        // Read x and y coordinates.
        uint xRaw;
        uint yRaw;
        assembly ("memory-safe") {
            xRaw := mload(add(blob, 0x21))
            yRaw := mload(add(blob, 0x41))
        }

        // Construct coordinates as felts.
        bool ok;
        Felt x;
        Felt y;
        (x, ok) = Fp.tryFromUint(xRaw);
        if (!ok) {
            revert Errors.CRYSOL_PointInvalid();
        }
        (y, ok) = Fp.tryFromUint(yRaw);
        if (!ok) {
            revert Errors.CRYSOL_PointInvalid();
        }

        // Construct point from coordinates.
        Point memory point = Point(x, y);

        // Revert if identity not 1 byte encoded.
        // TODO: Not explicitly tested.
        if (point.isIdentity()) {
            // TODO: Need different error type.
            revert Errors.CRYSOL_PointInvalid();
        }

        // Revert if point not on curve.
        if (!point.isOnCurve()) {
            revert Errors.CRYSOL_PointInvalid();
        }

        return point;
    }

    /// @dev Encodes point `point` as [SEC-1 v2] encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Point not on curve
    ///
    /// @dev Provides uncompressed 65 bytes encoding if point is not identity:
    ///         [0x04 prefix][32 bytes x coordinate][32 bytes y coordinate]
    ///
    ///      Provides single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function toEncoded(Point memory point)
        internal
        pure
        returns (bytes memory blob)
    {
        if (!point.isOnCurve()) {
            revert Errors.CRYSOL_PointNotOnCurve();
        }

        // Note to catch special encoding for identity.
        if (point.isIdentity()) {
            return bytes(hex"00");
        }

        return
            abi.encodePacked(bytes1(0x04), point.x.asUint(), point.y.asUint());
    }

    /// @dev Decodes point from [SEC-1 v2] compressed encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///          Blob not 0x00
    ///        ∧ Length not 33 bytes
    ///          ∨ Prefix byte not one in [0x02, 0x03]
    ///      ∨ Deserialized point not on curve
    ///
    /// @dev Expects compressed 33 bytes encoding if point is not identity:
    ///         [0x02 or 0x03 prefix][32 bytes x coordinate]
    ///
    ///      Expects single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function pointFromCompressedEncoded(bytes memory blob)
        internal
        view
        returns (Point memory)
    {
        // Note to catch special encoding for identity.
        if (blob.length == 1 && bytes1(blob) == bytes1(0x00)) {
            return Identity();
        }

        // Revert if length not 33.
        if (blob.length != 33) {
            revert Errors.CRYSOL_LengthInvalid();
        }

        // Read prefix byte.
        uint prefix;
        assembly ("memory-safe") {
            prefix := byte(0, mload(add(blob, 0x20)))
        }

        // Revert if prefix not 0x02 or 0x03.
        if (prefix != 0x02 && prefix != 0x03) {
            revert Errors.CRYSOL_PrefixInvalid();
        }

        // Read x coordinate.
        uint xRaw;
        assembly ("memory-safe") {
            xRaw := mload(add(blob, 0x21))
        }

        // Revert if identity not 1 byte encoded.
        // TODO: Should have own error for identity not 1 byte encoded?
        //
        // Note that identity is explicitly enforced to be 1 byte encoded,
        // eventhough for x = 0 the resulting point is not on the curve anyway.
        if (xRaw == 0) {
            revert Errors.CRYSOL_PointNotOnCurve();
        }

        // Construct x coordinate as felt.
        bool ok;
        Felt x;
        (x, ok) = Fp.tryFromUint(xRaw);
        if (!ok) {
            revert Errors.CRYSOL_PointNotOnCurve();
        }

        // Compute α = x³ + ax + b (mod p).
        // Note that adding a * x can be waived as ∀x: a * x = 0.
        // forgefmt: disable-next-item
        Felt alpha = x.mul(x)
                      .mul(x)
                      .add(Fp.unsafeFromUint(B));

        // Compute β = √α              (mod p)
        //           = α^{(p + 1) / 4} (mod p)
        Felt beta = alpha.exp(Fp.unsafeFromUint(_SQUARE_ROOT_EXPONENT));

        // Compute y coordinate.
        //
        // Note that y = β if β ≡ prefix (mod 2) else p - β.
        uint yRaw;
        unchecked {
            yRaw = beta.asUint() & 1 == prefix & 1
                ? beta.asUint()
                : P - beta.asUint();
        }

        // Construct y coordiante as felt.
        // Note that y coordinate is guaranteed to be a valid felt.
        Felt y = Fp.unsafeFromUint(yRaw);

        // Construct point from felt coordinates.
        Point memory point = Point(x, y);

        // Revert if point not on curve.
        // TODO: Find vectors for x coordinates not on the curve.
        if (!point.isOnCurve()) {
            revert Errors.CRYSOL_PointNotOnCurve();
        }

        return point;
    }

    /// @dev Encodes point `point` as [SEC-1 v2] compressed encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Point not on curve
    ///
    /// @dev Provides compressed 33 bytes encoding if point is not identity:
    ///         [0x02 or 0x03 prefix][32 bytes x coordinate]
    ///
    ///      Provides single zero byte encoding if point is identity:
    ///         [0x00]
    ///
    ///      See [SEC-1 v2] section 2.3.3 "Elliptic-Curve-Point-to-Octet-String".
    function toCompressedEncoded(Point memory point)
        internal
        pure
        returns (bytes memory blob)
    {
        if (!point.isOnCurve()) {
            revert Errors.CRYSOL_PointNotOnCurve();
        }

        // Note to catch special encoding for identity.
        if (point.isIdentity()) {
            return bytes(hex"00");
        }

        bytes1 prefix = point.yParity() == 0 ? bytes1(0x02) : bytes1(0x03);

        return abi.encodePacked(prefix, point.x.asUint());
    }
}
