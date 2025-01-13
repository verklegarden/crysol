// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";
import {Points, Point, ProjectivePoint} from "src/arithmetic/Points.sol";
import {Fp, Felt} from "src/arithmetic/Fp.sol";

import "src/Errors.sol" as Errors;

/**
 * @notice Secp256k1 Unit Tests
 */
contract Secp256k1Test is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;
    using Points for Point;
    using Points for ProjectivePoint;
    using Fp for Felt;

    // Uncompressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_ENCODED =
        hex"0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    Secp256k1Wrapper wrapper;

    function setUp() public {
        wrapper = new Secp256k1Wrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Constants

    function test_G() public view {
        PublicKey memory got = wrapper.G();
        PublicKey memory want =
            Points.pointFromEncoded(GENERATOR_ENCODED).intoPublicKey();

        assertTrue(got.eq(want));
    }

    //--------------------------------------------------------------------------
    // Test: Secret Key

    // -- trySecretKeyFromUint

    function testFuzz_trySecretKeyFromUint(uint seed) public view {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        (SecretKey sk, bool ok) = wrapper.trySecretKeyFromUint(scalar);
        assertTrue(ok);
        assertTrue(sk.isValid());

        assertEq(sk.asUint(), scalar);
    }

    function test_trySecretKeyFromUint_FailsIf_ScalarZero() public view {
        (, bool ok) = wrapper.trySecretKeyFromUint(0);
        assertFalse(ok);
    }

    function test_trySecretKeyFromUint_FailsIf_ScalarGreaterOrEqualToQ(
        uint seed
    ) public view {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        (, bool ok) = wrapper.trySecretKeyFromUint(scalar);
        assertFalse(ok);
    }

    // -- secretKeyFromUint

    function testFuzz_secretKeyFromUint(uint seed) public view {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        SecretKey sk = wrapper.secretKeyFromUint(scalar);

        assertTrue(sk.isValid());
        assertEq(sk.asUint(), scalar);
    }

    function test_secretKeyFromUint_RevertsIf_ScalarZero() public {
        vm.expectRevert(Errors.CRYSOL_ScalarInvalid.selector);
        wrapper.secretKeyFromUint(0);
    }

    function test_secretKeyFromUint_RevertsIf_ScalarGreaterOrEqualToQ(uint seed)
        public
    {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        vm.expectRevert(Errors.CRYSOL_ScalarInvalid.selector);
        wrapper.secretKeyFromUint(scalar);
    }

    // -- unsafeSecretKeyFromUint

    function testFuzz_unsafeSecretKeyFromUint(uint scalar) public view {
        SecretKey sk = wrapper.unsafeSecretKeyFromUint(scalar);

        assertEq(sk.asUint(), scalar);
    }

    // -- asUint

    function testFuzz_SecretKey_asUint(uint scalar) public view {
        assertEq(
            scalar, wrapper.asUint(Secp256k1.unsafeSecretKeyFromUint(scalar))
        );
    }

    // -- isValid

    function testFuzz_SecretKey_isValid(uint seed) public view {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        assertTrue(wrapper.isValid(Secp256k1.unsafeSecretKeyFromUint(scalar)));
    }

    function test_SecretKey_isValid_FailsIf_SecretKeyIsZero() public view {
        assertFalse(wrapper.isValid(Secp256k1.unsafeSecretKeyFromUint(0)));
    }

    function testFuzz_SecretKey_isValid_FailsIf_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public view {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        assertFalse(wrapper.isValid(Secp256k1.unsafeSecretKeyFromUint(scalar)));
    }

    // -- toAddress

    function testFuzz_SecretKey_toAddress(SecretKey sk) public view {
        vm.assume(sk.isValid());

        address got = wrapper.toAddress(sk);
        address want = vm.addr(sk.asUint());

        assertEq(got, want);
    }

    function test_SecretKey_toAddress_RevertsIf_SecretKeyInvalid_SecretKeyZero()
        public
    {
        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.toAddress(Secp256k1.unsafeSecretKeyFromUint(0));
    }

    function testFuzz_SecretKey_toAddress_RevertsIf_SecretKeyInvalid_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.toAddress(Secp256k1.unsafeSecretKeyFromUint(scalar));
    }

    //--------------------------------------------------------------------------
    // Test: Public Key

    // -- tryPublicKeyFromFelts

    function testFuzz_tryPublicKeyFromFelts(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory want = sk.toPublicKey();
        (PublicKey memory got, bool ok) =
            wrapper.tryPublicKeyFromFelts(want.x, want.y);
        assertTrue(ok);
        assertTrue(want.eq(got));
    }

    function testFuzz_tryPublicKeyFromFelts_FailsIf_PublicKeyInvalid_XCoordinateInvalidFelt(
        uint xSeed,
        Felt y
    ) public view {
        vm.assume(y.isValid());

        Felt x = Fp.unsafeFromUint(_bound(xSeed, Secp256k1.P, type(uint).max));

        (, bool ok) = wrapper.tryPublicKeyFromFelts(x, y);
        assertFalse(ok);
    }

    function testFuzz_tryPublicKeyFromFelts_FailsIf_PublicKeyInvalid_YCoordinateInvalidFelt(
        Felt x,
        uint ySeed
    ) public view {
        vm.assume(x.isValid());

        Felt y = Fp.unsafeFromUint(_bound(ySeed, Secp256k1.P, type(uint).max));

        (, bool ok) = wrapper.tryPublicKeyFromFelts(x, y);
        assertFalse(ok);
    }

    function testFuzz_tryPublicKeyFromFelts_FailsIf_PublicKeyInvalid_NotOnCurve(
        Felt x,
        Felt y
    ) public view {
        Point memory p = Point(x, y);
        vm.assume(!p.isOnCurve());

        (, bool ok) = wrapper.tryPublicKeyFromFelts(x, y);
        assertFalse(ok);
    }

    function test_tryPublicKeyFromFelts_FailsIf_PublicKeyInvalid_Identity()
        public
        view
    {
        Point memory id = Points.Identity();

        (, bool ok) = wrapper.tryPublicKeyFromFelts(id.x, id.y);
        assertFalse(ok);
    }

    // -- publicKeyFromFelts

    function testFuzz_publicKeyFromFelts(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory want = sk.toPublicKey();
        PublicKey memory got = wrapper.publicKeyFromFelts(want.x, want.y);
        assertTrue(want.eq(got));
    }

    function testFuzz_publicKeyFromFelts_RevertsIf_PublicKeyInvalid_XCoordinateInvalidFelt(
        uint xSeed,
        Felt y
    ) public {
        vm.assume(y.isValid());

        Felt x = Fp.unsafeFromUint(_bound(xSeed, Secp256k1.P, type(uint).max));

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromFelts(x, y);
    }

    function testFuzz_publicKeyFromFelts_RevertsIf_PublicKeyInvalid_YCoordinateInvalidFelt(
        Felt x,
        uint ySeed
    ) public {
        vm.assume(x.isValid());

        Felt y = Fp.unsafeFromUint(_bound(ySeed, Secp256k1.P, type(uint).max));

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromFelts(x, y);
    }

    function testFuzz_publicKeyFromFelts_FailsIf_PublicKeyInvalid_NotOnCurve(
        Felt x,
        Felt y
    ) public {
        Point memory p = Point(x, y);
        vm.assume(!p.isOnCurve());

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromFelts(x, y);
    }

    function test_publicKeyFromFelts_RevertsIf_PublicKeyInvalid_Identity()
        public
    {
        Point memory id = Points.Identity();

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromFelts(id.x, id.y);
    }

    // -- unsafePublicKeyFromFelts

    function testFuzz_unsafePublicKeyFromFelts(Felt x, Felt y) public view {
        PublicKey memory pk = wrapper.unsafePublicKeyFromFelts(x, y);
        assertEq(pk.x.asUint(), x.asUint());
        assertEq(pk.y.asUint(), y.asUint());
    }

    // -- tryPublicKeyFromUints

    function testFuzz_tryPublicKeyFromUints(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pk = sk.toPublicKey();
        uint x = pk.x.asUint();
        uint y = pk.y.asUint();

        PublicKey memory want = pk;
        (PublicKey memory got, bool ok) = wrapper.tryPublicKeyFromUints(x, y);
        assertTrue(ok);
        assertTrue(want.eq(got));
    }

    function testFuzz_tryPublicKeyFromUints_FailsIf_PointInvalid_XCoordinateNotAFelt(
        uint x,
        uint y
    ) public view {
        vm.assume(x >= Secp256k1.P);
        vm.assume(y < Secp256k1.P);

        (, bool ok) = wrapper.tryPublicKeyFromUints(x, y);
        assertFalse(ok);
    }

    function testFuzz_tryPublicKeyFromUints_FailsIf_PointInvalid_YCoordinateNotAFelt(
        uint x,
        uint y
    ) public view {
        vm.assume(x < Secp256k1.P);
        vm.assume(y >= Secp256k1.P);

        (, bool ok) = wrapper.tryPublicKeyFromUints(x, y);
        assertFalse(ok);
    }

    function testFuzz_tryPublicKeyFromUints_FailsIf_PointInvalid_NotOnCurve(
        Felt x,
        Felt y
    ) public view {
        Point memory p = Point(x, y);
        vm.assume(!p.isOnCurve());

        (, bool ok) = wrapper.tryPublicKeyFromUints(x.asUint(), y.asUint());
        assertFalse(ok);
    }

    function test_tryPublicKeyFromUints_FailsIf_PointInvalid_Identity()
        public
        view
    {
        Point memory id = Points.Identity();
        uint x = id.x.asUint();
        uint y = id.y.asUint();

        (, bool ok) = wrapper.tryPublicKeyFromUints(x, y);
        assertFalse(ok);
    }

    // -- publicKeyFromUints

    function testFuzz_publicKeyFromUints(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pk = sk.toPublicKey();
        uint x = pk.x.asUint();
        uint y = pk.y.asUint();

        PublicKey memory want = pk;
        PublicKey memory got = wrapper.publicKeyFromUints(x, y);
        assertTrue(want.eq(got));
    }

    function testFuzz_publicKeyFromUints_FailsIf_PointInvalid_XCoordinateNotAFelt(
        uint x,
        uint y
    ) public {
        vm.assume(x >= Secp256k1.P);
        vm.assume(y < Secp256k1.P);

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromUints(x, y);
    }

    function testFuzz_publicKeyFromUints_FailsIf_PointInvalid_YCoordinateNotAFelt(
        uint x,
        uint y
    ) public {
        vm.assume(x < Secp256k1.P);
        vm.assume(y >= Secp256k1.P);

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromUints(x, y);
    }

    function testFuzz_publicKeyFromUints_FailsIf_PointInvalid_NotOnCurve(
        Felt x,
        Felt y
    ) public {
        Point memory p = Point(x, y);
        vm.assume(!p.isOnCurve());

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromUints(x.asUint(), y.asUint());
    }

    function test_publicKeyFromUints_FailsIf_PointInvalid_Identity() public {
        Point memory id = Points.Identity();
        uint x = id.x.asUint();
        uint y = id.y.asUint();

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromUints(x, y);
    }

    // -- unsafePublicKeyFromUints

    function testFuzz_unsafePublicKeyFromUints(uint x, uint y) public view {
        PublicKey memory pk = wrapper.unsafePublicKeyFromUints(x, y);
        assertEq(pk.x.asUint(), x);
        assertEq(pk.y.asUint(), y);
    }

    // -- toAddress

    function testFuzz_PublicKey_toAddress(uint seed) public {
        SecretKey sk =
            Secp256k1.secretKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        address got = wrapper.toAddress(sk.toPublicKey());
        address want = vm.addr(sk.asUint());

        assertEq(got, want);
    }

    // -- toHash

    function testFuzz_PublicKey_toHash(PublicKey memory pk) public view {
        bytes32 got = wrapper.toHash(pk);
        bytes32 want = keccak256(abi.encodePacked(pk.x, pk.y));

        assertEq(got, want);
    }

    // -- isValid

    function testFuzz_PublicKey_isValid_If_CreatedViaValidSecretKey(uint seed)
        public
    {
        SecretKey sk =
            Secp256k1.secretKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        // Every public key created via valid secret key is valid.
        assertTrue(wrapper.isValid(sk.toPublicKey()));
    }

    function test_PublicKey_isValid_FailsIf_Identity() public view {
        PublicKey memory pk = Points.Identity().intoPublicKey();

        assertFalse(wrapper.isValid(pk));
    }

    function test_PublicKey_isValid_FailsIf_PointNotOnCurve() public view {
        PublicKey memory pk;

        pk.x = Fp.unsafeFromUint(1);
        pk.x = Fp.unsafeFromUint(3);
        assertFalse(wrapper.isValid(pk));
    }

    // -- yParity

    function testFuzz_PublicKey_yParity(uint x, uint y) public view {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(Secp256k1.unsafePublicKeyFromUints(x, y));

        assertEq(want, got);
    }

    // -- eq

    function testFuzz_PublicKey_eq(PublicKey memory pk1, PublicKey memory pk2)
        public
        view
    {
        bool want =
            pk1.x.asUint() == pk2.x.asUint() && pk1.y.asUint() == pk2.y.asUint();
        bool got = wrapper.eq(pk1, pk2);

        assertEq(want, got);
    }

    // -- intoPoint

    // TODO: Add no memory expansion tests for `into__()` functions.
    //       Must directly use library, not wrapper.

    function testFuzz_PublicKey_intoPoint(PublicKey memory pk) public view {
        Point memory point = wrapper.intoPoint(pk);

        assertEq(point.x.asUint(), pk.x.asUint());
        assertEq(point.y.asUint(), pk.y.asUint());
    }

    // -- Point::intoPublicKey

    function testFuzz_Point_intoPublicKey(Point memory point) public view {
        PublicKey memory pk = wrapper.intoPublicKey(point);

        assertEq(point.x.asUint(), pk.x.asUint());
        assertEq(point.y.asUint(), pk.y.asUint());
    }

    // -- toProjectivePoint

    function testFuzz_PublicKey_toProjectivePoint(PublicKey memory pk)
        public
        view
    {
        ProjectivePoint memory point = wrapper.toProjectivePoint(pk);

        if (pk.intoPoint().isIdentity()) {
            assertTrue(point.isIdentity());
        } else {
            assertEq(point.x.asUint(), pk.x.asUint());
            assertEq(point.y.asUint(), pk.y.asUint());
            assertEq(point.z.asUint(), 1);
        }
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    //----------------------------------
    // Secret Key

    // -- SecretKey <-> Bytes

    function testFuzz_secretKeyFromBytes(SecretKey sk1) public view {
        vm.assume(sk1.isValid());

        bytes memory blob = abi.encodePacked(sk1.asUint());

        SecretKey sk2 = wrapper.secretKeyFromBytes(blob);

        assertEq(sk1.asUint(), sk2.asUint());
    }

    function testFuzz_secretKeyFromBytes_RevertsIf_LengthNot32Bytes(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 32);

        vm.expectRevert(Errors.CRYSOL_LengthInvalid.selector);
        wrapper.secretKeyFromBytes(blob);
    }

    function test_secretKeyFromBytes_RevertsIf_DeserializedSecretKeyInvalid_SecretKeyZero(
    ) public {
        bytes memory blob = abi.encodePacked(uint(0));

        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.secretKeyFromBytes(blob);
    }

    function testFuzz_secretKeyFromBytes_RevertsIf_DeserializedSecretKeyInvalid_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        bytes memory blob = abi.encodePacked(scalar);

        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.secretKeyFromBytes(blob);
    }

    function testFuzz_SecretKey_toBytes(SecretKey sk) public view {
        vm.assume(sk.isValid());

        bytes memory blob = wrapper.toBytes(sk);

        assertEq(sk.asUint(), Secp256k1.secretKeyFromBytes(blob).asUint());
    }

    function test_SecretKey_toBytes_RevertsIf_SecretKeyInvalid_SecretKeyZero()
        public
    {
        SecretKey sk = Secp256k1.unsafeSecretKeyFromUint(0);

        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.toBytes(sk);
    }

    function testFuzz_SecretKey_toBytes_RevertsIf_SecretKeyInvalid_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);
        SecretKey sk = Secp256k1.unsafeSecretKeyFromUint(scalar);

        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.toBytes(sk);
    }

    //----------------------------------
    // Public Key

    // -- PublicKey <-> Bytes

    // TODO: PublicKey <-> Bytes: Need test vectors.
    function testFuzz_publicKeyFromBytes(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pk1 = sk.toPublicKey();
        bytes memory blob = pk1.toBytes();

        PublicKey memory pk2 = wrapper.publicKeyFromBytes(blob);

        assertTrue(pk1.eq(pk2));
    }

    function testFuzz_publicKeyFromBytes_RevertsIf_LengthNot64Bytes(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 64);

        vm.expectRevert(Errors.CRYSOL_LengthInvalid.selector);
        wrapper.publicKeyFromBytes(blob);
    }

    function testFuzz_publicKeyFromBytes_RevertsIf_DeserializedPublicKeyInvalid(
        PublicKey memory pk
    ) public {
        vm.assume(!pk.isValid());

        bytes memory blob = abi.encodePacked(pk.x, pk.y);

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.publicKeyFromBytes(blob);
    }

    function testFuzz_PublicKey_toBytes(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pk1 = sk.toPublicKey();

        bytes memory blob = wrapper.toBytes(pk1);
        assertEq(blob.length, 64);

        PublicKey memory pk2 = Secp256k1.publicKeyFromBytes(blob);
        assertTrue(pk1.eq(pk2));
    }

    function testFuzz_PublicKey_toBytes_RevertsIf_PublicKeyInvalid(
        PublicKey memory pk
    ) public {
        vm.assume(!pk.isValid());

        vm.expectRevert(Errors.CRYSOL_PublicKeyInvalid.selector);
        wrapper.toBytes(pk);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256k1Wrapper {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using Points for Point;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (PublicKey memory) {
        return Secp256k1.G();
    }

    //--------------------------------------------------------------------------
    // Secret Key

    function isValid(SecretKey sk) public pure returns (bool) {
        return sk.isValid();
    }

    function trySecretKeyFromUint(uint scalar)
        public
        pure
        returns (SecretKey, bool)
    {
        return Secp256k1.trySecretKeyFromUint(scalar);
    }

    function secretKeyFromUint(uint scalar) public pure returns (SecretKey) {
        return Secp256k1.secretKeyFromUint(scalar);
    }

    function unsafeSecretKeyFromUint(uint scalar)
        public
        pure
        returns (SecretKey)
    {
        return Secp256k1.unsafeSecretKeyFromUint(scalar);
    }

    function asUint(SecretKey sk) public pure returns (uint) {
        return sk.asUint();
    }

    function toAddress(SecretKey sk) public pure returns (address) {
        return sk.toAddress();
    }

    //--------------------------------------------------------------------------
    // Public Key

    function tryPublicKeyFromFelts(Felt x, Felt y)
        public
        pure
        returns (PublicKey memory, bool)
    {
        return Secp256k1.tryPublicKeyFromFelts(x, y);
    }

    function publicKeyFromFelts(Felt x, Felt y)
        public
        pure
        returns (PublicKey memory)
    {
        return Secp256k1.publicKeyFromFelts(x, y);
    }

    function unsafePublicKeyFromFelts(Felt x, Felt y)
        public
        pure
        returns (PublicKey memory)
    {
        return Secp256k1.unsafePublicKeyFromFelts(x, y);
    }

    function tryPublicKeyFromUints(uint x, uint y)
        public
        pure
        returns (PublicKey memory, bool)
    {
        return Secp256k1.tryPublicKeyFromUints(x, y);
    }

    function publicKeyFromUints(uint x, uint y)
        public
        pure
        returns (PublicKey memory)
    {
        return Secp256k1.publicKeyFromUints(x, y);
    }

    function unsafePublicKeyFromUints(uint x, uint y)
        public
        pure
        returns (PublicKey memory)
    {
        return Secp256k1.unsafePublicKeyFromUints(x, y);
    }

    function toAddress(PublicKey memory pk) public pure returns (address) {
        return pk.toAddress();
    }

    function toHash(PublicKey memory pk) public pure returns (bytes32) {
        return pk.toHash();
    }

    function isValid(PublicKey memory pk) public pure returns (bool) {
        return pk.isValid();
    }

    function yParity(PublicKey memory pk) public pure returns (uint) {
        return pk.yParity();
    }

    function eq(PublicKey memory pk, PublicKey memory other)
        public
        pure
        returns (bool)
    {
        return pk.eq(other);
    }

    function intoPoint(PublicKey memory pk)
        public
        pure
        returns (Point memory)
    {
        return pk.intoPoint();
    }

    function intoPublicKey(Point memory point)
        public
        pure
        returns (PublicKey memory)
    {
        return point.intoPublicKey();
    }

    function toProjectivePoint(PublicKey memory pk)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return pk.toProjectivePoint();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Secret Key

    function secretKeyFromBytes(bytes memory blob)
        public
        pure
        returns (SecretKey)
    {
        return Secp256k1.secretKeyFromBytes(blob);
    }

    function toBytes(SecretKey sk) public pure returns (bytes memory) {
        return sk.toBytes();
    }

    //----------------------------------
    // Public Key

    function publicKeyFromBytes(bytes memory blob)
        public
        pure
        returns (PublicKey memory)
    {
        return Secp256k1.publicKeyFromBytes(blob);
    }

    function toBytes(PublicKey memory pk) public pure returns (bytes memory) {
        return pk.toBytes();
    }
}
