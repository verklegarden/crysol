// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "src/curves/Secp256k1Arithmetic.sol";

/**
 * @notice Secp256k1 Unit Tests
 */
contract Secp256k1Test is Test {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    // Uncompressed Generator G.
    // Copied from [Sec 2 v2].
    bytes constant GENERATOR_ENCODED_UNCOMPRESSED =
        hex"0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    Secp256k1Wrapper wrapper;

    function setUp() public {
        wrapper = new Secp256k1Wrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Constants

    function test_G() public {
        PublicKey memory got = wrapper.G();
        PublicKey memory want =
            Secp256k1.publicKeyFromEncoded(GENERATOR_ENCODED_UNCOMPRESSED);

        assertEq(got.x, want.x);
        assertEq(got.y, want.y);
    }

    //--------------------------------------------------------------------------
    // Test: Secret Key

    // -- newSecretKey

    function test_newSecretKey() public {
        SecretKey sk = wrapper.newSecretKey();

        assertTrue(sk.isValid());

        // Verify vm can create wallet from secret key.
        vm.createWallet(sk.asUint());
    }

    // -- isValid

    function testFuzz_SecretKey_isValid(uint seed) public {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        assertTrue(wrapper.isValid(SecretKey.wrap(scalar)));
    }

    function test_SecretKey_isValid_FailsIf_SecertKeyIsZero() public {
        assertFalse(wrapper.isValid(SecretKey.wrap(0)));
    }

    function testFuzz_SecretKey_isValid_FailsIf_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        assertFalse(wrapper.isValid(SecretKey.wrap(scalar)));
    }

    // -- toPublicKey

    function testFuzz_SecretKey_toPublicKey(uint seed) public {
        SecretKey sk =
            Secp256k1.secretKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        address got = wrapper.toPublicKey(sk).toAddress();
        address want = vm.addr(sk.asUint());

        assertEq(got, want);
    }

    function testFuzz_SecretKey_toPublicKey_RevertsIf_SecretKeyInvalid(
        uint seed
    ) public {
        SecretKey sk = SecretKey.wrap(_bound(seed, Secp256k1.Q, type(uint).max));

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.toPublicKey(sk);
    }

    //--------------------------------------------------------------------------
    // Test: Public Key

    // -- toAddress

    function testFuzz_PublicKey_toAddress(uint seed) public {
        SecretKey sk =
            Secp256k1.secretKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        address got = wrapper.toAddress(Secp256k1.toPublicKey(sk));
        address want = vm.addr(sk.asUint());

        assertEq(got, want);
    }

    // -- toHash

    function testFuzz_PublicKey_toHash(PublicKey memory pk) public {
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

    function test_PublicKey_isValid_If_Identity() public {
        PublicKey memory pk = Secp256k1Arithmetic.Identity().intoPublicKey();

        assertTrue(pk.isValid());
    }

    function test_PublicKey_isValid_FailsIf_PointNotOnCurve() public {
        PublicKey memory pk;

        // Zero point not on curve.
        pk.x = 0;
        pk.y = 0;
        assertFalse(wrapper.isValid(pk));

        // Some other points.
        pk.x = 1;
        pk.x = 3;
        assertFalse(wrapper.isValid(pk));
        // TODO: Test PublicKey.isValid(): Add more points.
    }

    // -- yParity

    function testFuzz_PublicKey_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(PublicKey(x, y));

        assertEq(want, got);
    }

    // -- intoPoint

    // @todo Add no memory expansion tests for `into__()` functions.
    //       Must directly use library, not wrapper.

    function testFuzz_PublicKey_intoPoint(PublicKey memory pk) public {
        Point memory point = wrapper.intoPoint(pk);

        assertEq(point.x, pk.x);
        assertEq(point.y, pk.y);
    }

    function testFuzz_Point_intoPublicKey(Point memory point) public {
        PublicKey memory pk = wrapper.intoPublicKey(point);

        assertEq(pk.x, point.x);
        assertEq(pk.y, point.y);
    }

    function testFuzz_PublicKey_toProjectivePoint(PublicKey memory pk)
        public
    {
        ProjectivePoint memory jPoint = wrapper.toProjectivePoint(pk);

        assertEq(jPoint.x, pk.x);
        assertEq(jPoint.y, pk.y);
        assertEq(jPoint.z, 1);
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

/*

    //----------------------------------
    // Private Key

    // TODO: This is not serde.
    // -- privateKeyFromUint

    function testFuzz_privateKeyFromUint(uint seed) public {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        PrivateKey privKey = wrapper.privateKeyFromUint(scalar);

        assertEq(privKey.asUint(), scalar);
        assertTrue(privKey.isValid());
    }

    function testFuzz_privateKeyFromUint_RevertsIf_ScalarZero() public {
        vm.expectRevert("InvalidScalar()");
        wrapper.privateKeyFromUint(0);
    }

    function testFuzz_privateKeyFromUint_RevertsIf_ScalarGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        vm.expectRevert("InvalidScalar()");
        wrapper.privateKeyFromUint(scalar);
    }

    // -- asUint

    function testFuzz_PrivateKey_asUint(uint seed) public {
        assertEq(seed, wrapper.asUint(PrivateKey.wrap(seed)));
    }

    // -- privateKeyFromBytes

    function testFuzz_privateKeyFromBytes(uint seed) public {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        PrivateKey privKey =
            wrapper.privateKeyFromBytes(abi.encodePacked(scalar));

        assertTrue(privKey.isValid());
        assertEq(privKey.asUint(), scalar);
    }

    function testFuzz_privateKeyFromBytes_RevertsIf_LengthNot32Bytes(
        bytes memory seed
    ) public {
        vm.assume(seed.length != 32);

        vm.expectRevert("InvalidLength()");
        wrapper.privateKeyFromBytes(seed);
    }

    function testFuzz_privateKeyFromBytes_RevertsIf_DeserializedScalarInvalid(
        uint seed
    ) public {
        uint scalar =
            seed == 0 ? seed : _bound(seed, Secp256k1.Q, type(uint).max);

        vm.expectRevert("InvalidScalar()");
        wrapper.privateKeyFromBytes(abi.encodePacked(scalar));
    }

    // -- toBytes

    function testFuzz_PrivateKey_toBytes(PrivateKey privKey) public {
        vm.assume(privKey.isValid());

        assertEq(
            privKey.asUint(),
            wrapper.privateKeyFromBytes(wrapper.toBytes(privKey)).asUint()
        );
    }

    //----------------------------------
    // Public Key

    // -- publicKeyFromBytes

    function testFuzz_publicKeyFromBytes(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        PublicKey memory pubKey = privKey.toPublicKey();

        address want = pubKey.toAddress();
        address got = wrapper.publicKeyFromBytes(pubKey.toBytes()).toAddress();

        assertEq(want, got);
    }

    function test_publicKeyFromBytes_ViaGenerator() public {
        PublicKey memory want = Secp256k1.G();
        PublicKey memory got =
            wrapper.publicKeyFromBytes(GENERATOR_BYTES_UNCOMPRESSED);

        assertEq(want.toAddress(), got.toAddress());
    }

    function testFuzz_publicKeyFromBytes_RevertsIf_LengthNot65Bytes(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 65);

        vm.expectRevert("InvalidLength()");
        wrapper.publicKeyFromBytes(blob);
    }

    function testFuzz_publicKeyFromBytes_RevertsIf_PrefixByteNot0x04(
        bytes1 prefix
    ) public {
        vm.assume(prefix != bytes1(0x04));

        bytes memory blob = abi.encodePacked(prefix, bytes32(""), bytes32(""));

        vm.expectRevert("InvalidPrefix()");
        wrapper.publicKeyFromBytes(blob);
    }

    function testFuzz_publicKeyFromBytes_RevertsIf_DeserializedPublicKeyInvalid(
        PublicKey memory pubKey
    ) public {
        vm.assume(!pubKey.isValid());

        vm.expectRevert("InvalidPublicKey()");
        wrapper.publicKeyFromBytes(pubKey.toBytes());
    }

    // -- toBytes

    function testFuzz_PublicKey_toBytes(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        PublicKey memory pubKey = privKey.toPublicKey();

        address want = pubKey.toAddress();
        address got =
            Secp256k1.publicKeyFromBytes(wrapper.toBytes(pubKey)).toAddress();

        assertEq(want, got);
    }

    function test_PublicKey_asBytes_ViaGenerator() public {
        assertEq(GENERATOR_BYTES_UNCOMPRESSED, wrapper.toBytes(Secp256k1.G()));
    }
*/

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

    using Secp256k1Arithmetic for Point;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (PublicKey memory) {
        return Secp256k1.G();
    }

    //--------------------------------------------------------------------------
    // Secret Key

    function newSecretKey() public returns (SecretKey) {
        return Secp256k1.newSecretKey();
    }

    function isValid(SecretKey sk) public pure returns (bool) {
        return sk.isValid();
    }

    function toPublicKey(SecretKey sk)
        public
        returns (PublicKey memory)
    {
        return sk.toPublicKey();
    }

    function secretKeyFromUint(uint scalar) public pure returns (SecretKey) {
        return Secp256k1.secretKeyFromUint(scalar);
    }

    function asUint(SecretKey sk) public pure returns (uint) {
        return sk.asUint();
    }

    //--------------------------------------------------------------------------
    // Public Key

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

    function toBytes(PublicKey memory pk)
        public
        pure
        returns (bytes memory)
    {
        return pk.toBytes();
    }
}
