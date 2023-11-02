// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    AffinePoint,
    JacobianPoint
} from "src/curves/Secp256k1Arithmetic.sol";

import {Secp256k1Wrapper} from "./Secp256k1Wrapper.sol";

contract Secp256k1Test is Test {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    // Uncompressed Generator G.
    // Copied from [Sec 2 v2].
    bytes constant GENERATOR_BYTES_UNCOMPRESSED =
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
            Secp256k1.publicKeyFromBytes(GENERATOR_BYTES_UNCOMPRESSED);

        assertEq(got.x, want.x);
        assertEq(got.y, want.y);
    }

    //--------------------------------------------------------------------------
    // Test: Private Key

    // -- newPrivateKey

    function test_newPrivateKey() public {
        PrivateKey privKey = wrapper.newPrivateKey();

        assertTrue(privKey.isValid());

        // Verify vm can create wallet from private key.
        vm.createWallet(privKey.asUint());
    }

    // -- isValid

    function testFuzz_PrivateKey_isValid(uint seed) public {
        uint privKey = _bound(seed, 1, Secp256k1.Q - 1);

        assertTrue(wrapper.isValid(PrivateKey.wrap(privKey)));
    }

    function test_PrivateKey_isValid_FalseIf_PrivateKeyIsZero() public {
        assertFalse(wrapper.isValid(PrivateKey.wrap(0)));
    }

    function testFuzz_PrivateKey_isValid_FalseIf_PrivateKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint privKey = _bound(seed, Secp256k1.Q, type(uint).max);

        assertFalse(wrapper.isValid(PrivateKey.wrap(privKey)));
    }

    // -- toPublicKey

    function testFuzz_PrivateKey_toPublicKey(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        address got = wrapper.toPublicKey(privKey).toAddress();
        address want = vm.addr(privKey.asUint());

        assertEq(got, want);
    }

    function testFuzz_PrivateKey_toPublicKey_RevertsIf_PrivateKeyInvalid(
        uint seed
    ) public {
        PrivateKey privKey =
            PrivateKey.wrap(_bound(seed, Secp256k1.Q, type(uint).max));

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.toPublicKey(privKey);
    }

    //--------------------------------------------------------------------------
    // Test: Public Key

    // -- toAddress

    function testFuzz_PublicKey_toAddress(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        assertEq(
            wrapper.toAddress(Secp256k1.toPublicKey(privKey)),
            vm.addr(privKey.asUint())
        );
    }

    // -- toHash

    function testFuzz_PublicKey_toHash(PublicKey memory pubKey) public {
        bytes32 got = wrapper.toHash(pubKey);
        bytes32 want = keccak256(abi.encodePacked(pubKey.x, pubKey.y));

        assertEq(got, want);
    }

    // -- isValid

    function testFuzz_PublicKey_isValid(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        // Every public key created via valid private key is valid.
        assertTrue(wrapper.isValid(privKey.toPublicKey()));
    }

    function test_PublicKey_isValid_FalseIf_PointNotOnCurve() public {
        PublicKey memory pubKey;

        pubKey.x = 0;
        pubKey.y = 0;
        assertFalse(wrapper.isValid(pubKey));

        pubKey.x = 1;
        pubKey.x = 3;
        assertFalse(wrapper.isValid(pubKey));

        pubKey.x = type(uint).max;
        pubKey.x = type(uint).max;
        assertFalse(wrapper.isValid(pubKey));
    }

    // -- yParity

    function testFuzz_PublicKey_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(PublicKey(x, y));

        assertEq(want, got);
    }

    // -- intoAffinePoint

    // @todo Add no memory expansion tests for `into__()` functions.
    //       Must directly use library, not wrapper.

    function testFuzz_PublicKey_intoAffinePoint(PublicKey memory pubKey)
        public
    {
        AffinePoint memory point = wrapper.intoAffinePoint(pubKey);

        assertEq(point.x, pubKey.x);
        assertEq(point.y, pubKey.y);
    }

    function testFuzz_AffinePoint_intoPublicKey(AffinePoint memory point)
        public
    {
        PublicKey memory pubKey = wrapper.intoPublicKey(point);

        assertEq(pubKey.x, point.x);
        assertEq(pubKey.y, point.y);
    }

    function testFuzz_PublicKey_toJacobianPoint(PublicKey memory pubKey)
        public
    {
        JacobianPoint memory jacPoint = wrapper.toJacobianPoint(pubKey);

        assertEq(jacPoint.x, pubKey.x);
        assertEq(jacPoint.y, pubKey.y);
        assertEq(jacPoint.z, 1);
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    //----------------------------------
    // Private Key

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
}
