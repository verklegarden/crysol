// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";

import {ECDSAOffchain} from "offchain/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/signatures/ECDSA.sol";
import {ECDSAUnsafe} from "unsafe/signatures/ECDSAUnsafe.sol";

/**
 * @notice ECDSA Unit Tests
 */
contract ECDSATest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using ECDSAOffchain for SecretKey;
    using ECDSA for address;
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;
    using ECDSAUnsafe for Signature;

    ECDSAWrapper wrapper;

    function setUp() public {
        wrapper = new ECDSAWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Verification

    // -- verify with public key

    function testFuzz_verify_WithPublicKey(SecretKey sk, bytes32 digest)
        public
    {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(digest);

        bytes32 m = ECDSA.constructMessageHash(digest);
        PublicKey memory pk = sk.toPublicKey();

        assertTrue(wrapper.verify(pk, m, sig));
    }

    function testFuzz_verify_WithPublicKey_FailsIf_SignatureInvalid(
        SecretKey sk,
        bytes32 digest,
        uint8 vMask,
        uint rMask,
        uint sMask
    ) public {
        vm.assume(sk.isValid());
        vm.assume(vMask != 0 || rMask != 0 || sMask != 0);

        Signature memory sig = sk.sign(digest);

        sig.v ^= vMask;
        sig.r = bytes32(uint(sig.r) ^ rMask);
        sig.s = bytes32(uint(sig.s) ^ sMask);

        // Note that verify() reverts if signature is malleable.
        sig.intoNonMalleable();

        bytes32 m = ECDSA.constructMessageHash(digest);
        PublicKey memory pk = sk.toPublicKey();

        assertFalse(wrapper.verify(pk, m, sig));
    }

    function testFuzz_verify_WithPublicKey_RevertsIf_SignatureMalleable(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(digest).intoMalleable();

        bytes32 m = ECDSA.constructMessageHash(digest);
        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pk, m, sig);
    }

    function testFuzz_verify_WithPublicKey_RevertsIf_PublicKeyInvalid(
        PublicKey memory pk,
        bytes32 m,
        Signature memory sig
    ) public {
        vm.assume(!pk.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(pk, m, sig);
    }

    // -- verify with address

    function testFuzz_verify_WithAddress(SecretKey sk, bytes32 digest) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(digest);

        bytes32 m = ECDSA.constructMessageHash(digest);
        address addr = sk.toPublicKey().toAddress();

        assertTrue(wrapper.verify(addr, m, sig));
    }

    function testFuzz_verify_WithAddress_FailsIf_SignatureInvalid(
        SecretKey sk,
        bytes32 digest,
        uint8 vMask,
        uint rMask,
        uint sMask
    ) public {
        vm.assume(sk.isValid());
        vm.assume(vMask != 0 || rMask != 0 || sMask != 0);

        Signature memory sig = sk.sign(digest);

        sig.v ^= vMask;
        sig.r = bytes32(uint(sig.r) ^ rMask);
        sig.s = bytes32(uint(sig.s) ^ sMask);

        // Note that verify() reverts if signature is malleable.
        sig.intoNonMalleable();

        bytes32 m = ECDSA.constructMessageHash(digest);
        address addr = sk.toPublicKey().toAddress();

        assertFalse(wrapper.verify(addr, m, sig));
    }

    function testFuzz_verify_WithAddress_RevertsIf_SignatureMalleable(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(digest).intoMalleable();

        bytes32 m = ECDSA.constructMessageHash(digest);
        address addr = sk.toPublicKey().toAddress();

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(addr, m, sig);
    }

    function testFuzz_verify_WithAddress_RevertsIf_SignerZeroAddress(
        bytes32 m,
        Signature memory sig
    ) public {
        vm.expectRevert("SignerZeroAddress()");
        wrapper.verify(address(0), m, sig);
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- constructMessageHash

    function test_constructMessageHash() public view {
        bytes32 digest = keccak256(bytes("crysol <3"));

        bytes32 want = bytes32(
            0xf0d01579d47c5b662330453e5709f9c1e75de1f1b741f00e20c3c381ab997664
        );
        bytes32 got = wrapper.constructMessageHash(digest);

        assertEq(want, got);
    }

    // -- isMalleable

    function testFuzz_Signature_isMalleable(Signature memory sig) public view {
        vm.assume(uint(sig.s) > Secp256k1.Q / 2);

        assertTrue(wrapper.isMalleable(sig));
    }

    function testFuzz_Signature_isMalleable_FailsIf_SignatureNotMalleable(
        Signature memory sig
    ) public view {
        vm.assume(uint(sig.s) <= Secp256k1.Q / 2);

        assertFalse(wrapper.isMalleable(sig));
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    // -- Signature <-> Encoded

    function test_signatureFromEncoded() public view {
        // Test Case 1: v = 27
        bytes memory blob1 = (
            hex"0000000000000000000000000000000000000000000000000000000000000001"
            hex"0000000000000000000000000000000000000000000000000000000000000002"
            hex"1b"
        );
        Signature memory want1 =
            Signature({v: uint8(27), r: bytes32(uint(1)), s: bytes32(uint(2))});
        Signature memory got1 = wrapper.signatureFromEncoded(blob1);
        assertEq(want1.v, got1.v);
        assertEq(want1.r, got1.r);
        assertEq(want1.s, got1.s);

        // Test Case 1: v = 28
        bytes memory blob2 = (
            hex"0000000000000000000000000000000000000000000000000000000000000001"
            hex"0000000000000000000000000000000000000000000000000000000000000002"
            hex"1c"
        );
        Signature memory want2 =
            Signature({v: uint8(28), r: bytes32(uint(1)), s: bytes32(uint(2))});
        Signature memory got2 = wrapper.signatureFromEncoded(blob2);
        assertEq(want2.v, got2.v);
        assertEq(want2.r, got2.r);
        assertEq(want2.s, got2.s);
    }

    function testFuzz_signatureFromEncoded_RevertsIf_LengthInvalid(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 65);

        vm.expectRevert("LengthInvalid()");
        wrapper.signatureFromEncoded(blob);
    }

    function testFuzz_signatureFromEncoded_RevertsIf_SignatureMalleable(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(digest).intoMalleable();

        bytes memory blob = abi.encodePacked(sig.r, sig.s, sig.v);

        vm.expectRevert("SignatureMalleable()");
        wrapper.signatureFromEncoded(blob);
    }

    function test_Signature_toEncoded() public view {
        Signature memory sig =
            Signature({v: uint8(27), r: bytes32(uint(1)), s: bytes32(uint(2))});

        bytes memory want = (
            hex"0000000000000000000000000000000000000000000000000000000000000001"
            hex"0000000000000000000000000000000000000000000000000000000000000002"
            hex"1b"
        );
        bytes memory got = wrapper.toEncoded(sig);

        assertEq(want, got);
    }

    function testFuzz_Signature_toEncoded_RevertsIf_SignatureMalleable(
        Signature memory sig
    ) public {
        vm.assume(sig.isMalleable());

        vm.expectRevert("SignatureMalleable()");
        wrapper.toEncoded(sig);
    }

    // -- Signature <-> Compact Encoded

    function test_signatureFromCompactEncoded() public view {
        // Note that test cases are taken from EIP-2098.

        // Test Case 1:
        bytes memory blob1 = bytes.concat(
            hex"68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90",
            hex"7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064"
        );
        Signature memory got1 = wrapper.signatureFromCompactEncoded(blob1);
        Signature memory want1 = Signature({
            v: 27,
            r: 0x68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90,
            s: 0x7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064
        });
        assertEq(got1.v, want1.v);
        assertEq(got1.r, want1.r);
        assertEq(got1.s, want1.s);

        // Test Case 2:
        bytes memory blob2 = bytes.concat(
            hex"9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76",
            hex"939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793"
        );
        Signature memory got2 = wrapper.signatureFromCompactEncoded(blob2);
        Signature memory want2 = Signature({
            v: 28,
            r: 0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76,
            s: 0x139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793
        });
        assertEq(got2.v, want2.v);
        assertEq(got2.r, want2.r);
        assertEq(got2.s, want2.s);
    }

    function testFuzz_signatureFromCompactEncoded_RevertsIf_LengthInvalid(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 64);

        vm.expectRevert("LengthInvalid()");
        wrapper.signatureFromCompactEncoded(blob);
    }

    function test_signatureFromCompactEncoded_RevertsIf_SignatureMalleable()
        public
    {
        bytes memory blob = abi.encodePacked(type(uint).max, type(uint).max);

        vm.expectRevert("SignatureMalleable()");
        wrapper.signatureFromCompactEncoded(blob);
    }

    function test_Signature_toCompactEncoded() public view {
        // Note that test cases are taken from EIP-2098.

        // Test Case 1:
        Signature memory sig1 = Signature({
            v: 27,
            r: 0x68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90,
            s: 0x7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064
        });
        bytes memory got1 = wrapper.toCompactEncoded(sig1);
        bytes memory want1 = bytes.concat(
            hex"68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90",
            hex"7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064"
        );
        assertEq(got1, want1);

        // Test Case 2:
        Signature memory sig2 = Signature({
            v: 28,
            r: 0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76,
            s: 0x139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793
        });
        bytes memory got2 = wrapper.toCompactEncoded(sig2);
        bytes memory want2 = bytes.concat(
            hex"9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76",
            hex"939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793"
        );
        assertEq(got2, want2);
    }

    function test_Signature_toCompactEncoded_RevertsIf_SignatureMalleable(
        Signature memory sig
    ) public {
        vm.assume(sig.isMalleable());

        vm.expectRevert("SignatureMalleable()");
        wrapper.toCompactEncoded(sig);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract ECDSAWrapper {
    using ECDSA for address;
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;

    //--------------------------------------------------------------------------
    // Signature Verification

    function verify(PublicKey memory pk, bytes32 m, Signature memory sig)
        public
        pure
        returns (bool)
    {
        return pk.verify(m, sig);
    }

    function verify(address signer, bytes32 m, Signature memory sig)
        public
        pure
        returns (bool)
    {
        return signer.verify(m, sig);
    }

    //--------------------------------------------------------------------------
    // Utils

    function constructMessageHash(bytes32 digest)
        public
        pure
        returns (bytes32)
    {
        return ECDSA.constructMessageHash(digest);
    }

    function isMalleable(Signature memory sig) public pure returns (bool) {
        return sig.isMalleable();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    function signatureFromEncoded(bytes memory blob)
        public
        pure
        returns (Signature memory)
    {
        return ECDSA.signatureFromEncoded(blob);
    }

    function toEncoded(Signature memory sig)
        public
        pure
        returns (bytes memory)
    {
        return sig.toEncoded();
    }

    function signatureFromCompactEncoded(bytes memory blob)
        public
        pure
        returns (Signature memory)
    {
        return ECDSA.signatureFromCompactEncoded(blob);
    }

    function toCompactEncoded(Signature memory sig)
        public
        pure
        returns (bytes memory)
    {
        return sig.toCompactEncoded();
    }
}
