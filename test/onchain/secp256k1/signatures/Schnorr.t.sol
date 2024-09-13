// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "src/offchain/secp256k1/Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256k1/Secp256k1.sol";

import {
    Schnorr,
    Signature,
    SignatureCompressed
} from "src/onchain/secp256k1/signatures/Schnorr.sol";
import {SchnorrOffchain} from
    "src/offchain/secp256k1/signatures/SchnorrOffchain.sol";

/**
 * @notice Schnorr Unit Tests
 */
contract SchnorrTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using SchnorrOffchain for SecretKey;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;
    using Schnorr for SignatureCompressed;

    SchnorrWrapper wrapper;

    function setUp() public {
        wrapper = new SchnorrWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Verification

    // -- verify

    function testFuzz_verify(SecretKey sk, bytes32 digest) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(digest);

        bytes32 m = Schnorr.constructMessageHash(digest);
        PublicKey memory pk = sk.toPublicKey();

        assertTrue(wrapper.verify(pk, m, sig));
    }

    function testFuzz_verify_FailsIf_SignatureInvalid(
        SecretKey sk,
        bytes32 digest,
        uint sMask
    ) public {
        vm.assume(sk.isValid());
        vm.assume(sMask != 0);

        Signature memory sig = sk.sign(digest);

        sig.s = bytes32(uint(sig.s) ^ sMask);

        // Note that verify reverts if signature is insane.
        vm.assume(sig.isSane());

        bytes32 m = Schnorr.constructMessageHash(digest);
        PublicKey memory pk = sk.toPublicKey();

        assertFalse(wrapper.verify(pk, m, sig));
    }

    function testFuzz_verify_FailsIf_SignatureInsane_RNotAValidPublicKey(
        SecretKey sk,
        bytes32 m,
        Signature memory sig
    ) public {
        vm.assume(sk.isValid());
        vm.assume(sig.s != 0);
        vm.assume(uint(sig.s) < Secp256k1.Q);

        vm.assume(!sig.r.isValid());

        PublicKey memory pk = sk.toPublicKey();

        assertFalse(wrapper.verify(pk, m, sig));
    }

    function testFuzz_verify_RevertsIf_PublicKeyInvalid(
        PublicKey memory pk,
        bytes32 m,
        Signature memory sig
    ) public {
        vm.assume(!pk.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(pk, m, sig);
    }

    function testFuzz_verify_RevertsIf_SignatureInsane_SIsZero(
        SecretKey sk,
        bytes32 m,
        Signature memory sig
    ) public {
        vm.assume(sk.isValid());

        sig.s = 0;

        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureInsane()");
        wrapper.verify(pk, m, sig);
    }

    function testFuzz_verify_RevertsIf_SignatureInsane_SGreaterOrEqualToQ(
        SecretKey sk,
        bytes32 m,
        Signature memory sig
    ) public {
        vm.assume(sk.isValid());

        sig.s = bytes32(_bound(uint(sig.s), Secp256k1.Q, type(uint).max));

        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureInsane()");
        wrapper.verify(pk, m, sig);
    }

    // -- verify compressed

    function testFuzz_verify_Compressed(SecretKey sk, bytes32 digest) public {
        vm.assume(sk.isValid());

        SignatureCompressed memory sig = sk.sign(digest).intoCompressed();

        bytes32 m = Schnorr.constructMessageHash(digest);
        PublicKey memory pk = sk.toPublicKey();

        assertTrue(wrapper.verify(pk, m, sig));
    }

    function testFuzz_verify_Compressed_FailsIf_SignatureInvalid(
        SecretKey sk,
        bytes32 digest,
        uint sMask,
        uint160 rAddrMask
    ) public {
        vm.assume(sk.isValid());
        vm.assume(sMask != 0 || rAddrMask != 0);

        SignatureCompressed memory sig = sk.sign(digest).intoCompressed();

        sig.s = bytes32(uint(sig.s) ^ sMask);
        sig.rAddr = address(uint160(sig.rAddr) ^ rAddrMask);

        // Note that verify reverts if signature is insane.
        vm.assume(sig.isSane());

        bytes32 m = Schnorr.constructMessageHash(digest);
        PublicKey memory pk = sk.toPublicKey();

        assertFalse(wrapper.verify(pk, m, sig));
    }

    function testFuzz_verify_Compressed_RevertsIf_PublicKeyInvalid(
        PublicKey memory pk,
        bytes32 m,
        SignatureCompressed memory sig
    ) public {
        vm.assume(!pk.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(pk, m, sig);
    }

    function testFuzz_verify_Compressed_RevertsIf_SignatureInsane_SIsZero(
        SecretKey sk,
        bytes32 m,
        SignatureCompressed memory sig
    ) public {
        vm.assume(sk.isValid());

        sig.s = 0;

        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureInsane()");
        wrapper.verify(pk, m, sig);
    }

    function testFuzz_verify_Compressed_RevertsIf_SignatureInsane_SGreaterOrEqualToQ(
        SecretKey sk,
        bytes32 m,
        SignatureCompressed memory sig
    ) public {
        vm.assume(sk.isValid());

        sig.s = bytes32(_bound(uint(sig.s), Secp256k1.Q, type(uint).max));

        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureInsane()");
        wrapper.verify(pk, m, sig);
    }

    function testFuzz_verify_Compressed_RevertsIf_SignatureInsane_RAddrIsZero(
        SecretKey sk,
        bytes32 m,
        SignatureCompressed memory sig
    ) public {
        vm.assume(sk.isValid());

        sig.rAddr = address(0);

        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureInsane()");
        wrapper.verify(pk, m, sig);
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- constructMessageHash

    function test_constructMessageHash() public pure {
        bytes32 digest = keccak256(bytes("crysol <3"));

        bytes32 want = bytes32(
            0x3337f39d830c322fca415bae221f3c5c8b07bbb107e35a66d9252325ed567156
        );
        bytes32 got = Schnorr.constructMessageHash(digest);

        assertEq(want, got);
    }

    // -- isSane

    function testFuzz_isSane(SecretKey sk, Signature memory sig) public {
        vm.assume(sig.s != 0);
        vm.assume(uint(sig.s) < Secp256k1.Q);

        // Note to not assume random input is valid public key.
        // vm.assume(sig.r.isValid());
        vm.assume(sk.isValid());
        sig.r = sk.toPublicKey();

        assertTrue(sig.isSane());
    }

    function testFuzz_isSane_FailsIf_SIsZero(Signature memory sig)
        public
        pure
    {
        sig.s = 0;

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_FailsIf_SGreaterOrEqualToQ(Signature memory sig)
        public
        pure
    {
        sig.s = bytes32(_bound(uint(sig.s), Secp256k1.Q, type(uint).max));

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_FailsIf_RNotAValidPublicKey(Signature memory sig)
        public
        pure
    {
        vm.assume(!sig.r.isValid());

        assertFalse(sig.isSane());
    }

    // -- isSane compressed

    function testFuzz_isSane_Compressed(SignatureCompressed memory sig)
        public
        pure
    {
        vm.assume(sig.s != 0);
        vm.assume(uint(sig.s) < Secp256k1.Q);
        vm.assume(sig.rAddr != address(0));

        assertTrue(sig.isSane());
    }

    function testFuzz_isSane_Compressed_FailsIf_SIsZero(
        SignatureCompressed memory sig
    ) public pure {
        sig.s = 0;

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_Compressed_FailsIf_SGreaterOrEqualToQ(
        SignatureCompressed memory sig
    ) public pure {
        sig.s = bytes32(_bound(uint(sig.s), Secp256k1.Q, type(uint).max));

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_Compressed_FailsIf_RAddrIsZero(
        SignatureCompressed memory sig
    ) public pure {
        sig.rAddr = address(0);

        assertFalse(sig.isSane());
    }

    //--------------------------------------------------------------------------
    // Test: Type Conversions

    // -- intoCompressed

    function testFuzz_intoCompressed(Signature memory sig) public view {
        SignatureCompressed memory sigComp = wrapper.intoCompressed(sig);

        assertEq(sig.s, sigComp.s);
        assertEq(sig.r.toAddress(), sigComp.rAddr);
    }

    // -- toCompressed

    function testFuzz_toCompressed(Signature memory sig) public view {
        SignatureCompressed memory sigComp = wrapper.toCompressed(sig);

        assertEq(sig.s, sigComp.s);
        assertEq(sig.r.toAddress(), sigComp.rAddr);
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    // -- Signature <-> Encoded

    function test_signatureFromEncoded() public view {
        bytes memory blob = (
            hex"0000000000000000000000000000000000000000000000000000000000000001"
            hex"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            hex"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );

        Signature memory want =
            Signature({s: bytes32(uint(1)), r: Secp256k1.G()});
        Signature memory got = wrapper.signatureFromEncoded(blob);

        assertEq(want.s, got.s);
        assertTrue(want.r.eq(got.r));
    }

    function testFuzz_signatureFromEncoded_RevertsIf_LengthInvalid(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 96);

        vm.expectRevert("LengthInvalid()");
        wrapper.signatureFromEncoded(blob);
    }

    function testFuzz_signatureFromEncoded_RevertsIf_SignatureInsane(
        uint s,
        PublicKey memory r
    ) public {
        vm.assume(s == 0 || s >= Secp256k1.Q || !r.isValid());

        bytes memory blob = abi.encodePacked(s, r.x, r.y);

        vm.expectRevert("SignatureInsane()");
        wrapper.signatureFromEncoded(blob);
    }

    function test_Signature_toEncoded() public view {
        Signature memory sig =
            Signature({s: bytes32(uint(1)), r: Secp256k1.G()});

        bytes memory want = (
            hex"0000000000000000000000000000000000000000000000000000000000000001"
            hex"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            hex"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        bytes memory got = wrapper.toEncoded(sig);

        assertEq(want, got);
    }

    function testFuzz_Signature_toEncoded_RevertsIf_SignatureInsane(
        uint s,
        PublicKey memory r
    ) public {
        vm.assume(s == 0 || s >= Secp256k1.Q || !r.isValid());

        Signature memory sig = Signature(bytes32(s), r);

        vm.expectRevert("SignatureInsane()");
        wrapper.toEncoded(sig);
    }

    // Signature <-> compressed encoded

    function test_Signature_toCompressedEncoded() public view {
        Signature memory sig =
            Signature({s: bytes32(uint(1)), r: Secp256k1.G()});

        bytes memory want =
            abi.encodePacked(bytes32(uint(1)), Secp256k1.G().toAddress());
        bytes memory got = wrapper.toCompressedEncoded(sig);

        assertEq(want, got);
    }

    function testFuzz_Signature_toCompressedEncoded_RevertsIf_SignatureInsane(
        uint s,
        PublicKey memory r
    ) public {
        // Note to in order to compress a signature the public key r's address
        // is computed, ie ensure signature is insane due to their s value.
        vm.assume(s == 0 || s > Secp256k1.Q);

        Signature memory sig = Signature(bytes32(s), r);

        vm.expectRevert("SignatureInsane()");
        wrapper.toCompressedEncoded(sig);
    }

    // -- SignatureCompressed <-> compressed encoded

    function test_signatureFromCompressedEncoded() public view {
        bytes memory blob = (
            hex"0000000000000000000000000000000000000000000000000000000000000001"
            hex"0000000000000000000000000000000000000001"
        );

        SignatureCompressed memory want =
            SignatureCompressed({s: bytes32(uint(1)), rAddr: address(1)});
        SignatureCompressed memory got =
            wrapper.signatureFromCompressedEncoded(blob);

        assertEq(want.s, got.s);
        assertEq(want.rAddr, got.rAddr);
    }

    function testFuzz_signatureFromCompressedEncoded_RevertsIf_LengthInvalid(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 52);

        vm.expectRevert("LengthInvalid()");
        wrapper.signatureFromCompressedEncoded(blob);
    }

    function testFuzz_signatureFromCompressedEncoded_RevertsIf_SignatureInsane(
        uint s,
        address rAddr
    ) public {
        vm.assume(s == 0 || s >= Secp256k1.Q || rAddr == address(0));

        bytes memory blob = abi.encodePacked(s, rAddr);

        vm.expectRevert("SignatureInsane()");
        wrapper.signatureFromCompressedEncoded(blob);
    }

    function test_SignatureCompressed_toCompressedEncoded() public view {
        SignatureCompressed memory sig =
            SignatureCompressed({s: bytes32(uint(1)), rAddr: address(1)});

        bytes memory want = (
            hex"0000000000000000000000000000000000000000000000000000000000000001"
            hex"0000000000000000000000000000000000000001"
        );
        bytes memory got = wrapper.toCompressedEncoded(sig);

        assertEq(want, got);
    }

    function testFuzz_Signature_toEncoded_RevertsIf_SignatureInsane(
        uint s,
        address rAddr
    ) public {
        vm.assume(s == 0 || s >= Secp256k1.Q || rAddr == address(0));

        SignatureCompressed memory sig = SignatureCompressed(bytes32(s), rAddr);

        vm.expectRevert("SignatureInsane()");
        wrapper.toCompressedEncoded(sig);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract SchnorrWrapper {
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;
    using Schnorr for SignatureCompressed;

    //--------------------------------------------------------------------------
    // Signature Verification

    function verify(PublicKey memory pk, bytes32 digest, Signature memory sig)
        public
        pure
        returns (bool)
    {
        return pk.verify(digest, sig);
    }

    function verify(
        PublicKey memory pk,
        bytes32 digest,
        SignatureCompressed memory sig
    ) public pure returns (bool) {
        return pk.verify(digest, sig);
    }

    //--------------------------------------------------------------------------
    // Utils

    function constructMessageHash(bytes32 digest)
        public
        pure
        returns (bytes32)
    {
        return Schnorr.constructMessageHash(digest);
    }

    function isSane(Signature memory sig) public pure returns (bool) {
        return sig.isSane();
    }

    function isSane(SignatureCompressed memory sig)
        public
        pure
        returns (bool)
    {
        return sig.isSane();
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    function intoCompressed(Signature memory sig)
        public
        pure
        returns (SignatureCompressed memory)
    {
        return sig.intoCompressed();
    }

    function toCompressed(Signature memory sig)
        public
        pure
        returns (SignatureCompressed memory)
    {
        return sig.toCompressed();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    function signatureFromEncoded(bytes memory blob)
        public
        pure
        returns (Signature memory)
    {
        return Schnorr.signatureFromEncoded(blob);
    }

    function toEncoded(Signature memory sig)
        public
        pure
        returns (bytes memory)
    {
        return sig.toEncoded();
    }

    function toCompressedEncoded(Signature memory sig)
        public
        pure
        returns (bytes memory)
    {
        return sig.toCompressedEncoded();
    }

    function signatureFromCompressedEncoded(bytes memory blob)
        public
        pure
        returns (SignatureCompressed memory)
    {
        return Schnorr.signatureFromCompressedEncoded(blob);
    }

    function toCompressedEncoded(SignatureCompressed memory sig)
        public
        pure
        returns (bytes memory)
    {
        return sig.toCompressedEncoded();
    }
}
