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
    Schnorr, Signature, SignatureCompressed
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

    function testFuzz_verify_RevertsIf_SignatureInsane_SNotAFieldElement(
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

    function testFuzz_verify_Compressed_RevertsIf_SignatureInsane_SNotAFieldElement(
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

        bytes32 want = bytes32(0x3337f39d830c322fca415bae221f3c5c8b07bbb107e35a66d9252325ed567156);
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

    function testFuzz_isSane_FailsIf_SIsZero(Signature memory sig) public pure {
        sig.s = 0;

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_FailsIf_SNotAFieldElement(Signature memory sig) public pure {
        sig.s = bytes32(_bound(uint(sig.s), Secp256k1.Q, type(uint).max));

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_FailsIf_RNotAValidPublicKey(Signature memory sig) public pure {
        vm.assume(!sig.r.isValid());

        assertFalse(sig.isSane());
    }

    // -- isSane compressed

    function testFuzz_isSane_Compressed(SignatureCompressed memory sig) public pure {
        vm.assume(sig.s != 0);
        vm.assume(uint(sig.s) < Secp256k1.Q);
        vm.assume(sig.rAddr != address(0));

        assertTrue(sig.isSane());
    }

    function testFuzz_isSane_Compressed_FailsIf_SIsZero(SignatureCompressed memory sig) public pure  {
        sig.s = 0;

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_Compressed_FailsIf_SNotAFieldElement(SignatureCompressed memory sig) public pure {
        sig.s = bytes32(_bound(uint(sig.s), Secp256k1.Q, type(uint).max));

        assertFalse(sig.isSane());
    }

    function testFuzz_isSane_Compressed_FailsIf_RAddrIsZero(SignatureCompressed memory sig) public pure {
        sig.rAddr = address(0);

        assertFalse(sig.isSane());
    }

    //--------------------------------------------------------------------------
    // TODO: Test: Type Conversions

    // -- intoCompressed

    // -- toCompressed

    //--------------------------------------------------------------------------
    // TODO: Test: (De)Serialization

    // -- signatureFromEncoded

    // -- toEncoded

    // -- toCompressedEncoded

    // -- fromCompressedEncoded

    // -- toCompressedEncoded
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

    function verify(PublicKey memory pk, bytes32 digest, SignatureCompressed memory sig)
        public
        pure
        returns (bool)
    {
        return pk.verify(digest, sig);
    }

    //--------------------------------------------------------------------------
    // Utils

    function constructMessageHash(bytes32 digest) public pure returns (bytes32) {
        return Schnorr.constructMessageHash(digest);
    }

    function isSane(Signature memory sig) public pure returns (bool) {
        return sig.isSane();
    }

    function isSane(SignatureCompressed memory sig) public pure returns (bool) {
        return sig.isSane();
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    function intoCompressed(Signature memory sig) public pure returns (SignatureCompressed memory) {
        return sig.intoCompressed();
    }

    function toCompressed(Signature memory sig) public pure returns (SignatureCompressed memory) {
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

    function fromCompressedEncoded(bytes memory blob)
        public
        pure
        returns (SignatureCompressed memory)
    {
        return Schnorr.fromCompressedEncoded(blob);
    }

    function toCompressedEncoded(SignatureCompressed memory sig)
        public
        pure
        returns (bytes memory)
    {
        return sig.toCompressedEncoded();
    }
}
