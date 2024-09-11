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

    SchnorrWrapper wrapper;

    function setUp() public {
        wrapper = new SchnorrWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Verification

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
        uint sMask,
        uint rxMask,
        uint ryMask
    ) public {
        vm.assume(sk.isValid());
        vm.assume(sMask != 0 || rxMask != 0 || ryMask != 0);

        Signature memory sig = sk.sign(digest);

        sig.s = bytes32(uint(sig.s) ^ sMask);
        sig.r.x = sig.r.x ^ rxMask;
        sig.r.y = sig.r.y ^ rxMask;

        // Note that verify reverts if signature is insane.
        vm.assume(!sig.isSane());

        bytes32 m = Schnorr.constructMessageHash(digest);
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

    /*
    function testFuzz_verify_RevertsIf_SignatureInsane(
        SecretKey sk,
        bytes memory message,
        Signature memory sig
    ) public {
        vm.assume(sk.isValid());
        vm.assume(sig.commitment != address(0));

        sig.signature =
            bytes32(_bound(uint(sig.signature), Secp256k1.Q, type(uint).max));

        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pk, message, sig);
        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pk, keccak256(message), sig);
    }

    function testFuzz_verify_RevertsIf_SignatureTrivial(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig = Signature(0, address(0));

        PublicKey memory pk = sk.toPublicKey();

        vm.expectRevert("SignatureTrivial()");
        wrapper.verify(pk, message, sig);
        vm.expectRevert("SignatureTrivial()");
        wrapper.verify(pk, keccak256(message), sig);
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- Signature::isMalleable

    function testFuzz_Signature_isMalleable(Signature memory sig) public view {
        sig.signature =
            bytes32(_bound(uint(sig.signature), Secp256k1.Q, type(uint).max));

        assertTrue(wrapper.isMalleable(sig));
    }

    function testFuzz_Signature_isMalleable_FailsIf_SignatureNotMalleable(
        Signature memory sig
    ) public view {
        vm.assume(uint(sig.signature) < Secp256k1.Q);

        assertFalse(wrapper.isMalleable(sig));
    }
    */
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
