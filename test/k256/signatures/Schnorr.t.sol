// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Schnorr, Signature} from "src/k256/signatures/Schnorr.sol";

import {K256, SecretKey, PublicKey} from "src/k256/K256.sol";

import {Message} from "src/common/Message.sol";

/**
 * @notice Schnorr Unit Tests
 */
contract SchnorrTest is Test {
    using K256 for SecretKey;
    using K256 for PublicKey;

    using Schnorr for SecretKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    SchnorrWrapper wrapper;

    function setUp() public {
        wrapper = new SchnorrWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Verification

    function testFuzz_verify(SecretKey sk, bytes memory message) public {
        vm.assume(sk.isValid());

        Signature memory sig = sk.sign(message);

        PublicKey memory pk = sk.toPublicKey();
        assertTrue(wrapper.verify(pk, message, sig));
        assertTrue(wrapper.verify(pk, keccak256(message), sig));
    }

    function testFuzz_verify_FailsIf_SignatureInvalid(
        SecretKey sk,
        bytes memory message,
        uint signatureMask,
        uint160 commitmentMask
    ) public {
        vm.assume(sk.isValid());
        vm.assume(signatureMask != 0 || commitmentMask != 0);

        Signature memory sig = sk.sign(message);

        sig.signature = bytes32(uint(sig.signature) ^ signatureMask);
        sig.commitment = address(uint160(sig.commitment) ^ commitmentMask);

        // Note that verify reverts if signature is malleable or trivial.
        vm.assume(!sig.isMalleable());
        vm.assume(sig.signature != 0 || sig.commitment != address(0));

        PublicKey memory pk = sk.toPublicKey();
        assertFalse(wrapper.verify(pk, message, sig));
        assertFalse(wrapper.verify(pk, keccak256(message), sig));
    }

    function testFuzz_verify_RevertsIf_PublicKeyInvalid(
        PublicKey memory pk,
        bytes memory message
    ) public {
        vm.assume(!pk.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(
            pk, message, K256.secretKeyFromUint(1).sign(message)
        );
        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(
            pk, keccak256(message), K256.secretKeyFromUint(1).sign(message)
        );
    }

    function testFuzz_verify_RevertsIf_SignatureMalleable(
        SecretKey sk,
        bytes memory message,
        Signature memory sig
    ) public {
        vm.assume(sk.isValid());
        vm.assume(sig.commitment != address(0));

        sig.signature =
            bytes32(_bound(uint(sig.signature), K256.Q, type(uint).max));

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
    // Test: Signature Creation

    function testFuzz_sign(SecretKey sk, bytes memory message) public {
        vm.assume(sk.isValid());

        Signature memory sig1 = wrapper.sign(sk, message);
        Signature memory sig2 = wrapper.sign(sk, keccak256(message));

        assertEq(sig1.signature, sig2.signature);
        assertEq(sig1.commitment, sig2.commitment);

        PublicKey memory pk = sk.toPublicKey();
        assertTrue(pk.verify(message, sig1));
        assertTrue(pk.verify(message, sig2));
    }

    function testFuzz_sign_RevertsIf_SecretKeyInvalid(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(!sk.isValid());

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.sign(sk, message);

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.sign(sk, keccak256(message));
    }

    function testFuzz_signEthereumSignedMessageHash(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        Signature memory sig1 =
            wrapper.signEthereumSignedMessageHash(sk, message);
        Signature memory sig2 =
            wrapper.signEthereumSignedMessageHash(sk, keccak256(message));

        assertEq(sig1.signature, sig2.signature);
        assertEq(sig1.commitment, sig2.commitment);

        PublicKey memory pk = sk.toPublicKey();
        assertTrue(
            pk.verify(Message.deriveEthereumSignedMessageHash(message), sig1)
        );
        assertTrue(
            pk.verify(Message.deriveEthereumSignedMessageHash(message), sig2)
        );
    }

    function testFuzz_signEthereumSignedMessageHash_RevertsIf_SecretKeyInvalid(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(!sk.isValid());

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.signEthereumSignedMessageHash(sk, message);

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.signEthereumSignedMessageHash(sk, keccak256(message));
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- Signature::isMalleable

    function testFuzz_Signature_isMalleable(Signature memory sig) public {
        sig.signature =
            bytes32(_bound(uint(sig.signature), K256.Q, type(uint).max));

        assertTrue(wrapper.isMalleable(sig));
    }

    function testFuzz_Signature_isMalleable_FailsIf_SignatureNotMalleable(
        Signature memory sig
    ) public {
        vm.assume(uint(sig.signature) < K256.Q);

        assertFalse(wrapper.isMalleable(sig));
    }

    // -- Signature::toString

    function test_Signature_toString() public {
        Signature memory sig = Signature({
            signature: bytes32(type(uint).max),
            commitment: address(0x0)
        });

        string memory got = wrapper.toString(sig);
        string memory want =
            "Schnorr::Signature({ signature: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, commitment: 0x0000000000000000000000000000000000000000 })";

        assertEq(got, want);
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

    //--------------------------------------------------------------------------
    // Signature Verification

    function verify(
        PublicKey memory pk,
        bytes memory message,
        Signature memory sig
    ) public pure returns (bool) {
        return pk.verify(message, sig);
    }

    function verify(PublicKey memory pk, bytes32 digest, Signature memory sig)
        public
        pure
        returns (bool)
    {
        return pk.verify(digest, sig);
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    function sign(SecretKey sk, bytes memory message)
        public
        returns (Signature memory)
    {
        return sk.sign(message);
    }

    function sign(SecretKey sk, bytes32 digest)
        public
        returns (Signature memory)
    {
        return sk.sign(digest);
    }

    function signEthereumSignedMessageHash(SecretKey sk, bytes memory message)
        public
        returns (Signature memory)
    {
        return sk.signEthereumSignedMessageHash(message);
    }

    function signEthereumSignedMessageHash(SecretKey sk, bytes32 digest)
        public
        returns (Signature memory)
    {
        return sk.signEthereumSignedMessageHash(digest);
    }

    //--------------------------------------------------------------------------
    // Utils

    function isMalleable(Signature memory sig) public pure returns (bool) {
        return sig.isMalleable();
    }

    function toString(Signature memory sig)
        public
        view
        returns (string memory)
    {
        return sig.toString();
    }
}
