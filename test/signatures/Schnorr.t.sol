// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Schnorr, Signature} from "src/signatures/Schnorr.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

import {Message} from "src/Message.sol";

/**
 * @notice Schnorr Unit Tests
 */
contract SchnorrTest is Test {
    using Schnorr for PrivateKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    SchnorrWrapper wrapper;

    function setUp() public {
        wrapper = new SchnorrWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Verification

    function testFuzz_verify(PrivateKey privKey, bytes memory message) public {
        vm.assume(privKey.isValid());

        Signature memory sig = privKey.sign(message);

        PublicKey memory pubKey = privKey.toPublicKey();
        assertTrue(wrapper.verify(pubKey, message, sig));
        assertTrue(wrapper.verify(pubKey, keccak256(message), sig));
    }

    function testFuzz_verify_FailsIf_SignatureInvalid(
        PrivateKey privKey,
        bytes memory message,
        uint signatureMask,
        uint160 commitmentMask
    ) public {
        vm.assume(privKey.isValid());
        vm.assume(signatureMask != 0 || commitmentMask != 0);

        Signature memory sig = privKey.sign(message);

        sig.signature = bytes32(uint(sig.signature) ^ signatureMask);
        sig.commitment = address(uint160(sig.commitment) ^ commitmentMask);

        // Note that verify reverts if signature is malleable or trivial.
        vm.assume(!sig.isMalleable());
        vm.assume(sig.signature != 0 || sig.commitment != address(0));

        PublicKey memory pubKey = privKey.toPublicKey();
        assertFalse(wrapper.verify(pubKey, message, sig));
        assertFalse(wrapper.verify(pubKey, keccak256(message), sig));
    }

    function testFuzz_verify_RevertsIf_PublicKeyInvalid(
        PublicKey memory pubKey,
        bytes memory message
    ) public {
        vm.assume(!pubKey.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(
            pubKey, message, Secp256k1.privateKeyFromUint(1).sign(message)
        );
        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(
            pubKey,
            keccak256(message),
            Secp256k1.privateKeyFromUint(1).sign(message)
        );
    }

    function testFuzz_verify_RevertsIf_SignatureMalleable(
        PrivateKey privKey,
        bytes memory message,
        Signature memory sig
    ) public {
        vm.assume(privKey.isValid());
        vm.assume(sig.commitment != address(0));

        sig.signature =
            bytes32(_bound(uint(sig.signature), Secp256k1.Q, type(uint).max));

        PublicKey memory pubKey = privKey.toPublicKey();

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pubKey, message, sig);
        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pubKey, keccak256(message), sig);
    }

    function testFuzz_verify_RevertsIf_SignatureTrivial(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        Signature memory sig = Signature(0, address(0));

        PublicKey memory pubKey = privKey.toPublicKey();

        vm.expectRevert("SignatureTrivial()");
        wrapper.verify(pubKey, message, sig);
        vm.expectRevert("SignatureTrivial()");
        wrapper.verify(pubKey, keccak256(message), sig);
    }

    //--------------------------------------------------------------------------
    // Test: Signature Creation

    function testFuzz_sign(PrivateKey privKey, bytes memory message) public {
        vm.assume(privKey.isValid());

        Signature memory sig1 = wrapper.sign(privKey, message);
        Signature memory sig2 = wrapper.sign(privKey, keccak256(message));

        assertEq(sig1.signature, sig2.signature);
        assertEq(sig1.commitment, sig2.commitment);

        PublicKey memory pubKey = privKey.toPublicKey();
        assertTrue(pubKey.verify(message, sig1));
        assertTrue(pubKey.verify(message, sig2));
    }

    function testFuzz_sign_RevertsIf_PrivateKeyInvalid(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(!privKey.isValid());

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.sign(privKey, message);

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.sign(privKey, keccak256(message));
    }

    function testFuzz_signEthereumSignedMessageHash(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        Signature memory sig1 =
            wrapper.signEthereumSignedMessageHash(privKey, message);
        Signature memory sig2 =
            wrapper.signEthereumSignedMessageHash(privKey, keccak256(message));

        assertEq(sig1.signature, sig2.signature);
        assertEq(sig1.commitment, sig2.commitment);

        PublicKey memory pubKey = privKey.toPublicKey();
        assertTrue(
            pubKey.verify(
                Message.deriveEthereumSignedMessageHash(message), sig1
            )
        );
        assertTrue(
            pubKey.verify(
                Message.deriveEthereumSignedMessageHash(message), sig2
            )
        );
    }

    function testFuzz_signEthereumSignedMessageHash_RevertsIf_PrivateKeyInvalid(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(!privKey.isValid());

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.signEthereumSignedMessageHash(privKey, message);

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.signEthereumSignedMessageHash(privKey, keccak256(message));
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- Signature::isMalleable

    function testFuzz_Signature_isMalleable(Signature memory sig) public {
        sig.signature =
            bytes32(_bound(uint(sig.signature), Secp256k1.Q, type(uint).max));

        assertTrue(wrapper.isMalleable(sig));
    }

    function testFuzz_Signature_isMalleable_FailsIf_SignatureNotMalleable(
        Signature memory sig
    ) public {
        vm.assume(uint(sig.signature) < Secp256k1.Q);

        assertFalse(wrapper.isMalleable(sig));
    }

    // -- Signature::toString

    function test_Signature_toString() public {
        Signature memory sig = Signature({
            signature: bytes32(type(uint).max),
            commitment: address(0x0)
        });

        string memory got = wrapper.toString(sig);
        string memory want = string.concat(
            "Schnorr::Signature {\n",
            "    signature: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\n",
            "    commitment: 0x0000000000000000000000000000000000000000\n",
            "  }"
        );

        assertEq(got, want);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract SchnorrWrapper {
    using Schnorr for PrivateKey;
    using Schnorr for PublicKey;
    using Schnorr for Signature;

    //--------------------------------------------------------------------------
    // Signature Verification

    function verify(
        PublicKey memory pubKey,
        bytes memory message,
        Signature memory sig
    ) public pure returns (bool) {
        return pubKey.verify(message, sig);
    }

    function verify(
        PublicKey memory pubKey,
        bytes32 digest,
        Signature memory sig
    ) public pure returns (bool) {
        return pubKey.verify(digest, sig);
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    function sign(PrivateKey privKey, bytes memory message)
        public
        returns (Signature memory)
    {
        return privKey.sign(message);
    }

    function sign(PrivateKey privKey, bytes32 digest)
        public
        returns (Signature memory)
    {
        return privKey.sign(digest);
    }

    function signEthereumSignedMessageHash(
        PrivateKey privKey,
        bytes memory message
    ) public returns (Signature memory) {
        return privKey.signEthereumSignedMessageHash(message);
    }

    function signEthereumSignedMessageHash(PrivateKey privKey, bytes32 digest)
        public
        returns (Signature memory)
    {
        return privKey.signEthereumSignedMessageHash(digest);
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
