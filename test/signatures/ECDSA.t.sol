// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";
import {ECDSAUnsafe} from "unsafe/ECDSAUnsafe.sol";
import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

import {ECDSAWrapper} from "./ECDSAWrapper.sol";

contract ECDSATest is Test {
    using ECDSA for address;
    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;
    using ECDSAUnsafe for Signature;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    ECDSAWrapper wrapper;

    function setUp() public {
        wrapper = new ECDSAWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Verification

    function testFuzz_verify(PrivateKey privKey, bytes memory message) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();
        bytes32 digest = keccak256(message);

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        Signature memory sig = Signature(v, r, s);

        assertTrue(wrapper.verify(pubKey, message, sig));
        assertTrue(wrapper.verify(pubKey, digest, sig));
        assertTrue(wrapper.verify(pubKey.toAddress(), message, sig));
        assertTrue(wrapper.verify(pubKey.toAddress(), digest, sig));
    }

    function testFuzz_verify_FailsIf_SignatureInvalid(
        PrivateKey privKey,
        bytes memory message,
        uint8 vMask,
        uint rMask,
        uint sMask
    ) public {
        vm.assume(privKey.isValid());
        vm.assume(vMask != 0 || rMask != 0 || sMask != 0);

        PublicKey memory pubKey = privKey.toPublicKey();
        bytes32 digest = keccak256(message);

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        v ^= vMask;
        r = bytes32(uint(r) ^ rMask);
        s = bytes32(uint(s) ^ sMask);

        Signature memory sig = Signature(v, r, s);

        // Note that verify() reverts if signature is malleable.
        sig.intoNonMalleable();

        assertFalse(pubKey.verify(message, sig));
        assertFalse(pubKey.verify(digest, sig));
        assertFalse(pubKey.toAddress().verify(message, sig));
        assertFalse(pubKey.toAddress().verify(digest, sig));
    }

    function testFuzz_verify_RevertsIf_SignatureMalleable(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();
        bytes32 digest = keccak256(message);

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        Signature memory badSig = Signature(v, r, s).intoMalleable();

        vm.expectRevert("SignatureIsMalleable()");
        pubKey.verify(message, badSig);

        vm.expectRevert("SignatureIsMalleable()");
        pubKey.verify(digest, badSig);

        vm.expectRevert("SignatureIsMalleable()");
        pubKey.toAddress().verify(message, badSig);

        vm.expectRevert("SignatureIsMalleable()");
        pubKey.toAddress().verify(digest, badSig);
    }

    function testFuzz_verify_RevertsIf_PublicKeyInvalid(
        PublicKey memory pubKey,
        bytes memory message,
        Signature memory sig
    ) public {
        vm.assume(!pubKey.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        pubKey.verify(message, sig);

        vm.expectRevert("PublicKeyInvalid()");
        pubKey.verify(keccak256(message), sig);
    }

    function testFuzz_verify_RevertsIf_SignerZeroAddress(
        bytes memory message,
        Signature memory sig
    ) public {
        address signer = address(0);

        vm.expectRevert("SignerZeroAddress()");
        signer.verify(message, sig);

        vm.expectRevert("SignerZeroAddress()");
        signer.verify(keccak256(message), sig);
    }

    //--------------------------------------------------------------------------
    // Test: Signature Creation

    function testFuzz_sign(PrivateKey privKey, bytes memory message) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();

        Signature memory sig1 = privKey.sign(message);
        Signature memory sig2 = privKey.sign(keccak256(message));

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);

        assertTrue(pubKey.verify(message, sig1));
        assertTrue(pubKey.verify(message, sig2));
    }

    function testFuzz_sign_RevertsIf_PrivateKeyInvalid(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(!privKey.isValid());

        vm.expectRevert("PrivateKeyInvalid()");
        privKey.sign(message);

        vm.expectRevert("PrivateKeyInvalid()");
        privKey.sign(keccak256(message));
    }

    // @todo Test signEthereum...

    //--------------------------------------------------------------------------
    // Test: Utils

    function testFuzz_isMalleable(bool malleable, Signature memory sig)
        public
    {
        vm.assume(uint(sig.s) < Secp256k1.Q);

        if (malleable) {
            assertTrue(sig.intoMalleable().isMalleable());
        } else {
            assertFalse(sig.intoNonMalleable().isMalleable());
        }
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization
}
