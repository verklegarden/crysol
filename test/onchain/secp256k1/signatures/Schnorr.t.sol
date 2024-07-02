// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Message} from "src/onchain/common/Message.sol";

import {Secp256k1Offchain} from "src/offchain/secp256k1/Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256k1/Secp256k1.sol";

import {
    Schnorr, Signature
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
            pk, message, Secp256k1.secretKeyFromUint(1).sign(message)
        );
        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(
            pk, keccak256(message), Secp256k1.secretKeyFromUint(1).sign(message)
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
    // Utils

    function isMalleable(Signature memory sig) public pure returns (bool) {
        return sig.isMalleable();
    }
}
