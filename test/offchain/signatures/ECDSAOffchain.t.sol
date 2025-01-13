// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";

import {ECDSAOffchain} from "offchain/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

import "src/Errors.sol" as Errors;

/**
 * @notice ECDSAOffchain Unit Tests
 */
contract ECDSAOffchainTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;

    using ECDSA for PublicKey;

    ECDSAOffchainWrapper wrapper;

    function setUp() public {
        wrapper = new ECDSAOffchainWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Creation

    // -- sign

    function testFuzz_sign(SecretKey sk, bytes32 digest) public {
        vm.assume(sk.isValid());

        bytes32 m = ECDSA.constructMessageHash(digest);

        Signature memory sig = wrapper.sign(sk, digest);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testFuzz_sign_RevertsIf_SecretKeyInvalid(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(!sk.isValid());

        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.sign(sk, digest);
    }

    // -- signRaw

    function testFuzz_signRaw(SecretKey sk, bytes32 m) public {
        vm.assume(sk.isValid());

        Signature memory sig = wrapper.signRaw(sk, m);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testFuzz_signRaw_RevertsIf_SecretKeyInvalid(
        SecretKey sk,
        bytes32 m
    ) public {
        vm.assume(!sk.isValid());

        vm.expectRevert(Errors.CRYSOL_SecretKeyInvalid.selector);
        wrapper.signRaw(sk, m);
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- Signature::toString

    function test_Signature_toString() public view {
        Signature memory sig = Signature({
            v: 27,
            r: bytes32(type(uint).max),
            s: bytes32(type(uint).max)
        });

        string memory got = wrapper.toString(sig);
        string memory want =
            "ECDSA({ v: 27, r: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, s: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff })";

        assertEq(got, want);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract ECDSAOffchainWrapper {
    using ECDSAOffchain for SecretKey;
    using ECDSAOffchain for Signature;

    //--------------------------------------------------------------------------
    // Signature Creation

    function sign(SecretKey sk, bytes32 digest)
        public
        pure
        returns (Signature memory)
    {
        return sk.sign(digest);
    }

    function signRaw(SecretKey sk, bytes32 m)
        public
        pure
        returns (Signature memory)
    {
        return sk.signRaw(m);
    }

    //--------------------------------------------------------------------------
    // Utils

    function toString(Signature memory sig)
        public
        pure
        returns (string memory)
    {
        return sig.toString();
    }
}
