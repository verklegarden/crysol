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
    Secp256k1Arithmetic,
    Point
} from "src/onchain/secp256k1/Secp256k1Arithmetic.sol";

import {SchnorrOffchain} from
    "src/offchain/secp256k1/signatures/SchnorrOffchain.sol";
import {
    Schnorr, Signature, SignatureCompressed
} from "src/onchain/secp256k1/signatures/Schnorr.sol";

/**
 * @notice SchnorrOffchain Unit Tests
 */
contract SchnorrOffchainTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using Schnorr for PublicKey;

    SchnorrOffchainWrapper wrapper;

    function setUp() public {
        wrapper = new SchnorrOffchainWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Creation

    // -- sign

    function testFuzz_sign(SecretKey sk, bytes32 digest) public {
        vm.assume(sk.isValid());

        bytes32 m = Schnorr.constructMessageHash(digest);

        Signature memory sig = wrapper.sign(sk, digest);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testFuzz_sign_RevertsIf_SecretKeyInvalid(
        SecretKey sk,
        bytes32 digest
    ) public {
        vm.assume(!sk.isValid());

        vm.expectRevert("SecretKeyInvalid()");
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

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.signRaw(sk, m);
    }

    // -- signRaw with rand

    function testFuzz_signRaw_WithRand(SecretKey sk, bytes32 m, bytes32 rand) public {
        vm.assume(sk.isValid());

        Signature memory sig = wrapper.signRaw(sk, m, rand);

        assertTrue(sk.toPublicKey().verify(m, sig));
    }

    function testFuzz_signRaw_WithRand_RevertsIf_SecretKeyInvalid(
        SecretKey sk,
        bytes32 m,
        bytes32 rand
    ) public {
        vm.assume(!sk.isValid());

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.signRaw(sk, m, rand);
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- Signature::toString

    function test_Signature_toString() public view {
        Signature memory sig = Signature({
            s: bytes32(type(uint).max),
            r: Secp256k1Arithmetic.Identity().intoPublicKey()
        });

        string memory got = wrapper.toString(sig);
        string memory want =
            "Schnorr::Signature({ s: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, r: Secp256k1::PublicKey({ x: 0, y: 0 }) })";

        assertEq(got, want);
    }

    // -- SignatureCompressed::toString

    function test_SignatureCompressed_toString() public view {
        SignatureCompressed memory sig = SignatureCompressed({
            s: bytes32(type(uint).max),
            rAddr: address(0x0)
        });

        string memory got = wrapper.toString(sig);
        string memory want =
            "Schnorr::SignatureCompressed({ s: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, rAddr: 0x0000000000000000000000000000000000000000 })";

        assertEq(got, want);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract SchnorrOffchainWrapper {
    using SchnorrOffchain for SecretKey;
    using SchnorrOffchain for Signature;
    using SchnorrOffchain for SignatureCompressed;

    //--------------------------------------------------------------------------
    // Signature Creation

    function sign(SecretKey sk, bytes32 digest)
        public
        returns (Signature memory)
    {
        return sk.sign(digest);
    }

    function signRaw(SecretKey sk, bytes32 m)
        public
        returns (Signature memory)
    {
        return sk.signRaw(m);
    }

    function signRaw(SecretKey sk, bytes32 m, bytes32 rand)
        public
        returns (Signature memory)
    {
        return sk.signRaw(m, rand);
    }

    //--------------------------------------------------------------------------
    // Utils

    function toString(Signature memory sig)
        public
        view
        returns (string memory)
    {
        return sig.toString();
    }

    function toString(SignatureCompressed memory sig)
        public
        view
        returns (string memory)
    {
        return sig.toString();
    }
}
