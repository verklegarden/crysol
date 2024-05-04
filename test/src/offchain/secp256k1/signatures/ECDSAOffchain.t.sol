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

import {ECDSAOffchain} from
    "src/offchain/secp256k1/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/onchain/secp256k1/signatures/ECDSA.sol";
import {ECDSAUnsafe} from "src/unsafe/secp256k1/signatures/ECDSAUnsafe.sol";

/**
 * @notice ECDSAOffchain Unit Tests
 */
contract ECDSAOffchainTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using ECDSA for PublicKey;

    ECDSAOffchainWrapper wrapper;

    function setUp() public {
        wrapper = new ECDSAOffchainWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Creation

    function testFuzz_sign(SecretKey sk, bytes memory message) public {
        vm.assume(sk.isValid());

        Signature memory sig1 = wrapper.sign(sk, message);
        Signature memory sig2 = wrapper.sign(sk, keccak256(message));

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);

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

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);

        PublicKey memory pk = sk.toPublicKey();
        assertTrue(
            pk.verify(Message.deriveEthereumSignedMessageHash(message), sig1)
        );
        assertTrue(
            pk.verify(
                Message.deriveEthereumSignedMessageHash(keccak256(message)),
                sig2
            )
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

    // -- Signature::toString

    function test_Signature_toString() public {
        Signature memory sig = Signature({
            v: 27,
            r: bytes32(type(uint).max),
            s: bytes32(type(uint).max)
        });

        string memory got = wrapper.toString(sig);
        string memory want =
            "ECDSA::Signature({ v: 27, r: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, s: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff })";

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

    function sign(SecretKey sk, bytes memory message)
        public
        view
        returns (Signature memory)
    {
        return sk.sign(message);
    }

    function sign(SecretKey sk, bytes32 digest)
        public
        view
        returns (Signature memory)
    {
        return sk.sign(digest);
    }

    function signEthereumSignedMessageHash(SecretKey sk, bytes memory message)
        public
        view
        returns (Signature memory)
    {
        return sk.signEthereumSignedMessageHash(message);
    }

    function signEthereumSignedMessageHash(SecretKey sk, bytes32 digest)
        public
        view
        returns (Signature memory)
    {
        return sk.signEthereumSignedMessageHash(digest);
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
}
