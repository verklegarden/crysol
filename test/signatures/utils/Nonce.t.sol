// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Nonce} from "src/signatures/utils/Nonce.sol";

import {Secp256k1, SecretKey} from "src/curves/Secp256k1.sol";

/**
 * @notice Nonce Unit Tests
 */
contract NonceTest is Test {
    using Nonce for SecretKey;
    using Secp256k1 for SecretKey;

    NonceWrapper wrapper;

    function setUp() public {
        wrapper = new NonceWrapper();
    }

    function testFuzz_deriveNonce_IsDeterministic(
        SecretKey sk,
        bytes memory message
    ) public {
        vm.assume(sk.isValid());

        uint nonce1;
        uint nonce2;

        // Using deriveNonce from message.
        nonce1 = wrapper.deriveNonce(sk, message);
        nonce2 = wrapper.deriveNonce(sk, message);
        assertEq(nonce1, nonce2);

        // Using deriveNonce from digest.
        bytes32 digest = keccak256(message);
        nonce1 = wrapper.deriveNonce(sk, digest);
        nonce2 = wrapper.deriveNonce(sk, digest);
        assertEq(nonce1, nonce2);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract NonceWrapper {
    using Nonce for SecretKey;

    function deriveNonce(SecretKey sk, bytes memory message)
        public
        pure
        returns (uint)
    {
        return sk.deriveNonce(message);
    }

    function deriveNonce(SecretKey sk, bytes32 digest)
        public
        pure
        returns (uint)
    {
        return sk.deriveNonce(digest);
    }
}
