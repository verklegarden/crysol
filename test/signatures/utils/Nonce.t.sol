// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Nonce} from "src/signatures/utils/Nonce.sol";

import {Secp256k1, PrivateKey} from "src/curves/Secp256k1.sol";

/**
 * @notice Nonce Unit Tests
 */
contract NonceTest is Test {
    using Nonce for PrivateKey;
    using Secp256k1 for PrivateKey;

    NonceWrapper wrapper;

    function setUp() public {
        wrapper = new NonceWrapper();
    }

    // TODO: Not necessary if FieldElement type would be used.
    function testFuzz_deriveNonce_IsSecp256k1FieldElement(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        bytes32 digest = keccak256(message);

        assertTrue(wrapper.deriveNonce(privKey, message) < Secp256k1.Q);
        assertTrue(wrapper.deriveNonce(privKey, digest) < Secp256k1.Q);
    }

    function testFuzz_deriveNonce_IsDeterministic(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        uint nonce1;
        uint nonce2;

        // Using deriveNonce from message.
        nonce1 = wrapper.deriveNonce(privKey, message);
        nonce2 = wrapper.deriveNonce(privKey, message);
        assertEq(nonce1, nonce2);

        // Using deriveNonce from digest.
        bytes32 digest = keccak256(message);
        nonce1 = wrapper.deriveNonce(privKey, digest);
        nonce2 = wrapper.deriveNonce(privKey, digest);
        assertEq(nonce1, nonce2);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract NonceWrapper {
    using Nonce for PrivateKey;

    function deriveNonce(PrivateKey privKey, bytes memory message)
        public
        pure
        returns (uint)
    {
        return privKey.deriveNonce(message);
    }

    function deriveNonce(PrivateKey privKey, bytes32 digest)
        public
        pure
        returns (uint)
    {
        return privKey.deriveNonce(digest);
    }
}
