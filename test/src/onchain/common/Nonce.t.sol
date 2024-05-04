// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Nonce} from "src/onchain/common/Nonce.sol";

/**
 * @notice Nonce Unit Tests
 */
contract NonceTest is Test {
    NonceWrapper wrapper;

    function setUp() public {
        wrapper = new NonceWrapper();
    }

    function testFuzz_deriveNonce_IsDeterministic(uint sk, bytes memory message)
        public
    {
        uint nonce1;
        uint nonce2;

        // Using deriveNonceFrom message.
        nonce1 = wrapper.deriveNonce(sk, message);
        nonce2 = wrapper.deriveNonce(sk, message);
        assertEq(nonce1, nonce2);

        // Using deriveNonceFrom digest.
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
    function deriveNonce(uint sk, bytes memory message)
        public
        pure
        returns (uint)
    {
        return Nonce.deriveNonceFrom(sk, message);
    }

    function deriveNonce(uint sk, bytes32 digest) public pure returns (uint) {
        return Nonce.deriveNonceFrom(sk, digest);
    }
}
