// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {RandomOffchain} from "offchain/common/RandomOffchain.sol";

/**
 * @notice RandomOffchain Unit Tests
 */
contract RandomOffchainTest is Test {
    RandomOffchainWrapper wrapper;

    function setUp() public {
        wrapper = new RandomOffchainWrapper();
    }

    function test_readUint() public {
        uint a = wrapper.readUint();
        uint b = wrapper.readUint();

        assertNotEq(a, b);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract RandomOffchainWrapper {
    function readUint() public returns (uint) {
        return RandomOffchain.readUint();
    }
}
