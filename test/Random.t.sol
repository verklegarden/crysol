// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Random} from "src/Random.sol";

import {RandomWrapper} from "./RandomWrapper.sol";

contract RandomTest is Test {
    RandomWrapper wrapper;

    function setUp() public {
        wrapper = new RandomWrapper();
    }

    function test_readUint() public {
        uint a = wrapper.readUint();
        uint b = wrapper.readUint();

        assertNotEq(a, b);
    }
}
