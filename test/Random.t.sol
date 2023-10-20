// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Random} from "src/Random.sol";

contract RandomTest is Test {
    function test_readUint() public {
        uint a = Random.readUint();
        uint b = Random.readUint();

        assertNotEq(a, b);
    }
}
