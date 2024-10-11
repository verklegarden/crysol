// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {RandomExample} from "examples/Random.sol";

contract RandomExampleTest is Test {
    RandomExample example;

    function setUp() public {
        example = new RandomExample();
    }

    function test_run() public {
        example.run();
    }
}
