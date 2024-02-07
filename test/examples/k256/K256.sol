// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {K256Example} from "examples/k256/K256.sol";

/**
 * @title K256ExamplesTest
 *
 * @notice Tests k256 examples in examples/k256/K256.sol.
 */
contract K256ExamplesTest is Test {
    K256Example example;

    function setUp() public {
        example = new K256Example();
    }

    function test_run() public {
        example.run();
    }
}
