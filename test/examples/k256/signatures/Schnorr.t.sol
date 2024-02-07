// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {SchnorrExample} from "examples/k256/signatures/Schnorr.sol";

/**
 * @title SchnorrExamplesTest
 *
 * @notice Tests Schnorr examples in examples/k256/signatures/Schnorr.sol.
 */
contract SchnorrExamplesTest is Test {
    SchnorrExample example;

    function setUp() public {
        example = new SchnorrExample();
    }

    function test_run() public {
        example.run();
    }
}
