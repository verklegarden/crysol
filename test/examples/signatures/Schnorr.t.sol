// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {SchnorrExample} from "examples/signatures/Schnorr.sol";

/**
 * @title SchnorrExamplesTest
 *
 * @notice Tests Schnorr examples in src/examples/.
 */
contract SchnorrExamplesTest is Test {
    SchnorrExample example;

    function setUp() public {
        example = new SchnorrExample();
    }

    function test_signAndVerify() public {
        example.signAndVerify();
    }
}
