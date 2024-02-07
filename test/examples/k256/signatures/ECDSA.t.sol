// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {ECDSAExample} from "examples/k256/signatures/ECDSA.sol";

/**
 * @title ECDSAExamplesTest
 *
 * @notice Tests ECDSA examples in examples/k256/signatures/ECDSA.sol.
 */
contract ECDSAExamplesTest is Test {
    ECDSAExample example;

    function setUp() public {
        example = new ECDSAExample();
    }

    function test_run() public {
        example.run();
    }
}
