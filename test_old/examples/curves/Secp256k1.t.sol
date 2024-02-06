// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {Secp256k1Example} from "examples/curves/Secp256k1.sol";

/**
 * @title Secp256k1ExamplesTest
 *
 * @notice Tests secp256k1 examples in examples/curves/Secp256kk1.sol.
 */
contract Secp256k1ExamplesTest is Test {
    Secp256k1Example example;

    function setUp() public {
        example = new Secp256k1Example();
    }

    function test_run() public {
        example.run();
    }
}
