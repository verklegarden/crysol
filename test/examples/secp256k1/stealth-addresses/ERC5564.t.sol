// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {ERC5564Example} from "examples/secp256k1/stealth-addresses/ERC5564.sol";

contract ERC5564ExamplesTest is Test {
    ERC5564Example example;

    function setUp() public {
        example = new ERC5564Example();
    }

    function test_run() public {
        example.run();
    }
}
