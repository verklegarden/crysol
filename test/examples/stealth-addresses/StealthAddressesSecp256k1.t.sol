// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {StealthAddressesSecp256k1Example} from
    "examples/stealth-addresses/StealthAddressesSecp256k1.sol";

/**
 * @title StealthAddressesSecp256k1ExamplesTest
 *
 * @notice Tests StealthAddressesSecp256k1 examples in
 *         examples/stealth-addresses/StealthAddressesSecp256k1.sol.
 */
contract StealthAddressesSecp256k1ExamplesTest is Test {
    StealthAddressesSecp256k1Example example;

    function setUp() public {
        example = new StealthAddressesSecp256k1Example();
    }

    function test_run() public {
        example.run();
    }
}
