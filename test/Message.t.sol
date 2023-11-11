// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Message} from "src/Message.sol";

import {MessageWrapper} from "./MessageWrapper.sol";

contract MessageTest is Test {
    MessageWrapper wrapper;

    function setUp() public {
        wrapper = new MessageWrapper();
    }

    function test_X() public {}
}
