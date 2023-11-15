// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Message} from "src/Message.sol";

import {MessageSpec} from "spec/Message.spec.sol";

/**
 * @notice Message Specification Tests
 */
contract MessageSpecTest is Test {
    function testSpec_deriveEthereumMessageHash_From_Bytes(bytes memory message)
        public
    {
        bytes32 got = Message.deriveEthereumMessageHash(message);
        bytes32 want = MessageSpec.deriveEthereumMessageHash(message);

        assertEq(got, want);
    }

    function testSpec_deriveEthereumMessageHash_From_Digest(bytes32 digest)
        public
    {
        bytes32 got = Message.deriveEthereumMessageHash(digest);
        bytes32 want = MessageSpec.deriveEthereumMessageHash(digest);

        assertEq(got, want);
    }
}
