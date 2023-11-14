// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Message} from "src/Message.sol";

contract MessageTest is Test {
    MessageWrapper wrapper;

    function setUp() public {
        wrapper = new MessageWrapper();
    }

    function test_deriveEthereumMessageHash_From_Bytes() public {
        // @todo Compute/Find test vector.
    }

    function test_deriveEthereumMessageHash_From_Digest() public {
        // @todo Compute/Find test vector.
    }
}

/**
 * @title MessageWrapper
 *
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract MessageWrapper {
    function deriveEthereumMessageHash(bytes memory message)
        public
        pure
        returns (bytes32)
    {
        return Message.deriveEthereumMessageHash(message);
    }

    function deriveEthereumMessageHash(bytes32 digest)
        public
        pure
        returns (bytes32)
    {
        return Message.deriveEthereumMessageHash(digest);
    }
}
