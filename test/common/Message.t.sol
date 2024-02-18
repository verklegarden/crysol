// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Message} from "src/common/Message.sol";

/**
 * @notice Message Unit Tests
 */
contract MessageTest is Test {
    MessageWrapper wrapper;

    bytes constant MESSAGE = bytes("crysol <3");

    bytes32 constant ETHEREUM_SIGNED_MESSAGE_HASH = bytes32(
        0xf0d01579d47c5b662330453e5709f9c1e75de1f1b741f00e20c3c381ab997664
    );

    function setUp() public {
        wrapper = new MessageWrapper();
    }

    function test_deriveEthereumSignedMessageHash_From_Bytes() public {
        assertEq(
            wrapper.deriveEthereumSignedMessageHash(MESSAGE),
            ETHEREUM_SIGNED_MESSAGE_HASH
        );
    }

    function test_deriveEthereumSignedMessageHash_From_Digest() public {
        assertEq(
            wrapper.deriveEthereumSignedMessageHash(keccak256(MESSAGE)),
            ETHEREUM_SIGNED_MESSAGE_HASH
        );
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract MessageWrapper {
    function deriveEthereumSignedMessageHash(bytes memory message)
        public
        pure
        returns (bytes32)
    {
        return Message.deriveEthereumSignedMessageHash(message);
    }

    function deriveEthereumSignedMessageHash(bytes32 digest)
        public
        pure
        returns (bytes32)
    {
        return Message.deriveEthereumSignedMessageHash(digest);
    }
}
