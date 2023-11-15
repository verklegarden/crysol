// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

import {Message} from "src/Message.sol";

/**
 * @notice Message's Specification
 */
library MessageSpec {
    Vm private constant vm =
        Vm(address(uint160(uint(keccak256("hevm cheat code")))));

    function deriveEthereumMessageHash(bytes memory message)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32", keccak256(message)
            )
        );
    }

    function deriveEthereumMessageHash(bytes32 digest)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
    }
}
