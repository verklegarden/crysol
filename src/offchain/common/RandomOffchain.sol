/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

/**
 * @title RandomOffchain
 *
 * @notice Provides offchain access to cryptographically secure randomness
 *
 * @dev Randomness is sourced from cast's `wallet new` command.
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library RandomOffchain {
    // ~~~~~~~ Prelude ~~~~~~~
    // forgefmt: disable-start
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));
    modifier vmed() {
        if (block.chainid != 31337) revert("requireVm");
        _;
    }
    // forgefmt: disable-end
    // ~~~~~~~~~~~~~~~~~~~~~~~

    /// @dev Returns 32 bytes of cryptographically sound randomness.
    ///
    /// @custom:vm readUint()(uint)
    function readBytes32() internal vmed returns (bytes32) {
        return bytes32(readUint());
    }

    /// @dev Returns 256 bit of cryptographically sound randomness.
    ///
    /// @custom:vm ffi `cast wallet new`
    function readUint() internal vmed returns (uint) {
        string[] memory inputs = new string[](3);
        inputs[0] = "cast";
        inputs[1] = "wallet";
        inputs[2] = "new";

        bytes memory result = vm.ffi(inputs);

        // Note that while parts of `cast wallet new` output are constant it
        // always contains the new wallet's secret key and is therefore unique.
        //
        // Note that cast is trusted to create cryptographically secure wallets.
        return uint(keccak256(result));
    }
}
