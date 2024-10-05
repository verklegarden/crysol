// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {CSPRNG} from "offchain/CSPRNG.sol";

/**
 * @title CSPRNGExample
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/CSPRNG.sol:CSPRNGExample -vvvv
 *      ```
 */
contract CSPRNGExample is Script {
    function run() public {
        // Read uint from CSPRNG.
        uint rand = CSPRNG.readUint();
        console.log("Cryptographically secure random uint256: ", rand);
        console.log("");
    }
}
