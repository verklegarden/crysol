// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {ModularArithmetic} from "src/onchain/common/ModularArithmetic.sol";

/**
 * @notice ModularArithmetic Unit Tests
 */
contract ModularArithmeticTest is Test {
    ModularArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new ModularArithmeticWrapper();
    }

    // -- computeInverse

    function test_computeInverse() public {
        vm.skip(true);
        // TODO: Implement computeInverse() tests.
    }

    // -- computeExponentiation

    function test_computeExponentiation() public {
        vm.skip(true);
        // TODO: Implement computeExponentiation() tests.
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract ModularArithmeticWrapper {}
