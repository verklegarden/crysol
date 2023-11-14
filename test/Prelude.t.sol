// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

/**
 * @notice Prelude Unit Tests
 */
contract PreludeTest is Test {
    // ~~~~~~~ Prelude ~~~~~~~
    // forgefmt: disable-start

    // Note that vm is already imported via `is Test`.
    //Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));

    modifier vmed() {
        if (block.chainid != 31337) revert("NotVMed()");
        _;
    }
    // forgefmt: disable-end
    // ~~~~~~~~~~~~~~~~~~~~~~~

    function test_vmed() public {
        vmedFunction();
    }

    function testFuzz_vmed_RevertsIf_NotAnvilChainId(uint chainId) public {
        vm.assume(chainId != 31337);

        // Note that foundry expects chainId to be less than 2^64 - 1.
        // TODO(mp): Check whether such EIP exists.
        //           Until then use try-catch to keep test universal.
        try vm.chainId(chainId) {
            vm.expectRevert();
            vmedFunction();
        } catch {}
    }

    function vmedFunction() internal vmed {}
}
