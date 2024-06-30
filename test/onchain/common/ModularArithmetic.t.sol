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

    function testFuzz_computeInverse_ReturnsIdentity_IfIdentity(uint prime)
        public
    {
        // Note to just assume prime to be a prime.
        vm.assume(prime > 1);

        assertEq(wrapper.computeInverse(1, prime), 1);
    }

    function testFuzz_computeInverse_RevertsIf_XIsZero(uint prime) public {
        // Note to just assume prime to be a prime.

        vm.expectRevert("ModularInverseOfZeroDoesNotExist()");
        wrapper.computeInverse(0, prime);
    }

    function testFuzz_computeInverse_RevertsIf_XGreaterThanOrEqualToPrime(
        uint x,
        uint prime
    ) public {
        // Note to just assume prime to be a prime.
        vm.assume(x >= prime);

        vm.expectRevert("ModularInverseOfXGreaterThanPrime()");
        wrapper.computeInverse(x, prime);
    }

    // -- computeExponentiation

    function test_computeExponentiation() public {
        vm.skip(true);
        // TODO: Implement computeExponentiation() tests.
    }

    function testFuzz_computeExponentiation_RevertsIf_OutOfGas(
        uint base,
        uint exponent,
        uint prime
    ) public {
        // Note that modexp's min gas cost is 200.
        try wrapper.computeExponentiation{gas: 200}(base, exponent, prime)
        returns (uint) {
            fail();
        } catch {}
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract ModularArithmeticWrapper {
    function computeInverse(uint x, uint prime) public view returns (uint) {
        return ModularArithmetic.computeInverse(x, prime);
    }

    function computeExponentiation(uint base, uint exponent, uint prime)
        public
        view
        returns (uint)
    {
        return ModularArithmetic.computeExponentiation(base, exponent, prime);
    }
}
