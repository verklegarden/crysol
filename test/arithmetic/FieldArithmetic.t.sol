// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1} from "src/Secp256k1.sol";
import {FieldArithmetic, Felt} from "src/arithmetic/FieldArithmetic.sol";

/**
 * @notice FieldArithmetic Unit Tests
 */
contract FieldArithmeticTest is Test {
    using FieldArithmetic for Felt;

    FieldArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new FieldArithmeticWrapper();
    }

    //--------------------------------------------------------------------------
    // Felt Constants

    function test_ZERO() public view {
        assertEq(wrapper.ZERO().asUint(), 0);
    }

    function test_ONE() public view {
        assertEq(wrapper.ONE().asUint(), 1);
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    // -- tryFeltFromUint

    function testFuzz_tryFeltFromUint(uint seed) public view {
        uint scalar = _bound(seed, 0, Secp256k1.P - 1);

        (Felt felt, bool ok) = wrapper.tryFeltFromUint(scalar);
        assertTrue(ok);
        assertTrue(felt.isValid());

        assertEq(felt.asUint(), scalar);
    }

    function testFuzz_tryFeltFromUint_FailsIf_ScalarGreaterThanP(uint seed)
        public
        view
    {
        uint scalar = _bound(seed, Secp256k1.P, type(uint).max);

        (, bool ok) = wrapper.tryFeltFromUint(scalar);
        assertFalse(ok);
    }

    // -- feltFromUint

    function testFuzz_feltFromUint(uint seed) public view {
        uint scalar = _bound(seed, 0, Secp256k1.P - 1);

        Felt felt = wrapper.feltFromUint(scalar);
        assertTrue(felt.isValid());

        assertEq(felt.asUint(), scalar);
    }

    function testFuzz_feltFromUint_RevertsIf_ScalarGreaterThanP(uint seed)
        public
    {
        uint scalar = _bound(seed, Secp256k1.P, type(uint).max);

        vm.expectRevert("ScalarNotAFelt()");
        wrapper.feltFromUint(scalar);
    }

    // -- unsafeFeltFromUint

    function testFuzz_unsafeFeltFromUint(uint scalar) public view {
        Felt felt = wrapper.unsafeFeltFromUint(scalar);

        assertEq(felt.asUint(), scalar);
    }

    // -- asUint

    function testFuzz_asUint(uint scalar) public view {
        assertEq(
            scalar, wrapper.asUint(FieldArithmetic.unsafeFeltFromUint(scalar))
        );
    }

    //--------------------------------------------------------------------------
    // Arithmetic Functions

    // -- add

    function testFuzz_add() public view {
        Felt a = FieldArithmetic.unsafeFeltFromUint(Secp256k1.P - 1);
        Felt b = FieldArithmetic.unsafeFeltFromUint(1);

        Felt result = wrapper.add(a, b);
        assertEq(result.asUint(), 0);
    }

    // -- sub

    function test_sub() public view {
        Felt a = FieldArithmetic.unsafeFeltFromUint(1);
        Felt b = FieldArithmetic.unsafeFeltFromUint(2);

        Felt result = wrapper.sub(a, b);
        assertEq(result.asUint(), Secp256k1.P - 1);
    }

    // -- mul

    function test_mul() public view {
        Felt a = FieldArithmetic.unsafeFeltFromUint((Secp256k1.P / 2) + 1);
        Felt b = FieldArithmetic.unsafeFeltFromUint(2);

        Felt result = wrapper.mul(a, b);
        assertEq(result.asUint(), 1);
    }

    // -- div

    function test_div() public view {
        Felt a = FieldArithmetic.unsafeFeltFromUint(6);
        Felt b = FieldArithmetic.unsafeFeltFromUint(2);

        Felt result = wrapper.div(a, b);
        assertEq(result.asUint(), 3);
    }

    function testFuzz_div_RevertsIf_DivisorIsZero(Felt a) public {
        vm.assume(a.isValid());

        vm.expectRevert("DivByZero()");
        wrapper.div(a, FieldArithmetic.ZERO);
    }

    // -- parity

    function testFuzz_parity(Felt felt) public view {
        vm.assume(felt.isValid());

        if (felt.asUint() % 2 == 0) {
            assertEq(wrapper.parity(felt), 0);
        } else {
            assertEq(wrapper.parity(felt), 1);
        }
    }

    // -- inv

    function testFuzz_inv(Felt felt) public view {
        vm.assume(felt.isValid());

        vm.assume(!felt.isZero());

        Felt feltInv = wrapper.inv(felt);
        assertTrue(felt.isInv(feltInv));
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract FieldArithmeticWrapper {
    using FieldArithmetic for Felt;

    //--------------------------------------------------------------------------
    // Felt Constants

    function ZERO() public pure returns (Felt) {
        return FieldArithmetic.ZERO;
    }

    function ONE() public pure returns (Felt) {
        return FieldArithmetic.ONE;
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    function tryFeltFromUint(uint scalar) public pure returns (Felt, bool) {
        return FieldArithmetic.tryFeltFromUint(scalar);
    }

    function feltFromUint(uint scalar) public pure returns (Felt) {
        return FieldArithmetic.feltFromUint(scalar);
    }

    function unsafeFeltFromUint(uint scalar) public pure returns (Felt) {
        return FieldArithmetic.unsafeFeltFromUint(scalar);
    }

    function asUint(Felt felt) public pure returns (uint) {
        return FieldArithmetic.asUint(felt);
    }

    //--------------------------------------------------------------------------
    // Arithmetic Functions

    function add(Felt felt, Felt other) public pure returns (Felt) {
        return felt.add(other);
    }

    function sub(Felt felt, Felt other) public pure returns (Felt) {
        return felt.sub(other);
    }

    function mul(Felt felt, Felt other) public pure returns (Felt) {
        return felt.mul(other);
    }

    function div(Felt felt, Felt other) public view returns (Felt) {
        return felt.div(other);
    }

    function parity(Felt felt) public pure returns (uint) {
        return felt.parity();
    }

    function inv(Felt felt) public view returns (Felt) {
        return felt.inv();
    }

    function exp(Felt base, Felt exponent) public view returns (Felt) {
        return base.exp(exponent);
    }

    //--------------------------------------------------------------------------
    // Predicates

    function isValid(Felt felt) public pure returns (bool) {
        return felt.isValid();
    }

    function isZero(Felt felt) public pure returns (bool) {
        return felt.isZero();
    }

    function isInv(Felt felt, Felt feltInv) public pure returns (bool) {
        return felt.isInv(feltInv);
    }
}
