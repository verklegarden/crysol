// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1} from "src/Secp256k1.sol";
import {Fp, Felt} from "src/arithmetic/Fp.sol";

import "src/Errors.sol" as Errors;

/**
 * @notice Fp Unit Tests
 */
contract FpTest is Test {
    using Fp for Felt;

    FpWrapper wrapper;

    function setUp() public {
        wrapper = new FpWrapper();
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

    // -- tryFromUint

    function testFuzz_tryFromUint(uint seed) public view {
        uint scalar = _bound(seed, 0, Secp256k1.P - 1);

        (Felt felt, bool ok) = wrapper.tryFromUint(scalar);
        assertTrue(ok);
        assertTrue(felt.isValid());

        assertEq(felt.asUint(), scalar);
    }

    function testFuzz_tryFromUint_FailsIf_ScalarGreaterThanP(uint seed)
        public
        view
    {
        uint scalar = _bound(seed, Secp256k1.P, type(uint).max);

        (, bool ok) = wrapper.tryFromUint(scalar);
        assertFalse(ok);
    }

    // -- fromUint

    function testFuzz_feltFromUint(uint seed) public view {
        uint scalar = _bound(seed, 0, Secp256k1.P - 1);

        Felt felt = wrapper.feltFromUint(scalar);
        assertTrue(felt.isValid());

        assertEq(felt.asUint(), scalar);
    }

    function testFuzz_feltFromUint_RevertsIf_ScalarNotAFelt(uint seed)
        public
    {
        uint scalar = _bound(seed, Secp256k1.P, type(uint).max);

        vm.expectRevert(Errors.CRYSOL_ScalarNotAFelt.selector);
        wrapper.feltFromUint(scalar);
    }

    // -- unsafeFromUint

    function testFuzz_unsafeFromUint(uint scalar) public view {
        Felt felt = wrapper.unsafeFromUint(scalar);

        assertEq(felt.asUint(), scalar);
    }

    // -- asUint

    function testFuzz_asUint(uint scalar) public view {
        assertEq(scalar, wrapper.asUint(Fp.unsafeFromUint(scalar)));
    }

    //--------------------------------------------------------------------------
    // Predicates

    function testFuzz_isValid(uint scalar) public view {
        Felt felt = Fp.unsafeFromUint(scalar);

        if (scalar < Secp256k1.P) {
            assertTrue(wrapper.isValid(felt));
        } else {
            assertFalse(wrapper.isValid(felt));
        }
    }

    function testFuzz_isZero(uint scalar) public view {
        Felt felt = Fp.unsafeFromUint(scalar);

        if (scalar == 0) {
            assertTrue(wrapper.isZero(felt));
        } else {
            assertFalse(wrapper.isZero(felt));
        }
    }

    function testFuzz_isInv() public {
        // TODO: Test Fp.isInv() via vectors
        vm.skip(true);
    }

    //--------------------------------------------------------------------------
    // Arithmetic Functions

    // -- add

    function testFuzz_add() public view {
        Felt a = Fp.unsafeFromUint(Secp256k1.P - 1);
        Felt b = Fp.unsafeFromUint(1);

        Felt result = wrapper.add(a, b);
        assertEq(result.asUint(), 0);
    }

    // -- sub

    function test_sub() public view {
        Felt a = Fp.unsafeFromUint(1);
        Felt b = Fp.unsafeFromUint(2);

        Felt result = wrapper.sub(a, b);
        assertEq(result.asUint(), Secp256k1.P - 1);
    }

    // -- mul

    function test_mul() public view {
        Felt a = Fp.unsafeFromUint((Secp256k1.P / 2) + 1);
        Felt b = Fp.unsafeFromUint(2);

        Felt result = wrapper.mul(a, b);
        assertEq(result.asUint(), 1);
    }

    // -- div

    function test_div() public view {
        Felt a = Fp.unsafeFromUint(6);
        Felt b = Fp.unsafeFromUint(2);

        Felt result = wrapper.div(a, b);
        assertEq(result.asUint(), 3);
    }

    function testFuzz_div_RevertsIf_DivByZero(Felt a) public {
        vm.assume(a.isValid());

        vm.expectRevert(Errors.CRYSOL_DivByZero.selector);
        wrapper.div(a, Fp.ZERO);
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

    function test_inv_ReturnsIdentity_IfIdentity() public view {
        assertEq(wrapper.inv(Fp.ONE).asUint(), 1);
    }

    function test_inv_RevertsIf_InvOfZero() public {
        vm.expectRevert(Errors.CRYSOL_InvOfZero.selector);
        wrapper.inv(Fp.ZERO);
    }

    // -- exp

    function test_exp() public {
        // TODO: Test Fp.exp() via vectors
        vm.skip(true);
    }

    function testFuzz_exp_RevertsIf_OutOfGas(Felt base, Felt exponent) public {
        vm.assume(base.isValid());
        vm.assume(exponent.isValid());

        // Note that modexp's min gas cost is 200.
        try wrapper.exp{gas: 200}(base, exponent) returns (Felt) {
            fail();
        } catch {}
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract FpWrapper {
    using Fp for Felt;

    //--------------------------------------------------------------------------
    // Felt Constants

    function ZERO() public pure returns (Felt) {
        return Fp.ZERO;
    }

    function ONE() public pure returns (Felt) {
        return Fp.ONE;
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    function tryFromUint(uint scalar) public pure returns (Felt, bool) {
        return Fp.tryFromUint(scalar);
    }

    function feltFromUint(uint scalar) public pure returns (Felt) {
        return Fp.fromUint(scalar);
    }

    function unsafeFromUint(uint scalar) public pure returns (Felt) {
        return Fp.unsafeFromUint(scalar);
    }

    function asUint(Felt felt) public pure returns (uint) {
        return Fp.asUint(felt);
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
}
