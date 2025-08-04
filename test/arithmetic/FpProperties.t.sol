// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {Secp256k1} from "src/Secp256k1.sol";
import {Fp, Felt} from "src/arithmetic/Fp.sol";

/**
 * @notice Fp Property Tests
 */
contract FpPropertiesTest is Test {
    using Fp for Felt;

    //--------------------------------------------------------------------------
    // Arithmetic Functions

    // -- add + sub

    function testProperty_add_ResultIsFelt(Felt a, Felt b) public pure {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        Felt result = a.add(b);
        assertTrue(result.isValid());
        assertTrue(result.asUint() < Secp256k1.P);
    }

    function testProperty_sub_ResultIsFelt(Felt a, Felt b) public pure {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        Felt result = a.sub(b);
        assertTrue(result.isValid());
        assertTrue(result.asUint() < Secp256k1.P);
    }

    function testProperty_addsub_Relation(Felt a, Felt b) public pure {
        //   a + b = result
        // ↔ result - b = a
        // ↔ result - a = b
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        Felt result = a.add(b);
        assertEq(result.sub(b).asUint(), a.asUint());
        assertEq(result.sub(a).asUint(), b.asUint());
    }

    // -- mul + div

    function testProperty_mul_ResultIsFelt(Felt a, Felt b) public pure {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        Felt result = a.mul(b);
        assertTrue(result.isValid());
        assertTrue(result.asUint() < Secp256k1.P);
    }

    function testProperty_div_ResultIsFelt(Felt a, Felt b) public view {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        vm.assume(!b.isZero());

        Felt result = a.div(b);
        assertTrue(result.isValid());
        assertTrue(result.asUint() < Secp256k1.P);
    }

    function testProperty_muldiv_Relation(Felt a, Felt b) public view {
        //   a * b = result ∧ a != 0 ∧ b != 0
        // ↔ result / b = a
        // ↔ result / a = b
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        vm.assume(!a.isZero());
        vm.assume(!b.isZero());

        Felt result = a.mul(b);
        assertEq(result.div(b).asUint(), a.asUint());
        assertEq(result.div(a).asUint(), b.asUint());
    }

    // -- parity

    function testProperty_parity_IsZeroOrOne(Felt a) public pure {
        vm.assume(a.isValid());

        uint parity = a.parity();
        assertTrue(parity == 0 || parity == 1);
    }

    // -- inv

    function testProperty_inv_ResultIsFelt(Felt a) public view {
        vm.assume(a.isValid());

        vm.assume(!a.isZero());

        Felt result = a.inv();
        assertTrue(result.isValid());
        assertTrue(result.asUint() < Secp256k1.P);
    }

    // -- exp

    function testProperty_exp_ResultIsFelt(Felt a, Felt b) public view {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        Felt result = a.exp(b);
        assertTrue(result.isValid());
        assertTrue(result.asUint() < Secp256k1.P);
    }
}
