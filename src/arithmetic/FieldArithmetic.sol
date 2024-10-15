/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Secp256k1} from "../Secp256k1.sol";

type Felt is uint;

library FieldArithmetic {
    using FieldArithmetic for Felt;

    //--------------------------------------------------------------------------
    // Optimization Constants

    /// @dev Used during modular inversion.
    uint private constant P_MINUS_2 = addmod(0, P - 2, P);

    //--------------------------------------------------------------------------
    // Private Constants
    //
    // Reimported from Secp256k1.

    uint private constant P = Secp256k1.P;

    //--------------------------------------------------------------------------
    // Felt Constants

    Felt internal constant ZERO = Felt.wrap(0);
    Felt internal constant ONE = Felt.wrap(1);

    //--------------------------------------------------------------------------
    // Type Conversions

    function feltFromUint(uint scalar) internal pure returns (Felt) {
        (Felt felt, bool ok) = tryFeltFromUint(scalar);
        if (!ok) {
            revert("ScalarNotAFelt");
        }

        return felt;
    }

    function tryFeltFromUint(uint scalar) internal pure returns (Felt, bool) {
        if (scalar >= P) {
            return (ZERO, false);
        }

        return (Felt.wrap(scalar), true);
    }

    function unsafeFeltFromUint(uint scalar) internal pure returns (Felt) {
        return Felt.wrap(scalar);
    }

    function asUint(Felt felt) internal pure returns (uint) {
        return Felt.unwrap(felt);
    }

    //--------------------------------------------------------------------------
    // Comparison Functions

    /*
    function eq(Felt felt, Felt other) internal pure returns (bool) {
        return felt.asUint() == other.asUint();
    }

    function neq(Felt felt, Felt other) internal pure returns (bool) {
        return felt.asUint() != other.asUint();
    }

    function gt(Felt felt, Felt other) internal pure returns (bool) {
        return felt.asUint() > other.asUint();
    }

    function gte(Felt felt, Felt other) internal pure returns (bool) {
        return felt.asUint() >= other.asUint();
    }

    function lt(Felt felt, Felt other) internal pure returns (bool) {
        return felt.asUint() < other.asUint();
    }

    function lte(Felt felt, Felt other) internal pure returns (bool) {
        return felt.asUint() <= other.asUint();
    }
    */

    //--------------------------------------------------------------------------
    // Arithmetic Functions

    function add(Felt felt, Felt other) internal pure returns (Felt) {
        uint result = addmod(felt.asUint(), other.asUint(), P);
        // assert(result < P);

        return unsafeFeltFromUint(result);
    }

    function sub(Felt felt, Felt other) internal pure returns (Felt) {
        uint result;
        unchecked {
            result = addmod(felt.asUint(), P - other.asUint(), P);
        }
        // assert(result < P);

        return unsafeFeltFromUint(result);
    }

    function mul(Felt felt, Felt other) internal pure returns (Felt) {
        uint result = mulmod(felt.asUint(), other.asUint(), P);
        // assert(result < P);

        return unsafeFeltFromUint(result);
    }

    function div(Felt felt, Felt other) internal view returns (Felt) {
        if (other.isZero()) {
            revert("DivByZero()");
        }

        uint result = mulmod(felt.asUint(), other.inv().asUint(), P);
        // assert(result < P);

        return unsafeFeltFromUint(result);
    }

    function parity(Felt felt) internal pure returns (uint) {
        return felt.asUint() & 1;
    }

    function inv(Felt felt) internal view returns (Felt) {
        if (felt.isZero()) {
            revert("InvOfZero()");
        }

        return exp(felt, unsafeFeltFromUint(P_MINUS_2));
    }

    function exp(Felt base, Felt exponent) internal view returns (Felt) {
        // Payload to compute base^{exponent} (mod P).
        // Note that the size of each argument is 32 bytes.
        bytes memory payload =
            abi.encode(32, 32, 32, base.asUint(), exponent.asUint(), P);

        // The `modexp` precompile is at address 0x05.
        address target = address(5);

        ( /*bool ok*/ , bytes memory data) = target.staticcall(payload);
        // assert(ok); // Precompile calls do not fail.

        // Note that abi.decode() reverts if result is empty.
        // Result is empty iff the modexp computation failed due to insufficient
        // gas.
        uint result = abi.decode(data, (uint));
        // assert(result < P);

        return unsafeFeltFromUint(result);
    }

    //--------------------------------------------------------------------------
    // Predicates

    function isValid(Felt felt) internal pure returns (bool) {
        uint scalar = felt.asUint();

        return scalar < P;
    }

    function isZero(Felt felt) internal pure returns (bool) {
        return felt.asUint() == 0;
    }

    // TODO: Docs can be used to verify an inverse received as witness is valid.
    function isInv(Felt felt, Felt feltInv) internal pure returns (bool) {
        return mulmod(felt.asUint(), feltInv.asUint(), P) == 1;
    }
}
