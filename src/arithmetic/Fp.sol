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

import "src/Errors.sol" as Errors;

/**
 * @notice Felt is an secp256k1 field element
 *
 * @dev An secp256k1 field element is a scalar ∊ [0, P).
 *
 * @custom:example Constructing a secp256k1 field element:
 *
 *      ```solidity
 *      import {Fp, Felt} from "crysol/arithmetic/Fp.sol";
 *      contract Example {
 *          (Felt felt, bool ok) = Fp.tryFromUint(uint(1));
 *          assert(ok);
 *      }
 *      ```
 */
type Felt is uint;

/**
 * @title Fp
 *
 * @notice Provides arithmetic functionality within secp256k1's prime field
 *
 * @custom:references
 *      - [Dubois 2023]: https://eprint.iacr.org/2023/939.pdf
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Fp {
    using Fp for Felt;

    //--------------------------------------------------------------------------
    // Optimization Constants

    /// @dev Used during modular inversion.
    uint private constant _P_MINUS_2 = addmod(0, P - 2, P);

    //--------------------------------------------------------------------------
    // UNDEFINED Constants

    /// @dev The undefined felt instance.
    ///
    ///      This felt instantiation is used to indicate undefined behaviour.
    Felt private constant _UNDEFINED_FELT = Felt.wrap(type(uint).max);

    //--------------------------------------------------------------------------
    // Secp256k1 Constants
    //
    // Reimported from Secp256k1.

    uint internal constant P = Secp256k1.P;

    //--------------------------------------------------------------------------
    // Felt Constants

    Felt internal constant ZERO = Felt.wrap(0);
    Felt internal constant ONE = Felt.wrap(1);

    //--------------------------------------------------------------------------
    // Type Conversions

    /// @dev Tries to instantiate a felt from scalar `scalar`.
    ///
    /// @dev Note that returned felt is undefined if function fails to
    ///      instantiate felt.
    function tryFromUint(uint scalar) internal pure returns (Felt, bool) {
        if (scalar >= P) {
            return (_UNDEFINED_FELT, false);
        }

        return (Felt.wrap(scalar), true);
    }

    /// @dev Instantiates felt from scalar `scalar`.
    ///
    /// @dev Reverts if:
    ///        Scalar not a felt
    function fromUint(uint scalar) internal pure returns (Felt) {
        (Felt felt, bool ok) = tryFromUint(scalar);
        if (!ok) {
            revert Errors.CRYSOL_ScalarInvalid();
        }

        return felt;
    }

    /// @dev Instantiates felt from scalar `scalar` without performing safety
    ///      checks.
    ///
    /// @dev This function is unsafe and may lead to undefined behaviour if
    ///      used incorrectly.
    function unsafeFromUint(uint scalar) internal pure returns (Felt) {
        return Felt.wrap(scalar);
    }

    /// @dev Returns felt `felt` as uint.
    function asUint(Felt felt) internal pure returns (uint) {
        return Felt.unwrap(felt);
    }

    //--------------------------------------------------------------------------
    // Predicates

    /// @dev Returns whether felt `felt` is valid.
    function isValid(Felt felt) internal pure returns (bool) {
        return felt.asUint() < P;
    }

    /// @dev Returns whether felt `felt` is zero.
    function isZero(Felt felt) internal pure returns (bool) {
        return felt.asUint() == 0;
    }

    /// @dev Returns whether felt `felt` is the inverse of `feltInv`.
    function isInv(Felt felt, Felt feltInv) internal pure returns (bool) {
        return mulmod(felt.asUint(), feltInv.asUint(), P) == 1;
    }

    //--------------------------------------------------------------------------
    // Arithmetic Functions

    /// @dev Adds felts `felt` and `other` and returns the result.
    function add(Felt felt, Felt other) internal pure returns (Felt) {
        uint result = addmod(felt.asUint(), other.asUint(), P);
        // assert(result < P);

        return unsafeFromUint(result);
    }

    /// @dev Subtracts felts `other` from `felt` and returns the result.
    function sub(Felt felt, Felt other) internal pure returns (Felt) {
        uint result;
        unchecked {
            result = addmod(felt.asUint(), P - other.asUint(), P);
        }
        // assert(result < P);

        return unsafeFromUint(result);
    }

    /// @dev Multiplicates felt `felt` with `other` and returns the result.
    function mul(Felt felt, Felt other) internal pure returns (Felt) {
        uint result = mulmod(felt.asUint(), other.asUint(), P);
        // assert(result < P);

        return unsafeFromUint(result);
    }

    /// @dev Divides felt `felt` with `other` and returns the result.
    ///
    /// @dev Reverts if:
    ///        Other is zero
    function div(Felt felt, Felt other) internal view returns (Felt) {
        if (other.isZero()) {
            revert Errors.CRYSOL_DivByZero();
        }

        uint result = mulmod(felt.asUint(), other.inv().asUint(), P);
        // assert(result < P);

        return unsafeFromUint(result);
    }

    /// @dev Returns the parity of felt `felt` as 0 if even and 1 if odd.
    function parity(Felt felt) internal pure returns (uint) {
        return felt.asUint() & 1;
    }

    /// @dev Returns the inverse of felt `felt`.
    ///
    /// @dev Reverts if:
    ///        Felt is zero
    function inv(Felt felt) internal view returns (Felt) {
        if (felt.isZero()) {
            revert Errors.CRYSOL_InvOfZero();
        }

        // Note that while modular inversion is usually performed using the
        // extended Euclidean algorithm this function uses modular
        // exponentiation based on Fermat's little theorem from which follows:
        //  ∀ p ∊ Uint: ∀ x ∊ [1, p): p.isPrime() → xᵖ⁻² ≡ x⁻¹ (mod p)
        //
        // Note that modular exponentiation can be efficiently computed via the
        // `modexp` precompile. Due to the precompile's price structure the
        // expected gas usage is lower than using the extended Euclidean
        // algorithm.
        //
        // For further details, see [Dubois 2023].
        return exp(felt, unsafeFromUint(_P_MINUS_2));
    }

    /// @dev Computes the exponentiation of felt `base` with exponent `exponent`
    ///      and returns the result.
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

        return unsafeFromUint(result);
    }
}
