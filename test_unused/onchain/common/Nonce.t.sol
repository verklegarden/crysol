// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256k1/Secp256k1.sol";
import {Secp256k1Offchain} from "src/offchain/secp256k1/Secp256k1Offchain.sol";

//import {Nonce} from "src/onchain/common/Nonce.sol";

/**
 * @notice Nonce Unit Tests
 */
/*
contract NonceTest is Test {
    using Secp256k1 for SecretKey;
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for PublicKey;

    NonceWrapper wrapper;

    function setUp() public {
        wrapper = new NonceWrapper();
    }

    function testFuzz_deriveFrom_IsDeterministic(SecretKey sk, bytes32 digest)
        public
    {
        vm.assume(sk.isValid());

        bytes memory pk = sk.toPublicKey().toBytes();

        uint nonce1 = wrapper.deriveFrom(sk.asUint(), pk, digest);
        uint nonce2 = wrapper.deriveFrom(sk.asUint(), pk, digest);
        assertEq(nonce1, nonce2);
    }

    function testFuzz_deriveFrom_WithSalt_IsDeterministic(
        SecretKey sk,
        bytes32 digest,
        bytes32 salt
    ) public {
        vm.assume(sk.isValid());

        bytes memory pk = sk.toPublicKey().toBytes();

        uint nonce1 = wrapper.deriveFrom(sk.asUint(), pk, digest, salt);
        uint nonce2 = wrapper.deriveFrom(sk.asUint(), pk, digest, salt);
        assertEq(nonce1, nonce2);
    }
}
*/

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
/*
contract NonceWrapper {
    function deriveFrom(uint sk, bytes memory pk, bytes32 digest)
        public
        pure
        returns (uint)
    {
        return Nonce.deriveFrom(sk, pk, digest);
    }

    function deriveFrom(uint sk, bytes memory pk, bytes32 digest, bytes32 salt)
        public
        pure
        returns (uint)
    {
        return Nonce.deriveFrom(sk, pk, digest, salt);
    }
}
*/
