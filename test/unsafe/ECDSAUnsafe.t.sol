// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {Secp256k1, SecretKey} from "src/Secp256k1.sol";

import {ECDSAOffchain} from "offchain/signatures/ECDSAOffchain.sol";
import {ECDSA, Signature} from "src/signatures/ECDSA.sol";
import {ECDSAUnsafe} from "unsafe/signatures/ECDSAUnsafe.sol";

/**
 * @notice ECDSAUnsafe Unit Tests
 */
contract ECDSAUnsafeTest is Test {
    using Secp256k1 for SecretKey;

    using ECDSAOffchain for SecretKey;
    using ECDSA for SecretKey;

    ECDSAUnsafeWrapper wrapper;

    function setUp() public {
        wrapper = new ECDSAUnsafeWrapper();
    }

    function testFuzz_Signature_malleability_Loop(SecretKey sk, bytes32 digest)
        public
        view
    {
        vm.assume(sk.isValid());

        Signature memory start = sk.sign(digest);

        Signature memory mid = wrapper.intoMalleable(start);
        mid = wrapper.intoMalleable(mid); // NOP

        Signature memory end = wrapper.intoNonMalleable(mid);
        end = wrapper.intoNonMalleable(end); // NOP

        assertEq(start.v, end.v);
        assertEq(start.r, end.r);
        assertEq(start.s, end.s);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract ECDSAUnsafeWrapper {
    using ECDSAUnsafe for Signature;

    function intoMalleable(Signature memory sig)
        public
        pure
        returns (Signature memory)
    {
        return sig.intoMalleable();
    }

    function intoNonMalleable(Signature memory sig)
        public
        pure
        returns (Signature memory)
    {
        return sig.intoNonMalleable();
    }
}
