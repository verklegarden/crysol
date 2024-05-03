// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";


import {Secp256k1Offchain} from "offchain/secp256k1/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/secp256k1/Secp256k1.sol";

/**
 * @notice Secp256k1Offchain Unit Tests
 */
contract Secp256k1OffchainTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    Secp256k1OffchainWrapper wrapper;

    function setUp() public {
        wrapper = new Secp256k1OffchainWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Secret Key

    // -- newSecretKey

    function test_newSecretKey() public {
        SecretKey sk = wrapper.newSecretKey();

        assertTrue(sk.isValid());

        // Verify vm can create wallet from secret key.
        vm.createWallet(sk.asUint());
    }

    // -- toPublicKey

    function testFuzz_SecretKey_toPublicKey(uint seed) public {
        SecretKey sk =
            Secp256k1.secretKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        address got = wrapper.toPublicKey(sk).toAddress();
        address want = vm.addr(sk.asUint());

        assertEq(got, want);
    }

    function testFuzz_SecretKey_toPublicKey_RevertsIf_SecretKeyInvalid(
        uint seed
    ) public {
        SecretKey sk = SecretKey.wrap(_bound(seed, Secp256k1.Q, type(uint).max));

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.toPublicKey(sk);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256k1OffchainWrapper {
    using Secp256k1Offchain for SecretKey;

    //--------------------------------------------------------------------------
    // Secret Key

    function newSecretKey() public returns (SecretKey) {
        return Secp256k1Offchain.newSecretKey();
    }

    function toPublicKey(SecretKey sk) public returns (PublicKey memory) {
        return sk.toPublicKey();
    }
}
