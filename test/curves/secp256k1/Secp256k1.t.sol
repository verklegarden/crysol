// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

contract Secp256k1Test is Test {
    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    //--------------------------------------------------------------------------
    // Test: Private Key

    // -- newPrivateKey

    function test_newPrivateKey() public {
        PrivateKey privKey = Secp256k1.newPrivateKey();

        assertTrue(privKey.isValid());

        // Verify vm can create wallet from private key.
        vm.createWallet(privKey.asUint());
    }

    // -- isValid

    function testFuzz_PrivateKey_isValid(uint seed) public {
        uint privKey = _bound(seed, 1, Secp256k1.Q - 1);

        assertTrue(PrivateKey.wrap(privKey).isValid());
    }

    function test_PrivateKey_isValid_FalseIf_PrivateKeyIsZero() public {
        assertFalse(PrivateKey.wrap(0).isValid());
    }

    function testFuzz_PrivateKey_isValid_FalseIf_PrivateKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint privKey = _bound(seed, Secp256k1.Q, type(uint).max);

        assertFalse(PrivateKey.wrap(privKey).isValid());
    }

    // -- toPublicKey

    function testFuzz_PrivateKey_toPublicKey(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        assertEq(privKey.toPublicKey().toAddress(), vm.addr(privKey.asUint()));
    }

    function testFuzz_PrivateKey_toPublicKey_RevertsIf_PrivateKeyInvalid(
        uint seed
    ) public {
        PrivateKey privKey =
            PrivateKey.wrap(_bound(seed, Secp256k1.Q, type(uint).max));

        vm.expectRevert("PrivateKeyInvalid()");
        privKey.toPublicKey();
    }

    // -- Casting --

    // -- privateKeyFromUint

    function testFuzz_privateKeyFromUint(uint seed) public {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        PrivateKey privKey = Secp256k1.privateKeyFromUint(scalar);

        assertEq(privKey.asUint(), scalar);
        assertTrue(privKey.isValid());
    }

    function testFuzz_privateKeyFromUint_RevertsIf_ScalarZero() public {
        vm.expectRevert("InvalidScalar()");
        Secp256k1.privateKeyFromUint(0);
    }

    function testFuzz_privateKeyFromUint_RevertsIf_ScalarGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256k1.Q, type(uint).max);

        vm.expectRevert("InvalidScalar()");
        Secp256k1.privateKeyFromUint(scalar);
    }

    // -- asUint

    function testFuzz_PrivateKey_asUint(uint seed) public {
        assertEq(seed, PrivateKey.wrap(seed).asUint());
    }

    // -- privateKeyFromBytes

    function testFuzz_privateKeyFromBytes(uint seed) public {
        uint scalar = _bound(seed, 1, Secp256k1.Q - 1);

        PrivateKey privKey =
            Secp256k1.privateKeyFromBytes(abi.encodePacked(scalar));

        assertTrue(privKey.isValid());
        assertEq(privKey.asUint(), scalar);
    }

    function testFuzz_privateKeyFromBytes_RevertsIf_InvalidScalar(uint seed)
        public
    {
        uint scalar =
            seed == 0 ? seed : _bound(seed, Secp256k1.Q, type(uint).max);

        vm.expectRevert("InvalidScalar()");
        Secp256k1.privateKeyFromBytes(abi.encodePacked(scalar));
    }

    function testFuzz_privateKeyFromBytes_RevertsIf_InvalidLength(
        bytes memory seed
    ) public {
        vm.assume(seed.length != 0x20);

        vm.expectRevert("InvalidLength()");
        Secp256k1.privateKeyFromBytes(seed);
    }

    // -- asBytes

    function testFuzz_PrivateKey_asBytes(PrivateKey privKey) public {
        vm.assume(privKey.isValid());

        assertEq(
            privKey.asUint(),
            Secp256k1.privateKeyFromBytes(privKey.asBytes()).asUint()
        );
    }

    //--------------------------------------------------------------------------
    // Test: Public Key

    // -- toAddress

    function testFuzz_PublicKey_toAddress(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        assertEq(privKey.toPublicKey().toAddress(), vm.addr(privKey.asUint()));
    }

    // -- toHash

    function testFuzz_PublicKey_toHash(PublicKey memory pubKey) public {
        bytes32 got = pubKey.toHash();
        bytes32 want = keccak256(abi.encodePacked(pubKey.x, pubKey.y));

        assertEq(got, want);
    }

    // -- isValid

    function testFuzz_PublicKey_isValid(uint seed) public {
        PrivateKey privKey =
            Secp256k1.privateKeyFromUint(_bound(seed, 1, Secp256k1.Q - 1));

        // Every public key created via valid private key is valid.
        assertTrue(privKey.toPublicKey().isValid());
    }

    function test_PublicKey_isValid_FalseIf_PointNotOnCurve() public {
        PublicKey memory pubKey;

        pubKey.x = 0;
        pubKey.y = 0;
        assertFalse(pubKey.isValid());

        pubKey.x = 1;
        pubKey.x = 3;
        assertFalse(pubKey.isValid());

        pubKey.x = type(uint).max;
        pubKey.x = type(uint).max;
        assertFalse(pubKey.isValid());
    }

    // -- yParity

    function testFuzz_PublicKey_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = PublicKey(x, y).yParity();

        assertEq(want, got);
    }

    //----------------------------------
    // @todo Casting

    // @todo Uncompressed form G. See [Sec 2 v2].
    //       Good for (de)serialization tests.
    //04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9
    //59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448
    //A6855419 9C47D08F FB10D4B8
}
