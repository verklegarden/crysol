// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";

import {Secp256k1, PrivateKey} from "src/curves/Secp256k1.sol";

contract ECDSA_SigningTest is Test {
    using ECDSA for PrivateKey;

    function test_SignatureDeterministic(uint privKeySeed) public {
        // Let privKey ∊ [1, Q)
        PrivateKey privKey = Secp256k1.privateKeyFromUint(
            _bound(privKeySeed, 1, Secp256k1.Q - 1)
        );

        Signature memory sig1 = privKey.sign(bytes("hallo"));
        Signature memory sig2 = privKey.sign(bytes("hallo"));

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);
    }
}
