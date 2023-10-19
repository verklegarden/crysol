// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";
import {ECDSAExtended} from "src/signatures/ECDSAExtended.sol";

contract ECDSAExtendedTest is Test {
    using Secp256k1 for PrivateKey;
    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;
    using ECDSAExtended for PrivateKey;
    using ECDSAExtended for Signature;

    function test_intoMalleable(uint scalarSeed, bytes memory message) public {
        // Let scalar ∊ [1, Q).
        uint scalar = _bound(scalarSeed, 1, Secp256k1.Q - 1);
        PrivateKey privKey = Secp256k1.privateKeyFromUint(scalar);

        Signature memory sig = privKey.sign(message).intoMalleable();
        assertTrue(sig.isMalleable());
        assertTrue(
            privKey.toPublicKey().verify(message, sig.intoNonMalleable())
        );
    }

    function test_intoNonMalleable(uint scalarSeed, bytes memory message)
        public
    {
        // Let scalar ∊ [1, Q).
        uint scalar = _bound(scalarSeed, 1, Secp256k1.Q - 1);
        PrivateKey privKey = Secp256k1.privateKeyFromUint(scalar);

        Signature memory sig =
            privKey.sign(message).intoMalleable().intoNonMalleable();
        assertFalse(sig.isMalleable());
        assertTrue(privKey.toPublicKey().verify(message, sig));
    }

    // @todo Find out how foundry derives nonce.
    function test_recoverNonce() public {
        bytes memory message = bytes("crysol <3");
        PrivateKey privKey = Secp256k1.privateKeyFromUint(1);

        Signature memory sig = privKey.sign(message);

        uint nonce = privKey.recoverNonce(message, sig).asUint();
        console.log("Nonce", nonce);

        console.log(
            "Idea",
            uint(
                keccak256(
                    abi.encodePacked(privKey.asUint(), keccak256(message))
                )
            )
        );
        console.log(
            "Idea2",
            uint(
                keccak256(
                    abi.encodePacked(keccak256(message), privKey.asUint())
                )
            )
        );
    }
}
