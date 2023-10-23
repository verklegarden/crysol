// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";
import {ECDSAUnsafe} from "unsafe/ECDSAUnsafe.sol";
import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

/**
 * @title ECDSAWrapper
 *
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract ECDSAWrapper {
    using ECDSA for address;
    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;
    using ECDSAUnsafe for Signature;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    //--------------------------------------------------------------------------
    // Signature Verification

    function verify(
        PublicKey memory pubKey,
        bytes memory message,
        Signature memory sig
    ) public view returns (bool) {
        return pubKey.verify(message, sig);
    }

    function verify(
        PublicKey memory pubKey,
        bytes32 digest,
        Signature memory sig
    ) public view returns (bool) {
        return pubKey.verify(digest, sig);
    }

    function verify(address signer, bytes memory message, Signature memory sig)
        public
        view
        returns (bool)
    {
        return signer.verify(message, sig);
    }

    function verify(address signer, bytes32 digest, Signature memory sig)
        public
        view
        returns (bool)
    {
        return signer.verify(digest, sig);
    }

    //--------------------------------------------------------------------------
    // Signature Creation

    function sign(PrivateKey privKey, bytes memory message)
        public
        view
        returns (Signature memory)
    {
        return privKey.sign(message);
    }

    function sign(PrivateKey privKey, bytes32 digest)
        public
        view
        returns (Signature memory)
    {
        return privKey.sign(digest);
    }

    function signEthereumSignedMessage(PrivateKey privKey, bytes memory message)
        public
        view
        returns (Signature memory)
    {
        return privKey.signEthereumSignedMessage(message);
    }

    function signEthereumSignedMessageHash(PrivateKey privKey, bytes32 digest)
        public
        view
        returns (Signature memory)
    {
        return privKey.signEthereumSignedMessageHash(digest);
    }

    //--------------------------------------------------------------------------
    // Utils

    function isMalleable(Signature memory sig) public view returns (bool) {
        return sig.isMalleable();
    }

    function toString(Signature memory sig) public returns (string memory) {
        return sig.toString();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization
}
