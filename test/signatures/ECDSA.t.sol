// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";
import {ECDSAUnsafe} from "unsafe/ECDSAUnsafe.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

import {Message} from "src/Message.sol";

/**
 * @notice ECDSA Unit Tests
 */
contract ECDSATest is Test {
    using ECDSA for address;
    using ECDSA for PrivateKey;
    using ECDSA for PublicKey;
    using ECDSA for Signature;
    using ECDSAUnsafe for Signature;

    using Secp256k1 for PrivateKey;
    using Secp256k1 for PublicKey;

    ECDSAWrapper wrapper;

    function setUp() public {
        wrapper = new ECDSAWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Signature Verification

    function testFuzz_verify(PrivateKey privKey, bytes memory message) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();
        bytes32 digest = keccak256(message);

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        Signature memory sig = Signature(v, r, s);

        assertTrue(wrapper.verify(pubKey, message, sig));
        assertTrue(wrapper.verify(pubKey, digest, sig));
        assertTrue(wrapper.verify(pubKey.toAddress(), message, sig));
        assertTrue(wrapper.verify(pubKey.toAddress(), digest, sig));
    }

    function testFuzz_verify_FailsIf_SignatureInvalid(
        PrivateKey privKey,
        bytes memory message,
        uint8 vMask,
        uint rMask,
        uint sMask
    ) public {
        vm.assume(privKey.isValid());
        vm.assume(vMask != 0 || rMask != 0 || sMask != 0);

        PublicKey memory pubKey = privKey.toPublicKey();
        bytes32 digest = keccak256(message);

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        v ^= vMask;
        r = bytes32(uint(r) ^ rMask);
        s = bytes32(uint(s) ^ sMask);

        Signature memory sig = Signature(v, r, s);

        // Note that verify() reverts if signature is malleable.
        sig.intoNonMalleable();

        assertFalse(wrapper.verify(pubKey, message, sig));
        assertFalse(wrapper.verify(pubKey, digest, sig));
        assertFalse(wrapper.verify(pubKey.toAddress(), message, sig));
        assertFalse(wrapper.verify(pubKey.toAddress(), digest, sig));
    }

    function testFuzz_verify_RevertsIf_SignatureMalleable(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();
        bytes32 digest = keccak256(message);

        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privKey.asUint(), digest);

        Signature memory badSig = Signature(v, r, s).intoMalleable();

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pubKey, message, badSig);

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pubKey, digest, badSig);

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pubKey.toAddress(), message, badSig);

        vm.expectRevert("SignatureMalleable()");
        wrapper.verify(pubKey.toAddress(), digest, badSig);
    }

    function testFuzz_verify_RevertsIf_PublicKeyInvalid(
        PublicKey memory pubKey,
        bytes memory message,
        Signature memory sig
    ) public {
        vm.assume(!pubKey.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(pubKey, message, sig);

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.verify(pubKey, keccak256(message), sig);
    }

    function testFuzz_verify_RevertsIf_SignerZeroAddress(
        bytes memory message,
        Signature memory sig
    ) public {
        address signer = address(0);

        vm.expectRevert("SignerZeroAddress()");
        wrapper.verify(signer, message, sig);

        vm.expectRevert("SignerZeroAddress()");
        wrapper.verify(signer, keccak256(message), sig);
    }

    //--------------------------------------------------------------------------
    // Test: Signature Creation

    function testFuzz_sign(PrivateKey privKey, bytes memory message) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();

        Signature memory sig1 = wrapper.sign(privKey, message);
        Signature memory sig2 = wrapper.sign(privKey, keccak256(message));

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);

        assertTrue(pubKey.verify(message, sig1));
        assertTrue(pubKey.verify(message, sig2));
    }

    function testFuzz_sign_RevertsIf_PrivateKeyInvalid(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(!privKey.isValid());

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.sign(privKey, message);

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.sign(privKey, keccak256(message));
    }

    function testFuzz_signEthereumSignedMessageHash(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(privKey.isValid());

        PublicKey memory pubKey = privKey.toPublicKey();

        Signature memory sig1 =
            wrapper.signEthereumSignedMessageHash(privKey, message);
        Signature memory sig2 =
            wrapper.signEthereumSignedMessageHash(privKey, keccak256(message));

        assertEq(sig1.v, sig2.v);
        assertEq(sig1.r, sig2.r);
        assertEq(sig1.s, sig2.s);

        assertTrue(
            pubKey.verify(
                Message.deriveEthereumSignedMessageHash(message), sig1
            )
        );
        assertTrue(
            pubKey.verify(
                Message.deriveEthereumSignedMessageHash(keccak256(message)),
                sig2
            )
        );
    }

    function testFuzz_signEthereumSignedMessageHash_RevertsIf_PrivateKeyInvalid(
        PrivateKey privKey,
        bytes memory message
    ) public {
        vm.assume(!privKey.isValid());

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.signEthereumSignedMessageHash(privKey, message);

        vm.expectRevert("PrivateKeyInvalid()");
        wrapper.signEthereumSignedMessageHash(privKey, keccak256(message));
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- Signature::isMalleable

    function testFuzz_Signature_isMalleable(Signature memory sig) public {
        vm.assume(uint(sig.s) > Secp256k1.Q / 2);

        assertTrue(wrapper.isMalleable(sig));
    }

    function testFuzz_Signature_isMalleable_FailsIf_SignatureNotMalleable(
        Signature memory sig
    ) public {
        vm.assume(uint(sig.s) <= Secp256k1.Q / 2);

        assertFalse(wrapper.isMalleable(sig));
    }

    // -- Signature::toString

    function test_Signature_toString() public {
        Signature memory sig = Signature({
            v: 27,
            r: bytes32(type(uint).max),
            s: bytes32(type(uint).max)
        });

        string memory got = wrapper.toString(sig);
        string memory want = string.concat(
            "ECDSA::Signature {\n",
            "    v: 27,\n",
            "    r: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\n",
            "    s: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n",
            "  }"
        );

        assertEq(got, want);
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    function testFuzz_Signature_toBytes(Signature memory sig) public {
        bytes memory got = wrapper.toBytes(sig);
        bytes memory want = abi.encodePacked(sig.r, sig.s, sig.v);

        assertEq(got, want);
    }

    function testFuzz_signatureFromBytes(bytes memory blob) public {
        vm.assume(blob.length >= 3 * 32);

        (bytes32 r, bytes32 s, uint lastWord) =
            abi.decode(blob, (bytes32, bytes32, uint));

        // V is encoded in first byte of last word.
        uint8 v;
        assembly ("memory-safe") {
            v := byte(0, lastWord)
        }

        console.log(v);

        assembly ("memory-safe") {
            mstore(blob, 65)
        }
        Signature memory got = wrapper.signatureFromBytes(blob);

        assertEq(got.v, v);
        assertEq(got.r, r);
        assertEq(got.s, s);
    }

    function testFuzz_signatureFromBytes_RevertsIf_LengthInvalid(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 65);

        vm.expectRevert("LengthInvalid()");
        wrapper.signatureFromBytes(blob);
    }

    function test_Signature_toCompactBytes() public {
        // Note that test cases are taken from EIP-2098.

        // Test Case 1:
        Signature memory sig1 = Signature({
            v: 27,
            r: 0x68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90,
            s: 0x7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064
        });
        bytes memory got1 = wrapper.toCompactBytes(sig1);
        bytes memory want1 = bytes.concat(
            hex"68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90",
            hex"7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064"
        );
        assertEq(got1, want1);

        // Test Case 2:
        Signature memory sig2 = Signature({
            v: 28,
            r: 0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76,
            s: 0x139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793
        });
        bytes memory got2 = wrapper.toCompactBytes(sig2);
        bytes memory want2 = bytes.concat(
            hex"9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76",
            hex"939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793"
        );
        assertEq(got2, want2);
    }

    function test_signatureFromCompactBytes() public {
        // Note that test cases are taken from EIP-2098.

        // Test Case 1:
        bytes memory blob1 = bytes.concat(
            hex"68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90",
            hex"7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064"
        );
        Signature memory got1 = wrapper.signatureFromCompactBytes(blob1);
        Signature memory want1 = Signature({
            v: 27,
            r: 0x68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90,
            s: 0x7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064
        });
        assertEq(got1.v, want1.v);
        assertEq(got1.r, want1.r);
        assertEq(got1.s, want1.s);

        // Test Case 2:
        bytes memory blob2 = bytes.concat(
            hex"9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76",
            hex"939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793"
        );
        Signature memory got2 = wrapper.signatureFromCompactBytes(blob2);
        Signature memory want2 = Signature({
            v: 28,
            r: 0x9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76,
            s: 0x139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793
        });
        assertEq(got2.v, want2.v);
        assertEq(got2.r, want2.r);
        assertEq(got2.s, want2.s);
    }

    function testFuzz_signatureFromCompactBytes_RevertsIf_LengthInvalid(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 64);

        vm.expectRevert("LengthInvalid()");
        wrapper.signatureFromCompactBytes(blob);
    }
}

/**
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
    ) public pure returns (bool) {
        return pubKey.verify(message, sig);
    }

    function verify(
        PublicKey memory pubKey,
        bytes32 digest,
        Signature memory sig
    ) public pure returns (bool) {
        return pubKey.verify(digest, sig);
    }

    function verify(address signer, bytes memory message, Signature memory sig)
        public
        pure
        returns (bool)
    {
        return signer.verify(message, sig);
    }

    function verify(address signer, bytes32 digest, Signature memory sig)
        public
        pure
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

    function signEthereumSignedMessageHash(
        PrivateKey privKey,
        bytes memory message
    ) public view returns (Signature memory) {
        return privKey.signEthereumSignedMessageHash(message);
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

    function isMalleable(Signature memory sig) public pure returns (bool) {
        return sig.isMalleable();
    }

    function toString(Signature memory sig)
        public
        view
        returns (string memory)
    {
        return sig.toString();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    function toBytes(Signature memory sig) public pure returns (bytes memory) {
        return sig.toBytes();
    }

    function signatureFromBytes(bytes memory blob)
        public
        pure
        returns (Signature memory)
    {
        return ECDSA.signatureFromBytes(blob);
    }

    function toCompactBytes(Signature memory sig)
        public
        pure
        returns (bytes memory)
    {
        return sig.toCompactBytes();
    }

    function signatureFromCompactBytes(bytes memory blob)
        public
        pure
        returns (Signature memory)
    {
        return ECDSA.signatureFromCompactBytes(blob);
    }
}
