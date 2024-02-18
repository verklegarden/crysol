// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/secp256k1/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "src/secp256k1/Secp256k1Arithmetic.sol";

import {
    ERC5564,
    StealthMetaAddress,
    StealthAddress
} from "src/secp256k1/stealth-addresses/ERC5564.sol";

contract StealthAddressesSecp256k1PropertiesTest is Test {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    using ERC5564 for SecretKey;
    using ERC5564 for StealthMetaAddress;

    function testProperty_generateStealthAddress_GivenEphSk_IsDeterministic(
        SecretKey viewSk,
        SecretKey spendSk,
        SecretKey ephSk
    ) public {
        vm.assume(viewSk.isValid());
        vm.assume(spendSk.isValid());
        vm.assume(ephSk.isValid());

        StealthMetaAddress memory stealthMeta =
            StealthMetaAddress(spendSk.toPublicKey(), viewSk.toPublicKey());

        StealthAddress memory stealth1 =
            stealthMeta.generateStealthAddress(ephSk);

        StealthAddress memory stealth2 =
            stealthMeta.generateStealthAddress(ephSk);

        assertEq(stealth1.addr, stealth2.addr);
    }

    function testProperty_Receiver_CanSuccessfullyCheckStealthAddress(
        SecretKey viewSk,
        SecretKey spendSk,
        SecretKey ephSk
    ) public {
        vm.assume(viewSk.isValid());
        vm.assume(spendSk.isValid());
        vm.assume(ephSk.isValid());

        StealthMetaAddress memory stealthMeta =
            StealthMetaAddress(spendSk.toPublicKey(), viewSk.toPublicKey());

        StealthAddress memory stealth =
            stealthMeta.generateStealthAddress(ephSk);

        bool found = viewSk.checkStealthAddress(spendSk.toPublicKey(), stealth);
        assertTrue(found);
    }

    function testProperty_Receiver_CanComputeStealthAddressSecretKey(
        SecretKey viewSk,
        SecretKey spendSk,
        SecretKey ephSk
    ) public {
        vm.assume(viewSk.isValid());
        vm.assume(spendSk.isValid());
        vm.assume(ephSk.isValid());

        StealthMetaAddress memory stealthMeta =
            StealthMetaAddress(spendSk.toPublicKey(), viewSk.toPublicKey());

        StealthAddress memory stealth =
            stealthMeta.generateStealthAddress(ephSk);

        SecretKey sk = spendSk.computeStealthSecretKey(viewSk, stealth);

        assertTrue(sk.isValid());
        assertEq(sk.toPublicKey().toAddress(), stealth.addr);
    }
}
