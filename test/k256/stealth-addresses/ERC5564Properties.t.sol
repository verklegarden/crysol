// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {K256, SecretKey, PublicKey} from "src/k256/K256.sol";
import {
    K256Arithmetic, Point, ProjectivePoint
} from "src/k256/K256Arithmetic.sol";

import {
    ERC5564,
    StealthMetaAddress,
    StealthAddress
} from "src/k256/stealth-addresses/ERC5564.sol";

contract StealthAddressesK256PropertiesTest is Test {
    using K256 for SecretKey;
    using K256 for PublicKey;
    using K256 for Point;

    using K256Arithmetic for Point;
    using K256Arithmetic for ProjectivePoint;

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
