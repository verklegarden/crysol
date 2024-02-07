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

/**
 * @notice ERC-5564 Unit Tests
 */
contract ERC5564Test is Test {
    using K256 for SecretKey;
    using K256 for PublicKey;
    using K256 for Point;

    using K256Arithmetic for Point;
    using K256Arithmetic for ProjectivePoint;

    using ERC5564 for SecretKey;
    using ERC5564 for StealthMetaAddress;

    StealthAddressesK256Wrapper wrapper;

    function setUp() public {
        wrapper = new StealthAddressesK256Wrapper();
    }

    //--------------------------------------------------------------------------
    // Sender

    function test_generateStealthAddress_GivenEph() public {
        // Taken from: https://github.com/nerolation/executable-stealth-address-specs/blob/main/test.ipynb

        // Stealth meta address and respective key pairs.
        SecretKey spendSk = K256.secretKeyFromUint(
            30787322447577792890566286485782027903969759412226064433999487819529647462924
        );
        SecretKey viewSk = K256.secretKeyFromUint(
            50431308649801251425320023123245644035351225602185776979597242007527042324186
        );
        StealthMetaAddress memory stealthMeta = StealthMetaAddress({
            spendPk: spendSk.toPublicKey(),
            viewPk: viewSk.toPublicKey()
        });

        // Generate stealth address from stealth meta address.
        StealthAddress memory stealth;
        stealth = wrapper.generateStealthAddress(
            stealthMeta,
            K256.secretKeyFromUint(
                31582853143040820948875942041653389873450407831047855470517498178324574486065
            )
        );

        address wantAddr = address(0xc7c1BBf258340E551061E7D561798555aA871c0d);
        assertEq(stealth.addr, wantAddr);
    }

    //--------------------------------------------------------------------------
    // Receiver

    function test_checkStealthAddress() public {
        // Taken from: https://github.com/nerolation/executable-stealth-address-specs/blob/main/test.ipynb

        SecretKey spendSk = K256.secretKeyFromUint(
            30787322447577792890566286485782027903969759412226064433999487819529647462924
        );
        SecretKey viewSk = K256.secretKeyFromUint(
            50431308649801251425320023123245644035351225602185776979597242007527042324186
        );

        StealthAddress memory stealth;
        stealth = StealthAddress({
            addr: address(0xc7c1BBf258340E551061E7D561798555aA871c0d),
            ephPk: PublicKey({
                x: uint(
                    99931485108758068354634100015529707565438847495649276196131125998359569029703
                    ),
                y: uint(
                    4744375390796532504618795785909610189099640957761399522523575349957196497592
                    )
            }),
            viewTag: uint8(0x3d) // 0x3d = 61
        });

        bool found =
            wrapper.checkStealthAddress(viewSk, spendSk.toPublicKey(), stealth);
        assertTrue(found);
    }

    function test_checkStealthAddress_FailsIf_ViewTagIncorrect() public {
        // Taken from: https://github.com/nerolation/executable-stealth-address-specs/blob/main/test.ipynb

        SecretKey spendSk = K256.secretKeyFromUint(
            30787322447577792890566286485782027903969759412226064433999487819529647462924
        );
        SecretKey viewSk = K256.secretKeyFromUint(
            50431308649801251425320023123245644035351225602185776979597242007527042324186
        );

        StealthAddress memory stealth;
        stealth = StealthAddress({
            addr: address(0xc7c1BBf258340E551061E7D561798555aA871c0d),
            ephPk: PublicKey({
                x: uint(
                    99931485108758068354634100015529707565438847495649276196131125998359569029703
                    ),
                y: uint(
                    4744375390796532504618795785909610189099640957761399522523575349957196497592
                    )
            }),
            viewTag: uint8(0x3d) // 0x3d = 61
        });

        // Note to set incorrect view tag.
        stealth.viewTag = uint8(0x00);

        bool found =
            wrapper.checkStealthAddress(viewSk, spendSk.toPublicKey(), stealth);
        assertFalse(found);
    }

    function test_computeStealthSecretKey() public {
        // Taken from: https://github.com/nerolation/executable-stealth-address-specs/blob/main/test.ipynb

        SecretKey spendSk = K256.secretKeyFromUint(
            30787322447577792890566286485782027903969759412226064433999487819529647462924
        );
        SecretKey viewSk = K256.secretKeyFromUint(
            50431308649801251425320023123245644035351225602185776979597242007527042324186
        );

        StealthAddress memory stealth;
        stealth = StealthAddress({
            addr: address(0xc7c1BBf258340E551061E7D561798555aA871c0d),
            ephPk: PublicKey({
                x: uint(
                    99931485108758068354634100015529707565438847495649276196131125998359569029703
                    ),
                y: uint(
                    4744375390796532504618795785909610189099640957761399522523575349957196497592
                    )
            }),
            viewTag: uint8(0x3d) // 0x3d = 61
        });

        SecretKey gotSk =
            wrapper.computeStealthSecretKey(spendSk, viewSk, stealth);
        SecretKey wantSk = K256.secretKeyFromUint(
            0x81c527d561a196132fe18f2242385e4cdac91990657021cd0cee71a24d55242e
        );
        assertEq(gotSk.asUint(), wantSk.asUint());
    }

    function test_StealthMetaAddress_toString() public {
        // Taken from: https://github.com/nerolation/executable-stealth-address-specs/blob/main/test.ipynb

        PublicKey memory spendPk = PublicKey({
            x: 101360329545495956162666051930186878698033955801916540340568215465424285633263,
            y: 27884173484063268355525586231115143741771553385896109414861147204858225531545
        });
        PublicKey memory viewPk = PublicKey({
            x: 12497814997365815068905527286060252467359539672611551375389366654292063092228,
            y: 6165085391294201611990159913274691549635337727676630133767399716897791323976
        });

        StealthMetaAddress memory stealthMeta =
            StealthMetaAddress(spendPk, viewPk);

        string memory got = wrapper.toString(stealthMeta, "eth");
        string memory want =
            "st:eth:0x03e017e9d9dbcb9ce5771acfce74c95bc0eafb5db37ef4b1ac62375f8e7a4c8aef021ba1833a9575bd2ad924440a20a80417437f77b0539cbc3f5bbaeeb2881efe04";

        assertEq(got, want);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract StealthAddressesK256Wrapper {
    using ERC5564 for SecretKey;
    using ERC5564 for StealthMetaAddress;

    //--------------------------------------------------------------------------
    // Sender

    function generateStealthAddress(StealthMetaAddress memory stealthMeta)
        public
        returns (StealthAddress memory)
    {
        return stealthMeta.generateStealthAddress();
    }

    function generateStealthAddress(
        StealthMetaAddress memory stealthMeta,
        SecretKey ephSk
    ) public returns (StealthAddress memory) {
        return stealthMeta.generateStealthAddress(ephSk);
    }

    //--------------------------------------------------------------------------
    // Receiver

    function checkStealthAddress(
        SecretKey viewSk,
        PublicKey memory spendPk,
        StealthAddress memory stealth
    ) public returns (bool) {
        return viewSk.checkStealthAddress(spendPk, stealth);
    }

    function computeStealthSecretKey(
        SecretKey spendSk,
        SecretKey viewSk,
        StealthAddress memory stealth
    ) public view returns (SecretKey) {
        return spendSk.computeStealthSecretKey(viewSk, stealth);
    }

    //--------------------------------------------------------------------------
    // Utils

    function toString(
        StealthMetaAddress memory stealthMeta,
        string memory chain
    ) public view returns (string memory) {
        return stealthMeta.toString(chain);
    }
}
