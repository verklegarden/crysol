// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

import {
    StealthSecp256k1,
    StealthMetaAddress,
    StealthAddress
} from "src/stealth-addresses/StealthSecp256k1.sol";

/**
 * @notice StealthSecp256k1 Unit Tests
 */
contract StealthSecp256k1Test is Test {
    using Secp256k1 for PrivateKey;

    StealthSecp256k1Wrapper wrapper;

    function setUp() public {
        wrapper = new StealthSecp256k1Wrapper();
    }

    function test_StealthMetaAddress_toString() public {
        PrivateKey spendPrivKey = Secp256k1.privateKeyFromUint(uint(0x5a21e92ba5784ad9e94c9d670d3b21baff82c1668aa9ef9bd039674c7d4589f8));
        PrivateKey viewPrivKey = Secp256k1.privateKeyFromUint(uint(0xf6956ed1c1488982a7a80be72fa0ec8cc978d2c957b431e8b363557e552dbb75));

        StealthMetaAddress memory stealthMetaAddress = StealthMetaAddress({
            spendingPubKey: spendPrivKey.toPublicKey(),
            viewingPubKey: viewPrivKey.toPublicKey()
        });

        string memory chain = "eth";

        string memory got = wrapper.toString(stealthMetaAddress, chain);

        console.log(got);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract StealthSecp256k1Wrapper {
    function toString(
        StealthMetaAddress memory stealthMetaAddress,
        string memory chain
    ) public returns (string memory) {
        return StealthSecp256k1.toString(stealthMetaAddress, chain);
    }
}
