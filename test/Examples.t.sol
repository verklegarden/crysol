// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

// @todo Import examples
import {Example_ECDSA} from "script/examples/ECDSA.sol";

/**
 * @title ExamplesTest
 *
 * @notice Tests examples from script/examples/
 */
contract ExamplesTest is Test {
    //--------------------------------------------------------------------------
    // ECDSA

    function testExample_ECDSA_sign() public {
        Example_ECDSA example = new Example_ECDSA();
        example.signAndVerify();
    }
}
