// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, PrivateKey, PublicKey} from "src/curves/Secp256k1.sol";

library Secp256k1Spec {

    Vm private constant vm =
        Vm(address(uint160(uint(keccak256("hevm cheat code")))));


    /// @dev
    ///
    ///      Computed via:
    ///      ```bash
    ///      $ python spec/curves/Secp256k1.py toPublicKey <private key>
    ///      ```
    function privateKeyToPublicKey(PrivateKey privKey)
        internal
        returns (PublicKey memory)
    {
        string[] memory inputs = new string[](2);
        inputs[0] = "python";
        inputs[1] = "spec/curves/Secp256k1.py";
        //inputs[2] = "";
        //inputs[3] = string.concat("--scribe-message=", vm.toString(message));

        uint[2] memory result = abi.decode(vm.ffi(inputs), (uint[2]));

        return PublicKey(result[0], result[1]);
    }
}
