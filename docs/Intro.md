# Crysol Documentation

## What are `vmed` functions?

Traditionally, Solidity has been primarily used for verifying cryptographic objects and rarely for creating them, eg we verify ECDSA signatures in Solidity via `ecrecover` and create them via our non-Solidity based wallet libraries.

`crysol` takes a more comprehensive approach and also provides functionality to create cryptographic objects, allowing developers to test and experiment with cryptographic systems from within their Solidity environment.

However, most Solidity code is run on public blockchains - the last place one should perform operations requiring a private key as input.

To ensure operations using sensitive data are never run on non-local blockchains such functions are "`vmed`", meaning they revert whenever the blockchain's chain id is not `31337`.


## The Prelude

Many libraries include a code block called _prelude_ providing common internal functionality.
It provides the `vmed` modifier which protects certain functions from being called in non-local environments.

The _prelude_ code is:

```solidity
// ~~~~~~~ Prelude ~~~~~~~
// forgefmt: disable-start
Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));
modifier vmed() {
    if (block.chainid != 31337) revert("requireVm");
    _;
}
// forgefmt: disable-end
// ~~~~~~~~~~~~~~~~~~~~~~~
```
