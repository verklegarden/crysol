<div align="center">

<h1>crysol</h1>

<a href="">[![Unit Tests][tests-shield]][tests-shield-url]</a>
<a href="">![Apache2/MIT licensed][license-shield]</a>
<a href="">[![Solidity][solidity-shield]][solidity-shield-url]</a>

</div>

`crysol` is a collection of **pure Solidity** libraries providing **elliptic curve cryptography** for **on- and offchain operations**.

## Libraries

```ml
src
├─ common
│   ├─ Random - "Access to cryptographically secure randomness"
│   ├─ Message - "Functionality for constructing Ethereum Signed Message Hashes"
│   └─ Nonce - "Deterministic nonce derivation"
├─ secp256k1
│   ├─ Secp256k1 - "Cryptography-related functionality for the secp256k1 elliptic curve"
│   ├─ Secp256k1Arithmetic — "Arithmetic-related functionality for the secp256k1 elliptic curve"
│   ├─ signatures
│   │   ├─ ECDSA — "ECDSA signature functionality for secp256k1"
│   │   └─ Schnorr — "Schnorr signature functionality for secp256k1"
│   └─ stealth-addresses
│       └─ ERC5564 - "ERC-5564 conforming stealth addresses for secp256k1"
└─ interfaces
    ├─ IERC5564Announcer - "ERC-5564 stealth address announcement interface"
    └─ IERC5564Registry - "ERC-5564 stealth meta address registry interface"
```

## Installation

Install with [Foundry](https://getfoundry.sh/):

```bash
$ forge install pmerkleplant/crysol
```

## Examples

Several examples are provided in [`examples/`](./examples), such as:
- secure key pair and Ethereum address creation
- secp256k1 point arithmetic
- Schnorr and ECDSA signature creation and verification
- private ETH transfer via stealth addresses

## Contributing

The project uses the Foundry toolchain. You can find installation instructions [here](https://getfoundry.sh/).

Setup:

```bash
$ git clone https://github.com/pmerkleplant/crysol
$ cd crysol/
$ forge install
```

Run tests:

```bash
$ forge test
$ forge test -vvvv # Run with full stack traces
$ FOUNDRY_PROFILE=intense forge test # Run in intense mode
```

Lint:

```bash
$ forge fmt [--check]
```

## Safety

This is **experimental software** and is provided on an "as is" and "as available" basis.

We **do not give any warranties** and **will not be liable** for any loss incurred through any use of this codebase.

<!--- Shields -->
[tests-shield]: https://github.com/pmerkleplant/crysol/actions/workflows/unit-tests.yml/badge.svg
[tests-shield-url]: https://github.com/pmerkleplant/crysol/actions/workflows/unit-tests.yml
[license-shield]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[solidity-shield]: https://img.shields.io/badge/solidity-%3E=0.8.16%20%3C=0.8.24-aa6746
[solidity-shield-url]: https://github.com/pmerkleplant/crysol/actions/workflows/solc-version-tests.yml
