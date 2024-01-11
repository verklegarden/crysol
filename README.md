<div align="center">

<h1>crysol</h1>

<a href="">[![Unit Tests][tests-shield]][tests-shield-url]</a>
<a href="">[![License: MIT][license-shield]][license-shield-url]</a>
<a href="">[![Solidity][solidity-shield]][solidity-shield-url]</a>

</div>

> [!WARNING]
>
> This project is in a very early stage and important tests are still missing.
>
> Expect breaking changes!

`crysol` is a collection of pure Solidity libraries providing elliptic curve cryptography for on- and offchain operations.

## Installation

Install with [Foundry](https://getfoundry.sh/):

```bash
$ forge install pmerkleplant/crysol
```

## Libraries

```ml
src
├─ Random - "Provides access to cryptographically secure randomness"
├─ Message - "Functionality for constructing Ethereum Signed Message Hashes"
├─ curves
│   ├─ Secp256k1 - "Provides common cryptography-related functionality for the secp256k1 elliptic curve"
│   └─ Secp256k1Arithmetic — "Provides common arithmetic-related functionality for the secp256k1 elliptic curve"
├─ signatures
│   ├─ ECDSA — "Provides ECDSA signature functionality"
│   ├─ Schnorr — "Provides Schnorr signature functionality"
│   └─ utils
│       └─ Nonce - "Provides deterministic nonce derivation"
└─ stealth-addresses
    ├─ ERC5564Announcer - "Minimal ERC-5564 stealth address announcement contract and interface"
│   └─ StealthAddressesSecp256k1 - "ERC-5564 conforming stealth addresses for the secp256k1 curve"
```

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

## Tests

| **Library**                                   | **Unit Tests** | **Property-Based Tests** | **Specification-Based Tests** |
| --------------------------------------------- | -------------- | ------------------------ | ----------------------------- |
| `Random`                                      | ✅              | ❔                        | ❔                             |
| `Message`                                     | ✅              | ❔                        | ❔                             |
| `curves/Secp256k1`                            | ✅              | 🚧                        | ❌                             |
| `curves/Secp256k1Arithmetic`                  | ✅              | 🚧                        | ❌                             |
| `signatures/ECDSA`                            | ✅              | ✅                        | ❌                             |
| `signatures/Schnorr`                          | ✅              | ✅                        | ❌                             |
| `signatures/utils/Nonce`                      | ✅              | ❌                        | ❌                             |
| `stealth-addresses/ERC5564Announcer`          | ❌              | ❌                        | ❌                             |
| `stealth-addresses/StealthAddressesSecp256k1` | ❌              | ❌                        | ❌                             |

✅ Test Type Implemented &emsp; ❌ Test Type Not Implemented &emsp; 🚧 Test Type Partially Implemented &emsp; ❔ Test Type Not Applicable

## Safety

This is **experimental software** and is provided on an "as is" and "as available" basis.

We **do not give any warranties** and **will not be liable** for any loss incurred through any use of this codebase.

While `crysol` has been heavily tested, there may be parts that may exhibit unexpected emergent behavior when used with other code, or may break in future Solidity versions.

Please always include your own thorough tests when using `crysol` to make sure it works correctly with your code.

<!--- Shields -->
[tests-shield]: https://github.com/pmerkleplant/crysol/actions/workflows/unit-tests.yml/badge.svg
[tests-shield-url]: https://github.com/pmerkleplant/crysol/actions/workflows/unit-tests.yml
[license-shield]: https://img.shields.io/badge/License-MIT-yellow.svg
[license-shield-url]: https://opensource.org/licenses/MIT
[solidity-shield]: https://img.shields.io/badge/solidity-%3E=0.8.16%20%3C=0.8.23-aa6746
[solidity-shield-url]: https://github.com/pmerkleplant/crysol/actions/workflows/solc-version-tests.yml
