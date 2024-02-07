<div align="center">

<h1>crysol</h1>

<a href="">[![Unit Tests][tests-shield]][tests-shield-url]</a>
<a href="">[![License: MIT][license-shield]][license-shield-url]</a>
<a href="">[![Solidity][solidity-shield]][solidity-shield-url]</a>

</div>

> [!WARNING]
>
> This project is in early stage, expect breaking changes.
>
> Use at own risk!

`crysol` is a collection of pure Solidity libraries providing elliptic curve cryptography for on- and offchain operations.

## Libraries

```ml
src
├─ common
│   ├─ Random - "Access to cryptographically secure randomness"
│   ├─ Message - "Functionality for constructing Ethereum Signed Message Hashes"
│   └─ Nonce - "Deterministic nonce derivation"
├─ k256
│   ├─ K256 - "Common cryptography-related functionality for the k256 (secp256k1) elliptic curve"
│   ├─ K256Arithmetic — "Common arithmetic-related functionality for the k256 (secp256k1) elliptic curve"
│   ├─ signatures
│   │   ├─ ECDSA — "ECDSA signature functionality for k256"
│   │   └─ Schnorr — "Schnorr signature functionality for k256"
│   └─ stealth-addresses
│       └─ ERC5564 - "ERC-5564 conforming stealth addresses for k256"
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

## Tests

> Outdated!

| **Library**                                   | **Unit Tests** | **Property-Based Tests** |
| --------------------------------------------- | -------------- | ------------------------ |
| `Random`                                      | ✅              | ❔                      |
| `Message`                                     | ✅              | ❔                      |
| `curves/Secp256k1`                            | ✅              | 🚧                      |
| `curves/Secp256k1Arithmetic`                  | ✅              | 🚧                      |
| `signatures/ECDSA`                            | ✅              | ✅                      |
| `signatures/Schnorr`                          | ✅              | ✅                      |
| `signatures/utils/Nonce`                      | ✅              | ❌                      |
| `stealth-addresses/StealthAddressesSecp256k1` | ❌              | ❌                      |

✅ Implemented &emsp; ❌ Not Implemented &emsp; 🚧 In Progress &emsp; ❔ Not Applicable

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
[solidity-shield]: https://img.shields.io/badge/solidity-%3E=0.8.16%20%3C=0.8.24-aa6746
[solidity-shield-url]: https://github.com/pmerkleplant/crysol/actions/workflows/solc-version-tests.yml
