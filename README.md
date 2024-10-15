<div align="center">

<h1>crysol</h1>

<a href="">[![Tests][tests-shield]][tests-shield-url]</a>
<a href="">![Apache2/MIT licensed][license-shield]</a>

</div>

`crysol` is a $secp256k1$ elliptic curve library for EVM applications. It targets security, correctness, simplicity, readability, and reviewability as its primary goals.

Features:
- Key generation, verification and de/serialization
- ECDSA and Schnorr signature generation, verification and de/serialization
- Point arithmetic based on complete addition formulas and `ecrecover` precompile optimizations
- Prime field arithmetic
- Secure, simple and stable interfaces

For usage examples, see [`examples/`](./examples).

## Libraries

```ml
src
├─ Secp256k1 - "Secp256k1 cryptography library"
├─ arithmetic
│  ├─ Points "Secp256k1 point arithmetic library"
│  └─ Fp — "Secp256k1 prime field arithmetic library"
└─ signatures
   ├─ ECDSA — "ECDSA signature library"
   └─ Schnorr — "Schnorr signature library"

offchain
├─ RandomOffchain - "Access to cryptographically secure randomness"
├─ Secp256k1Offchain - "Offchain secp256k1 cryptography library"
└─ signatures
   ├─ ECDSAOffchain — "Offchain ECDSA signature library"
   └─ SchnorrOffchain — "Offchain Schnorr signature library"

unsafe
└─ signatures
   └─ ECDSAUnsafe — "Library for unsafe ECDSA signature operations"
```

## Installation

Install with [Foundry](https://getfoundry.sh/):

```bash
$ forge install verklegarden/crysol
```

## Contributing

The project uses the Foundry toolchain. You can find installation instructions [here](https://getfoundry.sh/).

Setup:

```bash
$ git clone https://github.com/verklegarden/crysol
$ cd crysol/
$ forge install
```

Note that the [`Makefile`](./Makefile) provides commands for common development operations:

```
$ make help
>
>  ██████ ██████  ██    ██ ███████  ██████  ██
> ██      ██   ██  ██  ██  ██      ██    ██ ██
> ██      ██████    ████   ███████ ██    ██ ██
> ██      ██   ██    ██         ██ ██    ██ ██
>  ██████ ██   ██    ██    ███████  ██████  ███████
>
> build                                              Build project
> clean                                              Clean build artifacts
> coverage                                           Update coverage report and print summary
> examples                                           Run examples
> fmt                                                Format project
> help                                               Print list of all commands
> test-intense                                       Run full test suite with intense fuzzing
> test-summary                                       Print summary of test suite
> test                                               Run full test suite
> todos                                              Grep TODO's in src/ and test/
```

## Safety

This is **experimental software** and is provided on an "as is" and "as available" basis.

We **do not give any warranties** and **will not be liable** for any loss incurred through any use of this codebase.

## License

Licensed under either of <a href="LICENSE-APACHE">Apache License, Version 2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

<!--- Shields -->
[tests-shield]: https://github.com/verklegarden/crysol/actions/workflows/ci.yml/badge.svg
[tests-shield-url]: https://github.com/verklegarden/crysol/actions/workflows/ci.yml
[license-shield]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
