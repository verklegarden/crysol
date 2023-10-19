# Crysol • [![Uint Tests](https://github.com/pmerkleplant/crysol/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/pmerkleplant/crysol/actions/workflows/unit-tests.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Warning**
>
> Very much work in progress! Don't use!

## Installation

Install module via Foundry:

```bash
$ forge install pmerkleplant/crysol
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

Update gas snapshots:

```bash
$ forge snapshot --nmt "Fuzz" [--check]
```
