[![dash-params](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_params.yml?style=flat&logo=github&logoColor=white&label=params)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_params.yml)
[![dash-params](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-params&style=flat&logo=codecov&logoColor=white&label=params)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fparams)

# dash-params

This crate supplies the network parameters for `mainnet`, `testnet3` and `regtest` used by the Dash Base SDK.

## Usage

To import `dash-params` to your project, add the following to the `[dependencies]` section in `Cargo.toml`

```toml
dash-params = "0.1.0-beta"
```

To use an unpublished revision of this crate, identify the commit hash to pin against and use the following replacing
the value of `rev`.

```toml
dash-params = { git = "https://github.com/dashpay/base-sdk", rev = "a1b2c3d4e5f67890abcdef1234567890abcdef" }
```

To build this crate on a clone of the repository, at the repository root, run the following

```bash
cargo build --package dash-params --all-features
```

## Features

This crate is `#![no_std]` + `alloc` by default.

| Feature | Default | Description |
| --- | --- | --- |
| `codec` | ✅ | Enables support for encoding and decoding types using [`bitcoin-consensus-encoding`](https://docs.rs/bitcoin-consensus-encoding) |
| `full` | | Enables all features and `std` support. |

<!-- [start:omit] -->

## Documentation

Documentation for the most recent release of `dash-params` is available at <https://dashpay.github.io/base-sdk/params>
and changes between versions are recorded in the [changelog](https://dashpay.github.io/base-sdk/params/changelog).

<!-- [end:omit] -->

## License

`dash-params` is released under the terms of the MIT license. Copyright &copy; 2026-present, The Dash Core developers.
To read a copy of the license terms, visit <https://opensource.org/license/MIT>.
