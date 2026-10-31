[![dash-num](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_num.yml?style=flat&logo=github&logoColor=white&label=num)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_num.yml)
[![dash-num](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-num&style=flat&logo=codecov&logoColor=white&label=num)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fnum)

# dash-num

This crate supplies the wide blob and arithmetic types used by the Dash Base SDK for consensus-stable types, including

* Fixed-width `HashBlob`s stored in little endian and rendered in big endian format for 160-bit (`Hash160`) and 256-bit
  width (`Hash256`)
* Unsigned 256-bit arithmetic (`Arith256`) with consensus-compatible behavior (e.g. wrapping operators)
* Compact representation of difficulty targets (`CompactTarget`) and bidirectional conversion with `Arith256`

## Usage

To import `dash-num` to your project, add the following to the `[dependencies]` section in `Cargo.toml`

```toml
dash-num = "0.2.0-beta"
```

To use an unpublished revision of this crate, identify the commit hash to pin against and use the following replacing
the value of `rev`.

```toml
dash-num = { git = "https://github.com/dashpay/base-sdk", rev = "a1b2c3d4e5f67890abcdef1234567890abcdef" }
```

To build this crate on a clone of the repository, at the repository root, run the following

```bash
cargo build --package dash-num --all-features
```

## Features

This crate is `#![no_std]` + `alloc` by default.

| Feature | Default | Description |
| ------- | ------- | ----------- |
| `codec` | ✅ | Enables support for encoding and decoding types using [`bitcoin-consensus-encoding`](https://docs.rs/bitcoin-consensus-encoding) |
| `full` | | Enables all features and `std` support. |
| `serde` | | Enables support for encoding and decoding types using [`serde`](https://github.com/serde-rs/serde). |

<!-- [start:omit] -->

## Documentation

Documentation for the most recent release of `dash-num` is available at <https://dashpay.github.io/base-sdk/num> and
changes between versions are recorded in the [changelog](https://dashpay.github.io/base-sdk/num/changelog).

<!-- [end:omit] -->

## License

`dash-num` is released under the terms of the MIT license. Copyright &copy; 2026-present, The Dash Core developers.
To read a copy of the license terms, visit <https://opensource.org/license/MIT>.
