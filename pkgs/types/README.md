[![dash-types](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_types.yml?style=flat&logo=github&logoColor=white&label=types)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_types.yml)
[![dash-types](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-types&style=flat&logo=codecov&logoColor=white&label=types)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Ftypes)

# dash-types

This crate supplies shared definitions and
[procedural macros](https://github.com/dashpay/base-sdk/tree/develop/pkgs/types/marker) that build the foundation
for the Base SDK's higher level types, including

* Support for Bitcoin-based consensus encoding (using [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)'s
  [`bitcoin-consensus-encoding`](https://docs.rs/bitcoin-consensus-encoding))
* Standardized `serde` formatting routines for common types (long integers, UTF-8 bytes, hex bytes)
* Growable (`Vec{De,En}coder`) and fixed sized (`Arr{De,En}coder`) codecs, fixed size buffers (`ArrayBuf`)
* Macro definitions to reduce routine boilerplate
* Name-stable programmatic identifiers (`TypeId`) for consensus types

## Usage

To import `dash-types` to your project, add the following to the `[dependencies]` section in `Cargo.toml`

```toml
dash-types = "0.1.0-beta"
```

To use an unpublished revision of this crate, identify the commit hash to pin against and use the following replacing
the value of `rev`.

```toml
dash-types = { git = "https://github.com/dashpay/base-sdk", rev = "a1b2c3d4e5f67890abcdef1234567890abcdef" }
```

To build this crate on a clone of the repository, at the repository root, run the following

```bash
cargo build --package dash-types --all-features
```

## Features

This crate is `#![no_std]` + `alloc` by default.

| Feature | Default | Description |
| ------- | ------- | ----------- |
| `bitcoin-primitives` | | Enables [adapters](https://github.com/dashpay/base-sdk/blob/develop/pkgs/types/src/adapters.rs) for types defined in [`bitcoin-primitives`](https://docs.rs/bitcoin-primitives). _Implies `codec`._ |
| `codec` | :white_check_mark: | Enables support for encoding and decoding types using [`bitcoin-consensus-encoding`](https://docs.rs/bitcoin-consensus-encoding) |
| `full` | | Enables all features and `std` support. |
| `serde` | | Enables support for encoding and decoding types using [`serde`](https://github.com/serde-rs/serde). |

## Documentation

<!-- pyml disable-next-line no-bare-urls -->
Documentation for the most recent release of `dash-types` is available at https://dashpay.github.io/base-sdk/types and
changes between versions are recorded in the [changelog](https://dashpay.github.io/base-sdk/types/changelog).

## License

<!-- pyml disable-next-line no-bare-urls -->
`dash-types` is released under the terms of the MIT license. Copyright &copy; 2026-present, The Dash Core developers.
To read a copy of the license terms, visit https://opensource.org/license/MIT.
