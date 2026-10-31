[![dash-pkc](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_pkc.yml?style=flat&logo=github&logoColor=white&label=pkc)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_pkc.yml)
[![dash-pkc](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-pkc&style=flat&logo=codecov&logoColor=white&label=pkc)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fpkc)

> [!WARNING]
>
> It is heavily advised **against** using this library for new consensus implementations and to use established
> spec-conformant libraries like [supranational/blst](https://github.com/supranational/blst) as this library codifies
> primitives predating the final IETF spec and includes a non-standard (now legacy) scheme.
>
> **This library has not undergone a formal security review.**

# dash-pkc

This crate supplies the curve primitives for signing, verifying and encrypting used by the Dash Base SDK for
consensus-stable types, including

* Distinct byte bag and operative types to allow parsing _without_ pulling in crypto dependencies with native
  zeroization and constant-time comparison.
* A bug-compatible implementation of the sunset BLS12-381 scheme used by the reference implementation (also known as
  "legacy" or Chia scheme) and the current active (i.e. "basic") scheme.
* Shared DH secret derivation and encryption using BLS12-381's integrated encryption scheme.
* A consensus-compatible wrapper around secp256k1 with support for DER (en/de)coding, recoverable signatures and
  Bitcoin-derived compression semantics.
* Scalar and point tweaks for BLS12-381 and secp256k1

## Usage

To import `dash-pkc` to your project, add the following to the `[dependencies]` section in `Cargo.toml`

```toml
dash-pkc = "0.2.0-beta"
```

To use an unpublished revision of this crate, identify the commit hash to pin against and use the following replacing
the value of `rev`.

```toml
dash-pkc = { git = "https://github.com/dashpay/base-sdk", rev = "a1b2c3d4e5f67890abcdef1234567890abcdef" }
```

To build this crate on a clone of the repository, at the repository root, run the following

```bash
cargo build --package dash-pkc --all-features
```

## Features

This crate is `#![no_std]` + `alloc` by default.

| Feature | Default | Description |
| --- | --- | --- |
| `bls` | | Enables support for BLS12-381 operations backed by [`blst`](https://docs.rs/blst). Byte types are available without enabling this feature. |
| `codec` | ✅ | Enables support for encoding and decoding types using [`bitcoin-consensus-encoding`](https://docs.rs/bitcoin-consensus-encoding) |
| `ecdsa` | | Enables secp256k1 operations backed by [`rust-secp256k1`](https://docs.rs/secp256k1). Byte types are available without enabling this feature. |
| `eddsa` | | Enables ed25519 operations backed by [`ed25519-dalek`](https://docs.rs/ed25519-dalek). Byte types are available without enabling this feature. |
| `full` | | Enables all features and `std` support. |
| `portable` | | Disables optimizations that constrain CPU support for the target architecture. |
| `serde` | | Enables support for encoding and decoding types using [`serde`](https://github.com/serde-rs/serde). Types serialized as their wire image also need `codec`. |

<!-- [start:omit] -->

## Documentation

Documentation for the most recent release of `dash-pkc` is available at <https://dashpay.github.io/base-sdk/pkc> and
changes between versions are recorded in the [changelog](https://dashpay.github.io/base-sdk/pkc/changelog).

<!-- [end:omit] -->

## License

`dash-pkc` is released under the terms of the MIT license. Copyright &copy; 2026-present, The Dash Core developers.
To read a copy of the license terms, visit <https://opensource.org/license/MIT>.
