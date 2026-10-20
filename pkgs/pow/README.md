[![dash-pow](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_pow.yml?style=flat&logo=github&logoColor=white&label=pow)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_pow.yml)
[![dash-pow](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-pow&style=flat&logo=codecov&logoColor=white&label=pow)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fpow)

# dash-pow

This crate supplies the Proof of Work hash primitive for the Dash Base SDK.

## Usage

To import `dash-pow` to your project, add the following to the `[dependencies]` section in `Cargo.toml`

```toml
dash-pow = "0.1.0-beta"
```

To use an unpublished revision of this crate, identify the commit hash to pin against and use the following replacing
the value of `rev`.

```toml
dash-pow = { git = "https://github.com/dashpay/base-sdk", rev = "a1b2c3d4e5f67890abcdef1234567890abcdef" }
```

To build this crate on a clone of the repository, at the repository root, run the following

```bash
cargo build --package dash-pow --all-features
```

## Features

This crate is `#![no_std]` + `alloc` by default.

| Feature | Default | Description |
| ------- | ------- | ----------- |
| `full` |  | Enables all features and `std` support. |
| `portable` | ✅ | Allows builds without the target features listed below, using software AES. |

## System Requirements

This crate relies on instruction set extensions that set hardware minimums for the architectures listed below.
<!-- [start:sysinfo] -->
Builds for these architectures fail unless the build flags for them are
[defined](https://github.com/dashpay/base-sdk/blob/dash-pow-0.1.0-beta/.cargo/config.toml) or the `portable` feature is
enabled. Builds for other architectures run without hardware acceleration.

* (x86_64) Intel Broadwell, AMD Zen, or newer with AES-NI and ADX enabled.
* (AArch64) ARMv8-A or newer with
  [cryptographic extensions](https://support.arm.com/documentation/109697/2026_06/Feature-descriptions/The-Armv8-0-architecture-extension?lang=en#md445-the-armv80-architecture-extension__feat_FEAT_Crypto).
* (WebAssembly) Wasm 2.0-capable runtime with support for [vector instructions](https://www.w3.org/TR/2024/CR-wasm-core-2-20241217/#vector-instructions).

Using non-`portable` builds on hosts that do not meet the above requirements will likely result in abrupt termination
due to illegal instructions (`SIGILL`).
<!-- [end:sysinfo] -->

## Documentation

<!-- pyml disable-next-line no-bare-urls -->
Documentation for the most recent release of `dash-pow` is available at https://dashpay.github.io/base-sdk/pow and
changes between versions are recorded in the [changelog](https://dashpay.github.io/base-sdk/pow/changelog).

## License

<!-- pyml disable-next-line no-bare-urls -->
`dash-pkc` is released under the terms of the MIT license. Copyright &copy; 2026-present, The Dash Core developers.
To read a copy of the license terms, visit https://opensource.org/license/MIT.
