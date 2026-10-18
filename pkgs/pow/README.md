[![dash-pow](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_pow.yml?style=flat&logo=github&logoColor=white&label=pow)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_pow.yml)
[![dash-pow](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-pow&style=flat&logo=codecov&logoColor=white&label=pow)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fpow)

# dash-pow

This crate supplies the X11 proof-of-work hash chain used by the Dash Base SDK.

## Features

This crate is `#![no_std]` + `alloc` by default.

| Feature | Default | Description |
| ------- | ------- | ----------- |
| `full` | | Enables all features and `std` support. |
| `portable` | | Allows builds without the target features listed below, using software AES. |
| `std` | | Enables `std` support. |

## Target features

Without `portable`, builds require the following target features. The repository's `.cargo/config.toml` sets them for
in-tree builds.

| Architecture | Target features |
| ------------ | --------------- |
| `aarch64` | `neon`, `aes` |
| `wasm32` | `simd128` |
| `x86_64` | `x86-64-v3`, `aes` |

Builds without `portable` use hardware AES with no runtime detection. Such a binary faults with an illegal instruction
on CPUs that lack AES.
