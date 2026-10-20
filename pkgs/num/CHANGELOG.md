# Changelog

All notable changes to [`dash-num`](https://crates.io/crates/dash-num) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CompactTarget::block_proof`, the work contributed by a block with that target, zero for negative, overflowing or
  zero targets.
- `from_hex_lossy` for `HashBlob`, `make_hash!` types and `Arith256`, an infallible parse of the leading hex digits of
  a string, matching the reference implementation.
- `u64` operands for `Arith256`: `+=`, `-=`, `|=`, `^=`, `/`, `/=`, `==` and `!=`. Inferred operands such as
  `a == x.into()` may now need a type annotation.
- `From<&T>` conversions into `Arith256` from `&u8` through `&u128` and `&Hash256`, and `From<&Arith256>` for
  `Hash256`.

### Changed

- **The minimum supported Rust version is raised from 1.85 to 1.89.**
- `HashBlob`, `make_hash!` types and `Arith256` serialize as their little-endian storage bytes for machine-readable
  formats, JSON retains hex encoded big-endian string encoding.
- `CompactTarget::from_str` requires exactly 8 hex digits, optionally `0x`/`0X`-prefixed. Shorter input is now
  rejected with `ParseHexError::OddLength` or `ParseHexError::InvalidLength`.
- The `serde` feature no longer implies `codec`. `CompactTarget` implements `Serialize` and `Deserialize` without
  `codec`. Callers that relied on `serde` to enable `codec` must enable it explicitly.
- `Arith256::to_f64` rounds like the reference implementation. It was one ULP off on roughly 1% of inputs.

### Removed

- `ParseHexError` has moved to `dash-types` as `dash_types::ParseHexError`.
- The `dash_types::Numeric` re-export in favour of a wholesale crate re-export. `dash_num::Numeric` imports must switch
  to `dash_num::__deps::dash_types::Numeric` or depend on `dash-types` directly.

## [0.1.0-beta] - 2026-09-14

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-num-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-num-0.1.0-beta
