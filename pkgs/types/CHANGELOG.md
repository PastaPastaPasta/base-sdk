# Changelog

All notable changes to [`dash-types`](https://crates.io/crates/dash-types) and
[`dash-types-marker`](https://crates.io/crates/dash-types-marker) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Implementation of `LowerHex`, `UpperHex`, `FromStr`, `From<&[u8; N]>` and `TryFrom<&[u8]>` for `{derive,make}_bytes!`.
- `ParseHexError` is moved from `dash-num`, superseding `dash_num::ParseHexError`.
- `serialize::hex::serialize_as` and `serialize::hex::deserialize_as`, to permit caller-defined handling of
  human-readable encoding while sharing common machine-readable encoding.
- `CoreBool`, a wire boolean that decodes any non-zero byte as `true` and encodes as `0x00` or `0x01`, as Dash Core
  reads and writes a `bool`.
- `CompactSize::decode_size`, which applies Dash Core's `MAX_SIZE` range check to a size, as `ReadCompactSize` does by
  default.
- `serialize::opt_str_u64`: `str_u64` for an `Option<u64>` field.

### Changed

- **The minimum supported Rust version is raised from 1.85 to 1.89.**
- `DecodeError` gains `MalleableBls`, for BLS bytes canonical in neither scheme, which Dash Core rejects as a "malleable
  BLS object". Exhaustive matches on `DecodeError` must add an arm.
- `{derive,make}_bytes!`-defined types serialize as their raw storage bytes for machine-readable formats. JSON and
  other human-readable formats retain hex in storage order for `fwd` and in reverse storage order for `rev`.
- `derive_bytes!` emits `From<[u8; N]>` in place of `impl_bytes!`, and `make_sbytes!` emits the implementation itself.
   Callers of `impl_bytes!` without `derive_bytes!` must now write the conversion manually.
  - As a result, both `make_bytes!` and `make_sbytes!` carry it with `nocodec` tag and without the `codec` feature and
    callers that wrote the conversion manually for those configurations must drop it.
- The `serde` feature no longer implies `codec`. `impl_num!` is available without `codec` and emits its `serde`
  implementation independently, as does `make_num!`. Callers that relied on `serde` to enable `codec` must enable it
  explicitly.
- The `zeroize` export is moved from the crate root to `__deps`. Callers must switch to `dash_types::__deps::zeroize`.
- Types using `derive_bytes!` that implemented `From<&[u8; N]>`, `TryFrom<&[u8]>`, `FromStr`, `LowerHex` or `UpperHex`
  manually must drop those implementations, as `derive_bytes!` now emits them.
- `serialize::hex` writes raw bytes for machine-readable formats instead of emitting a hex-encoded string.
- `serialize::hex::deserialize` returns any `T` built from a byte slice instead of `Vec<u8>`. Callers that relied on
  `Vec<u8>` as the fixed return type must now mention it explicitly.
- `serialize::str_u64` writes a native `u64` to machine-readable formats. `str_u64` is a workaround for number-precision
  limitations in JSON and is now contained only for human-readable formats.
- Decoding `Vec<T>`, `String` and script buffers rejects a length prefix above `MAX_SER_SIZE` even when enough bytes
  remain, matching Dash Core's `ReadCompactSize`.
- Decoding `Vec<T>` reserves each batch exactly, as Core's `reserve(allocated)` does, rather than growing its capacity
  geometrically past the batch.

### Removed

- The `codec::Checkable` and `codec::Hashable` compatibility aliases in favour of exports from the crate root.
- `BaseCodec` for `bool`, which rejected bytes other than `0x00` and `0x01` that Dash Core accepts. Wire types use
  `CoreBool` instead.

### Fixed

- `serialize::utf8_lossy`'s serializer and deserializer arms were not in sync, writing valid UTF-8 as a string for
  machine-readable formats but expecting byte buffers when reading, failing round trips. This has since been resolved.

## [0.1.0-beta] - 2026-09-14

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-types-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-types-0.1.0-beta
