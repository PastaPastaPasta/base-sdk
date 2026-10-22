# Changelog

All notable changes to [`dash-types`](https://crates.io/crates/dash-types) and
[`dash-types-marker`](https://crates.io/crates/dash-types-marker) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `impl_new!`, which declares a struct with named fields and a `new` taking every field in declaration order.
- A `get` accessor for `make_num!`-defined types, returning the inner integer.

### Changed

- The inner integer of `make_num!`-defined types is private. Callers construct them with `new` or `From` and read them
  with `get` or `Numeric::to_base`.
- `serialize::str_u64` also carries an `Option<u64>` field, with `None` as null. Its `serialize` and `deserialize` are
  generic over the sealed `serialize::str_u64::Value` trait, which `u64` and `Option<u64>` implement.

## [0.2.0-beta] - 2026-10-20

### Added

- Implementation of `LowerHex`, `UpperHex`, `FromStr`, `From<&[u8; N]>` and `TryFrom<&[u8]>` for `{derive,make}_bytes!`.
- `ParseHexError` is moved from `dash-num`, superseding `dash_num::ParseHexError`.
- `serialize::hex::serialize_as` and `serialize::hex::deserialize_as`, to permit caller-defined handling of
  human-readable encoding while sharing common machine-readable encoding.
- `CompactSize::decode_unbounded`, decoding a value read as a number rather than a size, such as service flags,
  without the `MAX_SER_SIZE` range check.
- `CompactSize::decode_len`, decoding a length or count prefix range-checked like `CompactSize::decode` and
  bounded by a caller limit and the remaining input.
- `Signable`, a trait for consensus types that hold a signature. `Signable::payload` returns the 32-byte digest the
  key signs, `Signable::set_signature` stores a signature if it verifies against the supplied key and
  `Signable::reset_signature` drops the signature.
- `CompactSize::decode_as`, with the sealed `CompactUint` trait, for `CompactSize`-encoded integer fields bounded by both
  `MAX_SER_SIZE` and their type.
- `codec::decode_vec` reads a CompactSize-prefixed vector and rejects a count above a caller limit before any
  element is decoded or allocated.

### Changed

- **The minimum supported Rust version is raised from 1.85 to 1.89.**
- **Decoding a `CompactSize` rejects a value above `MAX_SER_SIZE`.** Callers reading a value as a number (instead of a
  size) must switch to `CompactSize::decode_unbounded`.
- **Machine-readable formats receive raw bytes in place of hex or strings.** JSON and other human-readable formats are
  unaffected unless noted.
  - `{derive,make}_bytes!`-defined types serialize as their raw storage bytes. Human-readable formats retain hex in
    storage order for `fwd` and in reverse storage order for `rev`.
  - `serialize::hex` writes raw bytes instead of a hex-encoded string.
  - `serialize::str_u64` writes a native `u64` to work around number-precision limitations in JSON and is now
    confined to human-readable formats.
  - `serialize::utf8_lossy` writes raw bytes, or a string only for human-readable formats and valid UTF-8, and reads
    back in the same manner so round trips succeed.
- **The `serde` feature no longer implies `codec`.** `impl_num!` and `make_num!` are available without `codec` and emit
  their `serde` implementation independently. Callers that relied on `serde` to enable `codec` must enable it
  explicitly.
- `bool` decodes any non-zero byte as `true` instead of rejecting bytes above `1`. Encoding still writes `0` or
  `1`, so a decoded byte above `1` **does not round-trip**.
- Decoding `Vec<T>`, `String` and script buffers treats length prefixes differently.
  - A prefix above `MAX_SER_SIZE` is rejected even when enough bytes remain.
  - A prefix past the remaining input is reported as `DecodeError::Eof` instead of `CompactSizeExceedsLimit`.
  - `Vec<T>` reserves each batch exactly rather than growing its capacity geometrically past the batch.
- `derive_bytes!` emits `From<[u8; N]>` in place of `impl_bytes!`. `make_sbytes!` emits the implementation itself.
  Callers of `impl_bytes!` without `derive_bytes!` must now write the conversion manually.
  - `make_bytes!` and `make_sbytes!` therefore emit `From<[u8; N]>` even with the `nocodec` tag or without the `codec`
    feature, where it was previously absent. Callers that wrote the conversion manually for those configurations must
    drop it.
  - `derive_bytes!` (and by extension `make_bytes!`) also emits `From<&[u8; N]>`, `TryFrom<&[u8]>`, `FromStr`,
    `LowerHex` and `UpperHex`, while `make_sbytes!` does not. Types using `derive_bytes!` or `make_bytes!` that
    implemented them manually must drop those implementations.
- `serialize::hex::deserialize` returns any `T` built from a byte slice instead of `Vec<u8>`. Callers that relied on
  `Vec<u8>` as the fixed return type must now mention it explicitly.
- The `zeroize` export is moved from the crate root to `__deps`. Callers must switch to `dash_types::__deps::zeroize`.

### Removed

- The `codec::Checkable` and `codec::Hashable` compatibility aliases in favour of exports from the crate root.

## [0.1.0-beta] - 2026-09-14

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-types-0.2.0-beta...HEAD
[0.2.0-beta]: https://github.com/dashpay/base-sdk/compare/dash-types-0.1.0-beta...dash-types-0.2.0-beta
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-types-0.1.0-beta
