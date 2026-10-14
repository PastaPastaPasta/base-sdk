# Changelog

All notable changes to [`dash-pkc`](https://crates.io/crates/dash-pkc) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Bls{Public,Secret}Key::negate`, `BlsSecretKey::mul_tweak`, `EcdsaPublicKey::negate` and `EcdsaSecretKey::mul_tweak`.
- `portable` feature, forwarding `blst/portable`, for binaries that run on any CPU of the target architecture.
- `to::<S>()` on `BlsPkBytes`, `BlsSkBytes`, `BlsSigBytes`, `BlsIesBlobBytes` and `BlsIesMultiBytes`, which
  validates the bytes under scheme `S` and returns the typed value.
- `EcdsaRecSigBytes::from_bytes_mask`, which accepts any header byte and masks it into a recovery id and compression
  flag.
- `ECDSA_REC_SIG_LEN`, the length of a compact recoverable signature.

### Changed

- **The minimum supported Rust version is raised from 1.85 to 1.89.**
- **`bls` requires ADX on x86_64 unless `portable` is enabled.**
- `BlsScheme::sk_to_bytes` returns `Zeroizing<[u8; 32]>` instead of a bare array. Code that binds the result as
  `[u8; 32]` must dereference it.
- `EcdsaSecretKey::negate` takes `&self` and returns the negated key as `Result<Self, EcdsaError>` instead of negating
  in place and returning `()`, matching the other tweaks. A call that drops the return value still compiles, warned of
  only by `unused_must_use`, but leaves the key as it was. Callers must bind the result, e.g. `sk = sk.negate()?`.
- The following types serialize as raw bytes for machine-readable formats, following changes to `dash-types` and
  `dash-num`. JSON and other human-readable formats are unaffected by this change.

  `BlsPkBytes`, `BlsSigBytes`, `BlsPkHash`, `BlsShareId`, `BlsIes{Blob,Multi}Bytes`, `BlsPublicKey`, `BlsSignature`,
  `Bls{Pk,Sig}Share`, `BlsIes{Blob,Multi}`, `EcdsaPkBytes`, `EcdsaSigBytes`, `EcdsaRecSigBytes`, `EcdsaPkHash`,
  `EcdsaPublicKey`, `EcdsaSignature`, `EcdsaRecSignature`, `EddsaPkBytes`, `EddsaSigBytes`, `EddsaPkHash`,
  `EddsaPublicKey`, `EddsaSignature`.
- The `serde` feature no longer implies `codec`. `BlsIes{Blob,Multi}` and `BlsIes{Blob,Multi}Bytes` serialize as
  their wire image and implement `Serialize` and `Deserialize` only with both features. Callers that relied on `serde`
  to enable `codec` must enable it explicitly.
- `BlsPkBytes`, `BlsSkBytes`, `BlsSigBytes`, `BlsPkHash`, `BlsDhBytes`, `BlsIesBlobBytes` and `BlsIesMultiBytes` drop
  their scheme parameter. Callers remove the type argument and pick the scheme when they convert with `to::<S>()`.
- `EcdsaRecSigBytes::from_raw` is renamed to `from_bytes`, with unchanged behaviour.

### Fixed

- Decoding `BlsIes{Blob,Multi}Bytes`, and so `BlsIes{Blob,Multi}`, rejects a ciphertext length, blob count or blob
  length above `MAX_SER_SIZE` even when enough bytes remain, and reports one past the remaining input as
  `DecodeError::Eof`.

## [0.1.0-beta] - 2026-09-15

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-pkc-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-pkc-0.1.0-beta
