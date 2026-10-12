# Changelog

All notable changes to [`dash-pkc`](https://crates.io/crates/dash-pkc) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Bls{Public,Secret}Key::negate`, `BlsSecretKey::mul_tweak`, `EcdsaPublicKey::negate` and `EcdsaSecretKey::mul_tweak`.
- `portable` feature, forwarding `blst/portable`, for binaries that run on any CPU of the target architecture.

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

## [0.1.0-beta] - 2026-09-15

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-pkc-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-pkc-0.1.0-beta
