# Changelog

All notable changes to [`dash-pkc`](https://crates.io/crates/dash-pkc) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Bls{Public,Secret}Key::negate`, `BlsSecretKey::mul_tweak`, `EcdsaPublicKey::negate` and `EcdsaSecretKey::mul_tweak`.
- `BlsSchemeKind`, `BlsCtx` and `BlsSchemeSource` select Dash Core's legacy or basic BLS scheme at runtime. They need no
  feature, so wire types can carry the scheme without the `bls` backend.
- `BlsEager`, `BlsLazy`, `BlsValue` and `BlsPoint` decode BLS fields as Dash Core's `CBLSWrapper` and `CBLSLazyWrapper`
  do, under an explicit scheme source, with the aliases `BlsEager{Pk,Sig,Sk}` and `BlsLazy{Pk,Sig}`. Eager decoding
  yields a valid object, the invalid object (serialized as zeros) or Core's "malleable BLS object" error. Lazy objects
  keep Core's state changes after `get` and after serializing under another scheme. The `bls` feature now depends on
  `spin` for the lazy object's lock.
- `BlsValue::from_set_bytes_basic` decodes as Dash Core's `SetBytes` under the basic scheme, with no round trip, as Core
  reads governance and CoinJoin signatures.

### Changed

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

## [0.1.0-beta] - 2026-09-15

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-pkc-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-pkc-0.1.0-beta
