# Changelog

All notable changes to [`dash-pkc`](https://crates.io/crates/dash-pkc) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `BlsScheme::is_canonical_pk` and `BlsScheme::is_canonical_sig`, each scheme's rule for `is_canonical::<S>()`.
- `BlsScheme::g1_bytes` and `BlsScheme::g2_bytes`, each scheme's byte layout of a point; `BlsScheme::pk_ietf_bytes`,
  the IETF compressed form of a G1 encoding in that layout, and `BlsScheme::sig_ietf_x_bytes`, the `x` of a G2
  encoding in the IETF compressed layout with the sign bit clear.

### Changed

- `BlsPkBytes::to::<BlsScChia>()` and `BlsPublicKey::<BlsScChia>::from_bytes` read `x = 0` with the sign bit set,
  (0, -2), as the reference implementation does.
- `is_canonical::<BlsScChia>()` on `BlsPkBytes` and `BlsSigBytes` accepts legacy encodings of an `x` with no point on
  the curve, as the reference implementation does; for signatures, only with the sign bit clear. `to::<BlsScChia>()`
  still refuses them, having no point to return.

## [0.2.0-beta] - 2026-10-20

### Added

- `Bls{Public,Secret}Key::negate`, `BlsSecretKey::mul_tweak`, `EcdsaPublicKey::negate` and `EcdsaSecretKey::mul_tweak`.
- `portable` feature, forwarding `blst/portable`, for binaries that run on any CPU of the target architecture.
- `to::<S>()` on `BlsPkBytes`, `BlsSkBytes`, `BlsSigBytes`, `BlsIesBlobBytes` and `BlsIesMultiBytes`, which
  validates the bytes under scheme `S` and returns the typed value.
- `EcdsaRecSigBytes::from_bytes_mask`, which accepts any header byte and masks it into a recovery id and compression
  flag.
- `ECDSA_REC_SIG_LEN`, the length of a compact recoverable signature.
- `BlsSecretKey::sign_message`, `BlsSkShare::sign_message`, `BlsPublicKey::verify_message`,
  `BlsSignature::{fast,secure}_verify_aggregates_message`, `BlsSignature::verify_aggregates_messages` and
  `BlsScheme::plaintext_msg`, taking a message of any length. The legacy scheme signs the message's SHA-256 digest.
- `is_canonical::<S>()` on `BlsPkBytes`, `BlsSigBytes` and `BlsSkBytes`, behind the `bls` feature. It rejects bytes
  that decode under scheme `S` only after masking, or not at all. Null bytes count as canonical.

### Changed

- **The minimum supported Rust version is raised from 1.85 to 1.89.**
- **`bls` requires ADX on x86_64 unless `portable` is enabled.**
- **Signing and verification methods are renamed to name their input.**
  - `BlsSecretKey::sign`, `BlsSkShare::sign`, `BlsPublicKey::verify` and
    `BlsSignature::{fast,secure}_verify_aggregates` gain a `_digest` suffix and take a 32-byte hashed message.
  - `BlsSignature::verify_aggregates` is renamed to `verify_aggregates_digests` and takes `&[[u8; 32]]`.
  - `BlsScheme::msg_ref` is renamed to `digest_msg`, and `BlsScheme::Msg` is passed by value as `Msg<'a>`.
  - `EcdsaSecretKey::sign` and `EcdsaPublicKey::verify` are renamed to `sign_digest` and `verify_digest`.
  - `EddsaSecretKey::sign` and `EddsaPublicKey::verify` are renamed to `sign_message` and `verify_message`.
- **`EcdsaSecretKey::negate` takes `&self` and returns the negated key as `Result<Self, EcdsaError>`.** It previously
  negated in place and returned `()`, and now matches the other tweaks. A call that drops the return value still
  compiles, though warned if `unused_must_use` is enabled, but would otherwise leave the key as-is. Callers must bind
  the result, e.g. `sk = sk.negate()?`.
- **`EcdsaPublicKey::verify_digest` normalizes S before verifying**, so a high-S signature verifies like its low-S
  twin. Callers refusing malleable signatures should check with `EcdsaSignature::is_low_s`.
- **`BlsPkBytes`, `BlsSkBytes`, `BlsSigBytes`, `BlsPkHash`, `BlsDhBytes`, `BlsIesBlobBytes` and `BlsIesMultiBytes` drop
  their scheme parameter.** Callers drop the type argument and define the scheme when they exercise the operational
  type with `to::<S>()`.
- **The following types serialize as raw bytes for machine-readable formats**, following changes to `dash-types` and
  `dash-num`. JSON and other human-readable formats are unaffected by this change.

  `BlsPkBytes`, `BlsSigBytes`, `BlsPkHash`, `BlsShareId`, `BlsIes{Blob,Multi}Bytes`, `BlsPublicKey`, `BlsSignature`,
  `Bls{Pk,Sig}Share`, `BlsIes{Blob,Multi}`, `EcdsaPkBytes`, `EcdsaSigBytes`, `EcdsaRecSigBytes`, `EcdsaPkHash`,
  `EcdsaPublicKey`, `EcdsaSignature`, `EcdsaRecSignature`, `EddsaPkBytes`, `EddsaSigBytes`, `EddsaPkHash`,
  `EddsaPublicKey`, `EddsaSignature`.
- **The `serde` feature no longer implies `codec`.** `BlsIes{Blob,Multi}` and `BlsIes{Blob,Multi}Bytes` serialize as
  their wire image and implement `Serialize` and `Deserialize` only with `serde` and `codec` enabled, serving as the exception.

  - Callers that relied on `serde`
    to enable `codec` must enable it explicitly.
- Decoding `BlsIes{Blob,Multi}Bytes` (and by extension `BlsIes{Blob,Multi}`), enforces limits on lengths and counts.
  - A ciphertext length, blob count or blob length above `MAX_SER_SIZE` is rejected even when enough bytes remain.
  - A value past the remaining input is reported as `DecodeError::Eof`.
  - `BlsIesMultiBytes` rejects more than `MAX_IES_RECIPIENTS` ciphertexts.
- `BlsScheme::sk_to_bytes` returns `Zeroizing<[u8; 32]>` instead of a bare array. Code that binds the result as
  `[u8; 32]` must dereference it.
- `EcdsaRecSigBytes::from_raw` is renamed to `from_bytes`.

## [0.1.0-beta] - 2026-09-15

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-pkc-0.2.0-beta...HEAD
[0.2.0-beta]: https://github.com/dashpay/base-sdk/compare/dash-pkc-0.1.0-beta...dash-pkc-0.2.0-beta
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-pkc-0.1.0-beta
