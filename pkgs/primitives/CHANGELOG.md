# Changelog

All notable changes to `dash-primitives` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `Signable` for `JoinSig`, `DissolveSig` and `SharedRegistrarSig`, the consents the share owners of a shared
  masternode sign, and for `ProUpShareTx`. Each accepts only a canonical signature: a header from 27 to 34 and a low S.
- `Commitment::sig_hash`, the digest the quorum and the members of a final commitment sign.
- `request_id`, `msg_hash` and `sig_hash` on `MnHardFork` and `AssetUnlock`, and `llmq_sig_hash`, the digest a quorum
  signs for a signing request.
- `CollateralSig::as_slice` and `OwnerSig::as_slice`, the signature bytes as read.

### Changed

- `CollateralSig` and `OwnerSig` decode and deserialize a signature of any length. `as_bytes` returns `None` unless it
  is 65 bytes.
