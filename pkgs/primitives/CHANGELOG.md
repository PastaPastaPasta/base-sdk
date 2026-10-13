# Changelog

All notable changes to `dash-primitives` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Fixed

- Decoding range-checks the `DynBitset` bit count, `CoinbaseCommitment::best_cl_height_diff` and the `NetInfoV2`
  purpose and entry counts against `MAX_SER_SIZE`, as consensus rules require. A `NetInfoV2` count or domain name
  length past the remaining input is reported as `DecodeError::Eof`.
- Decoding `GovVote` rejects a signature length above 96 before reading it, then a signature that is neither 65 nor 96
  bytes.
- Decoding a `NIEntry::Domain` rejects a name above 253 bytes before reading it.
