# Changelog

All notable changes to `dash-primitives` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `GovObject::signature_hash` and `GovVote::signature_hash`, Core's `GetSignatureHash()` (the object or vote as written
  without its signature).
