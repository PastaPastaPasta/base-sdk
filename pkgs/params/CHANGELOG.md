# Changelog

All notable changes to `dash-params` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.
- `ChainSetup`, built by `ChainParamsBuilder` from a `Network` and a `Release`, holds the chain parameters of the
  reference implementation at v23.1.8 or v24.0.0-rc.5. It adds the devnet (`Network::Devnet` and its devnet genesis
  block), v23.1's parameters and each release's version-bits deployments to the network tables, which stay as they are.
  `contrib/params` regenerates the corpora that check it from the release tags.
- `dash-params` now depends on `dash-pow`, which "requires x86-64-v3 and AES", "NEON and AES" on AArch64 and "128-bit
  SIMD" on WebAssembly. Builds without those target features need the new `portable` feature.
- `Network::Devnet` sits before `Network::Regtest`, so the discriminant of `Regtest` is now 3.
