# Changelog

All notable changes to `dash-params` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.
- `Network` and its `&'static` per-network tables are replaced by `NetworkKind` (with devnets), `Release` and an owned
  `ChainParams` built by `ChainParamsBuilder`, which applies Dash Core's chain-params and spork command-line options
  with Core's errors.
