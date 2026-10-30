# Changelog

All notable changes to `dash-params` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.
- `ChainSetup`, built by `ChainParamsBuilder` from a `Network` and a `Release`, applies Dash Core's chain-params and
  spork command-line options with Core's errors. It adds devnets (`Network::Devnet`, named devnets and their devnet
  genesis blocks), v23.1's parameters, LLMQ overrides and the spork signers to the network tables, which stay as they
  are. LLMQ sizes and thresholds outside `u16`, which Core accepts, are refused (`ParamsError::LlmqOutOfRange`).
