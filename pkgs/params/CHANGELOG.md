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
- `ChainParams::min_blocks_to_keep`: pruning keeps the block files of the blocks this close to the tip. At
  `Release::V24_0` it is 2304 (four days) on mainnet, testnet and devnets and 288 on regtest; at `Release::V23_1` it
  is 288 on every chain.
- `Release::V24_0` and the network tables follow Dash Core v24.0.0-rc.5: the mainnet `v24` and `evo_shares`
  schedule, the minimum chain work, assumed-valid block, checkpoints and transaction statistics of mainnet and
  testnet, the fixed seeds, the assumed mainnet size (62 GB) and the testnet and devnet prune height (3000).
  `Release::V23_1` keeps v23.1.8's values.
