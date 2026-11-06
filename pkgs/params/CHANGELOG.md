# Changelog

All notable changes to `dash-params` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `BRR_PERIODS_PERMILLE`, the masternode share of the block value in each block reward reallocation period.
- **`BuriedDeployment::Ipv4Optional` and `ConsensusParams::ipv4_optional_height`**, from which masternode primary
  addresses need not be IPv4. As in the reference implementation v24.0.0, the height is 0 on testnet and not scheduled
  (`ConsensusParams::NOT_SCHEDULED`) on mainnet and regtest.

### Changed

- **`ChainParams` drops the runtime-policy fields** `prune_after_height`, `assumed_blockchain_size_gb`,
  `assumed_chain_state_size_gb`, `default_consistency_checks` and `is_mockable_chain`.
