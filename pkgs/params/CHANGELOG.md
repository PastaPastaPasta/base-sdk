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
- `ConsensusParams` has a new public field, `llmq_sizes`, so a `ConsensusParams` literal must set it (the network tables
  use `LlmqSizes::NONE`). `ConsensusParams::llmq` applies these LLMQ size options.
- `ChainParamsBuilder` applies the reference implementation's chain-params options (`ChainOption`, set with `arg`,
  `negate`, `parse_arg` and typed setters), `-fastprune`, `-sporkaddr` and v23.1's `-minsporkkeys`, as each release
  does. `build` now returns `Result<ChainSetup, ParamsError>`, whose errors carry the reference's error text.
  `ChainSetup::spork_signers` holds the resolved spork signers. `ChainOption` and `ParamsError` are `#[non_exhaustive]`.
- The devnet table's `checkpoints` holds height 0 only. `ChainParams::all_checkpoints` adds a devnet's genesis block at
  height 1, which depends on the devnet's name.
- New helpers `BuriedDeployment::test_activation_name`, `ConsensusParams::difficulty_adjustment_interval`,
  `DeploymentPos::index`, `LlmqType::AVAILABLE`, `MAX_LLMQ_SIZE`, `LlmqParams::max_cycles`,
  `LlmqParams::max_store_depth`, `LlmqParams::is_single_member` and `Release::min_spork_keys`.
- `dash-params` now depends on `base58ck` and `thiserror`.
