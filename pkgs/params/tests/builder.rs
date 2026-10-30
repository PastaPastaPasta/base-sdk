//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Builder behaviour beyond Core's corpus: typed setters, the inputs this
//! crate refuses where Core accepts or asserts, and the hard-coded pins.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_num::Hash256;
use dash_params::{
  available_params, BuriedDeployment, ChainOption, ChainParams, ChainParamsBuilder, ChainSetup, DeploymentPos,
  LlmqType, Network, ParamsError, Release,
};
use dash_types::Numeric;
use rstest::rstest;

type BlockHeight = bitcoin_units::BlockHeight;

const fn h(height: u32) -> BlockHeight {
  BlockHeight::from_u32(height)
}

fn regtest(release: Release) -> ChainParamsBuilder {
  ChainParamsBuilder::new(Network::Regtest, release)
}

fn devnet(release: Release) -> ChainParamsBuilder {
  ChainParamsBuilder::new(Network::Devnet, release)
}

fn build(builder: ChainParamsBuilder) -> ChainSetup {
  builder.build().unwrap()
}

/// The [`ChainParams`] copy that `Deref` and coercion reach.
fn chain(setup: &ChainSetup) -> &ChainParams {
  setup
}

#[rstest]
fn option_names_round_trip() {
  for o in ChainOption::ALL {
    assert_eq!(ChainOption::from_name(o.name()), Some(o));
  }
  assert_eq!(ChainOption::from_name("dip3params"), None);
}

#[rstest]
fn deployments_follow_the_release() {
  let v23 = build(regtest(Release::V23_1));
  let v24 = build(regtest(Release::V24_0));
  assert_eq!(v23.deployment(DeploymentPos::V24).unwrap().bit, 12);
  assert_eq!(v24.deployment(DeploymentPos::V24).unwrap().bit, 13);
  assert!(v23.deployment(DeploymentPos::EvoShares).is_none());
  assert_eq!(v24.deployment(DeploymentPos::EvoShares).unwrap().bit, 14);
  let err = regtest(Release::V23_1)
    .arg(ChainOption::VbParams, "evo_shares:0:9")
    .build()
    .unwrap_err();
  assert_eq!(err.to_string(), "Invalid deployment (evo_shares)");
}

#[rstest]
fn typed_setters_equal_their_arguments(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let typed = regtest(release)
    .activation_height(BuriedDeployment::V20, h(1000))
    .activation_height(BuriedDeployment::MnRr, h(1001))
    .dip3(h(105), h(106))
    .budget(h(10), h(20), h(30))
    .fast_prune(true);
  let args = regtest(release)
    .arg(ChainOption::TestActivationHeight, "v20@1000")
    .arg(ChainOption::TestActivationHeight, "mn_rr@1001")
    .arg(ChainOption::Dip3Params, "105:106")
    .arg(ChainOption::BudgetParams, "10:20:30")
    .arg(ChainOption::FastPrune, "");
  let p = build(typed);
  assert_eq!(p, build(args));
  assert_eq!(p.consensus.dip0003_height, h(105));
  assert_eq!(p.consensus.budget_payments_start_block, h(20));
  assert_eq!(p.prune_after_height, 100);

  let p = build(devnet(release).devnet_name("bs5").pow_target_spacing(60));
  assert_eq!(p.consensus.pow_target_spacing, 60);
  assert_eq!(p.devnet_name.as_deref(), Some("devnet-bs5"));
  assert_eq!(p.data_dir(), "devnet-bs5");
}

/// Every override reaches both the setup's views and the [`ChainParams`]
/// copy, except the LLMQ parameters, which only the setup holds.
#[rstest]
fn overrides_reach_the_static_copy(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let p = build(
    regtest(release)
      .arg(ChainOption::VbParams, "v24:5:9:10")
      .arg(ChainOption::LlmqTestParams, "5:4")
      .dip3(h(105), h(106))
      .fast_prune(true),
  );
  assert_eq!(chain(&p).consensus, *p.consensus);
  assert_eq!(chain(&p).consensus.deployments.v24, p.consensus.deployments.v24);
  assert_eq!(p.consensus.deployments.v24.min_activation_height, h(10));
  assert_eq!(chain(&p).consensus.dip0003_height, h(105));
  assert_eq!(chain(&p).prune_after_height, 100);
  let q = p.consensus.llmq(LlmqType::LlmqTest).unwrap();
  assert_eq!(
    (q.size, q.min_size, q.threshold, q.dkg_bad_votes_threshold),
    (5, 4, 4, 4)
  );
  assert_eq!(available_params(LlmqType::LlmqTest).unwrap().size, 3);

  let p = build(
    devnet(release)
      .devnet_name("bs5")
      .arg(ChainOption::LlmqChainLocks, "llmq_50_60")
      .arg(ChainOption::HighSubsidyBlocks, "7"),
  );
  assert_eq!(chain(&p).consensus, *p.consensus);
  assert_eq!(chain(&p).consensus.llmq_type_chain_locks, LlmqType::Llmq50_60);
  assert_eq!(chain(&p).consensus.high_subsidy_blocks, 7);
}

/// A named devnet's checkpoints hold its own devnet genesis block, in the
/// setup and in the [`ChainParams`] copy (Q1).
#[rstest]
fn named_devnet_checkpoints(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let unnamed = build(devnet(release));
  let p = build(devnet(release).devnet_name("bs5"));
  let devnet_genesis = p.devnet_genesis.as_ref().unwrap();
  assert_eq!(devnet_genesis.name, "devnet-bs5");
  assert_ne!(devnet_genesis.hash, unnamed.consensus.hash_devnet_genesis_block);
  assert_eq!(p.consensus.hash_devnet_genesis_block, devnet_genesis.hash);
  assert_eq!(
    p.checkpoints,
    [(h(0), p.consensus.hash_genesis_block), (h(1), devnet_genesis.hash)]
  );
  assert_eq!(chain(&p).checkpoints, p.checkpoints);
  assert_eq!(chain(&p).chain_tx_data.timestamp, i64::from(devnet_genesis.time));
  // An empty name is the unnamed devnet.
  assert_eq!(build(devnet(release).devnet_name("")), unnamed);
}

#[rstest]
fn activation_height_without_option_name_is_cores_error() {
  let err = regtest(Release::V24_0)
    .activation_height(BuriedDeployment::Dip0003, h(5))
    .build()
    .unwrap_err();
  assert_eq!(
    err.to_string(),
    "Invalid name (dip0003@5) for -testactivationheight=name@height."
  );
}

/// BL-31: Core's `ParseInt32` accepts negative `-dip3params`, `-budgetparams`
/// and `-vbparams` heights; a budget start of -1 pays treasury at block 1,
/// which no unsigned height expresses, so they are refused, never clamped.
#[rstest]
#[case(ChainOption::BudgetParams, "10:-1:30", -1)]
#[case(ChainOption::BudgetParams, "-5:20:30", -5)]
#[case(ChainOption::BudgetParams, "10:20:-2147483648", -2_147_483_648)]
#[case(ChainOption::Dip3Params, "-1:106", -1)]
#[case(ChainOption::Dip3Params, "105:-106", -106)]
#[case(ChainOption::VbParams, "v24:0:999:-350", -350)]
fn negative_heights_are_refused(#[case] option: ChainOption, #[case] value: &str, #[case] got: i64) {
  for release in Release::ALL {
    let err = regtest(release).arg(option, value).build().unwrap_err();
    assert_eq!(err, ParamsError::NegativeHeight(option, got));
  }
}

/// A later `-vbparams` replaces an earlier negative minimum height, so only
/// a height still negative in the final parameters is refused.
#[rstest]
fn overwritten_negative_heights_are_accepted(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  for second in ["v24:0:9:0", "v24:0:9"] {
    let p = build(
      regtest(release)
        .arg(ChainOption::VbParams, "v24:0:9:-1")
        .arg(ChainOption::VbParams, second),
    );
    let d = p.consensus.deployments.v24;
    assert_eq!(
      (d.start_time, d.timeout, d.min_activation_height),
      (0, 9, h(0)),
      "{second}"
    );
  }
  let err = regtest(release)
    .arg(ChainOption::VbParams, "testdummy:0:9:-5")
    .arg(ChainOption::VbParams, "v24:0:9:-1")
    .arg(ChainOption::VbParams, "v24:0:9:0")
    .build()
    .unwrap_err();
  assert_eq!(err, ParamsError::NegativeHeight(ChainOption::VbParams, -5));
  let p = build(regtest(release).arg(ChainOption::Dip3Params, "-1:5").dip3(h(4), h(5)));
  assert_eq!(p.consensus.dip0003_height, h(4));
}

/// Core's own errors take precedence over the BL-31 refusal, within one
/// option and across options read later.
#[rstest]
#[case(&[(ChainOption::Dip3Params, "-1:x")], "Invalid enforcement height (x)")]
#[case(&[(ChainOption::VbParams, "nope:0:9:-1")], "Invalid deployment (nope)")]
#[case(
  &[(ChainOption::Dip3Params, "-1:600"), (ChainOption::BudgetParams, "x")],
  "Budget parameters malformed, expecting <masternode>:<budget>:<superblock>"
)]
#[case(&[(ChainOption::VbParams, "v24:0:9:-1"), (ChainOption::VbParams, "nope:1:2")], "Invalid deployment (nope)")]
#[case(
  &[(ChainOption::BudgetParams, "-1:2:3"), (ChainOption::LlmqTestInstantSendDip0024, "x")],
  "Invalid LLMQ type specified for -llmqtestinstantsenddip0024."
)]
fn cores_errors_come_first(#[case] args: &[(ChainOption, &str)], #[case] core: &str) {
  let mut builder = regtest(Release::V24_0);
  for (option, value) in args {
    builder = builder.arg(*option, *value);
  }
  assert_eq!(builder.build().unwrap_err().to_string(), core);
}

#[rstest]
fn negation_follows_cores_settings() {
  // A repeatable option keeps the values after its last negation.
  let p = build(
    regtest(Release::V24_0)
      .arg(ChainOption::TestActivationHeight, "x")
      .negate(ChainOption::TestActivationHeight)
      .arg(ChainOption::TestActivationHeight, "v19@5"),
  );
  assert_eq!(p.consensus.v19_height, h(5));
  let p = build(
    regtest(Release::V24_0)
      .arg(ChainOption::VbParams, "x")
      .negate(ChainOption::VbParams),
  );
  assert_eq!(p, build(regtest(Release::V24_0)));
  // A single-valued option reads a trailing negation as `0`.
  let err = regtest(Release::V24_0)
    .dip3(h(1), h(2))
    .negate(ChainOption::Dip3Params)
    .build()
    .unwrap_err();
  assert_eq!(err, ParamsError::Dip3Malformed);
  let p = build(regtest(Release::V24_0).fast_prune(true).negate(ChainOption::FastPrune));
  assert_eq!(p.prune_after_height, 1000);
}

#[rstest]
fn zero_adjustment_interval_is_none() {
  let spaced = |s| build(devnet(Release::V24_0).pow_target_spacing(s));
  assert_eq!(spaced(150).consensus.difficulty_adjustment_interval(), Some(576));
  assert_eq!(spaced(86_401).consensus.difficulty_adjustment_interval(), None);
}

/// Core asserts `V20Height >= DIP0003Height` and `MN_RRHeight >= V20Height`
/// at the end of the regtest constructor; the builder reports them instead.
#[rstest]
fn regtest_height_order_is_checked() {
  let err = regtest(Release::V24_0).dip3(h(600), h(600)).build().unwrap_err();
  assert_eq!(err, ParamsError::V20BelowDip3);
  let err = regtest(Release::V24_0)
    .activation_height(BuriedDeployment::MnRr, h(5))
    .build()
    .unwrap_err();
  assert_eq!(err, ParamsError::MnRrBelowV20);
  let ok = regtest(Release::V24_0)
    .dip3(h(600), h(600))
    .activation_height(BuriedDeployment::V20, h(600))
    .activation_height(BuriedDeployment::MnRr, h(600));
  assert_eq!(build(ok).consensus.v20_height, h(600));
}

#[rstest]
fn options_of_other_chains_are_ignored(
  #[values(Network::Main, Network::Testnet3)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let mut builder = ChainParamsBuilder::new(network, release);
  // The spork options are read on every chain.
  let chain_only = |o: &ChainOption| !matches!(o, ChainOption::SporkAddr | ChainOption::MinSporkKeys);
  for option in ChainOption::ALL.into_iter().filter(chain_only) {
    builder = builder.arg(option, "x");
  }
  assert_eq!(build(builder), build(ChainParamsBuilder::new(network, release)));
}

/// n-6: an LLMQ role option names one of the chain's configured types, by
/// Core's name; `llmq_none` and types the chain does not run are Core's
/// "Invalid LLMQ type" (chainparams.cpp:178-195).
#[rstest]
#[case::devnet_none(Network::Devnet, ChainOption::LlmqChainLocks, "llmq_none", false)]
#[case::devnet_unconfigured(Network::Devnet, ChainOption::LlmqPlatform, "llmq_test_platform", false)]
#[case::devnet_unknown(Network::Devnet, ChainOption::LlmqMnhf, "llmq_x", false)]
#[case::devnet_configured(Network::Devnet, ChainOption::LlmqMnhf, "llmq_400_85", true)]
#[case::regtest_none(Network::Regtest, ChainOption::LlmqTestInstantSendDip0024, "llmq_none", false)]
#[case::regtest_unconfigured(Network::Regtest, ChainOption::LlmqTestInstantSendDip0024, "llmq_devnet", false)]
#[case::regtest_configured(Network::Regtest, ChainOption::LlmqTestInstantSendDip0024, "llmq_test", true)]
fn llmq_roles_name_configured_types(
  #[case] network: Network,
  #[case] option: ChainOption,
  #[case] name: &str,
  #[case] found: bool,
) {
  for release in Release::ALL {
    let result = ChainParamsBuilder::new(network, release).arg(option, name).build();
    match result {
      Ok(p) => {
        assert!(found, "{name}");
        let t = p
          .consensus
          .llmq_params()
          .find(|(t, _)| t.to_string() == name)
          .unwrap()
          .0;
        assert!([
          p.consensus.llmq_type_chain_locks,
          p.consensus.llmq_type_dip0024_instant_send,
          p.consensus.llmq_type_platform,
          p.consensus.llmq_type_mnhf,
        ]
        .contains(&t));
      }
      Err(err) => {
        assert!(!found, "{name}: {err}");
        assert_eq!(err, ParamsError::LlmqTypeName(option));
      }
    }
  }
}

#[rstest]
fn llmq_role_rotation_is_cores() {
  let err = devnet(Release::V24_0)
    .arg(ChainOption::LlmqChainLocks, "llmq_devnet_dip0024")
    .build()
    .unwrap_err();
  assert_eq!(
    err.to_string(),
    "LLMQ type specified for -llmqchainlocks must NOT use rotation"
  );
  let err = devnet(Release::V24_0)
    .arg(ChainOption::LlmqInstantSendDip0024, "llmq_devnet")
    .build()
    .unwrap_err();
  assert_eq!(
    err.to_string(),
    "LLMQ type specified for -llmqinstantsenddip0024 must use rotation"
  );
}

/// The LLMQ size override's option, Core's quorum name for it, the type it
/// changes and the network that reads it.
const LLMQ_SIZE_OPTIONS: [(ChainOption, &str, LlmqType, Network); 2] = [
  (
    ChainOption::LlmqTestParams,
    "LLMQ_TEST",
    LlmqType::LlmqTest,
    Network::Regtest,
  ),
  (
    ChainOption::LlmqDevnetParams,
    "LLMQ_DEVNET",
    LlmqType::LlmqDevnet,
    Network::Devnet,
  ),
];

/// Quirk 46: Core types an LLMQ's size, minSize and threshold as `int` and
/// starts with any size or threshold outside `u16` that passes its own
/// checks; `dash-params` refuses them with `LlmqOutOfRange`, after every
/// check Core makes.
#[rstest]
fn quirk_46_llmq_overrides_outside_u16(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let v24 = release == Release::V24_0;
  for (option, name, llmq_type, network) in LLMQ_SIZE_OPTIONS {
    let builder = || ChainParamsBuilder::new(network, release);
    let with = |value: &str| builder().arg(option, value).build();
    let out_of_range = |size, threshold| Err(ParamsError::LlmqOutOfRange(name, size, threshold));

    // In range, at the u16 boundary.
    let p = with("3:65535").unwrap();
    let q = p.consensus.llmq(llmq_type).unwrap();
    assert_eq!(
      (q.size, q.min_size, q.threshold, q.dkg_bad_votes_threshold),
      (3, 65535, 65535, 65535)
    );
    let p = with("0:0").unwrap();
    assert_eq!(p.consensus.llmq(llmq_type).unwrap().size, 0);

    // Outside u16, where Core starts.
    assert_eq!(with("3:65536"), out_of_range(3, 65536));
    assert_eq!(with("-1:2"), out_of_range(-1, 2));
    assert_eq!(with("3:-1"), out_of_range(3, -1));
    assert_eq!(with("-2147483648:2147483647"), out_of_range(i32::MIN, i32::MAX));

    // Sizes above MAX_LLMQ_SIZE are Core's error at v24 only.
    let too_large = |size| Err(ParamsError::LlmqSizeTooLarge(name, size));
    assert_eq!(with("400:2").unwrap().consensus.llmq(llmq_type).unwrap().size, 400);
    if v24 {
      assert_eq!(with("401:2"), too_large(401));
      assert_eq!(with("65535:2"), too_large(65535));
      assert_eq!(with("65536:2"), too_large(65536));
      assert_eq!(with("1000000:-1"), too_large(1_000_000));
    } else {
      assert_eq!(with("65535:2").unwrap().consensus.llmq(llmq_type).unwrap().size, 65535);
      assert_eq!(with("65536:2"), out_of_range(65536, 2));
      assert_eq!(with("1000000:2"), out_of_range(1_000_000, 2));
    }

    // Within one option, Core splits, parses the size, then the threshold.
    let core = |value: &str| with(value).unwrap_err().to_string();
    assert_eq!(core("-1:2b"), format!("Invalid {name} threshold (2b)"));
    assert_eq!(core("x:70000"), format!("Invalid {name} size (x)"));
    assert_eq!(
      core("-1"),
      format!("{name} parameters malformed, expecting <size>:<threshold>")
    );
    assert_eq!(
      core("-1:2:3"),
      format!("{name} parameters malformed, expecting <size>:<threshold>")
    );

    // A later occurrence replaces an out-of-range one.
    let p = builder().arg(option, "-1:2").arg(option, "4:3").build().unwrap();
    assert_eq!(p.consensus.llmq(llmq_type).unwrap().size, 4);
  }
}

/// Quirk 46 across options: Core's errors in options it reads after the
/// size overrides, and its asserts, come before `LlmqOutOfRange`.
#[rstest]
#[case::regtest_dip0024(
  Network::Regtest,
  &[(ChainOption::LlmqTestParams, "-1:2"), (ChainOption::LlmqTestInstantSendDip0024, "bogus")],
  "Invalid LLMQ type specified for -llmqtestinstantsenddip0024."
)]
#[case::regtest_is_threshold(
  Network::Regtest,
  &[(ChainOption::LlmqTestParams, "-1:2"), (ChainOption::LlmqTestInstantSendParams, "1:2b")],
  "Invalid LLMQ_TEST_INSTANTSEND threshold (2b)"
)]
#[case::regtest_assert(
  Network::Regtest,
  &[(ChainOption::LlmqTestPlatformParams, "3:70000"), (ChainOption::Dip3Params, "600:600")],
  "v20 height below dip0003 height"
)]
#[case::devnet_spacing(
  Network::Devnet,
  &[(ChainOption::LlmqDevnetParams, "-2:9"), (ChainOption::PowTargetSpacing, "abc")],
  "Invalid parsing of powTargetSpacing (abc)"
)]
#[case::spork_address(
  Network::Regtest,
  &[(ChainOption::LlmqTestParams, "-1:2"), (ChainOption::SporkAddr, "invalid")],
  "Invalid spork address specified with -sporkaddr"
)]
#[case::first_out_of_range(
  Network::Regtest,
  &[(ChainOption::LlmqTestPlatformParams, "3:70000"), (ChainOption::LlmqTestParams, "-1:2")],
  "LLMQ_TEST size (-1) or threshold (2) outside 0 to 65535"
)]
fn quirk_46_cores_errors_come_first(
  #[case] network: Network,
  #[case] args: &[(ChainOption, &str)],
  #[case] error: &str,
) {
  for release in Release::ALL {
    let mut builder = ChainParamsBuilder::new(network, release);
    for (option, value) in args {
      builder = builder.arg(*option, *value);
    }
    assert_eq!(builder.build().unwrap_err().to_string(), error, "{release:?}");
  }
}

/// Quirk 46 on networks where Core ignores the option: nothing is refused.
#[rstest]
fn quirk_46_ignored_options_start(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  for (option, _, _, reads) in LLMQ_SIZE_OPTIONS {
    for network in Network::ALL.into_iter().filter(|n| *n != reads) {
      let plain = build(ChainParamsBuilder::new(network, release));
      let p = build(ChainParamsBuilder::new(network, release).arg(option, "-1:2"));
      assert_eq!(p, plain, "{network:?} {}", option.name());
    }
  }
}

/// Quirk 34: Core's hard-coded network pins, with their rule sites in
/// validation.cpp (ConnectBlock `bad-sb-start`, ContextualCheckBlockHeader
/// `bad-diffbits`, IsQuorumTypeEnabled) and deterministicmns.cpp
/// (`bad-dip3-enf-block`). Each value is checked on all four networks.
#[rstest]
fn hard_coded_pins(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  for network in Network::ALL {
    let p = build(ChainParamsBuilder::new(network, release));
    let main = network == Network::Main;
    // Core's TESTNET_LLMQ_25_67_ACTIVATION_HEIGHT is one global constant.
    assert_eq!(p.pins.llmq_25_67_activation_height, h(847_000), "{network:?}");
    // NetworkIDString() == MAIN && nHeight <= 68589.
    assert_eq!(p.pins.pre_dgw_tolerance_until, main.then_some(h(68_589)), "{network:?}");
    // Only mainnet pins the superblock start and DIP3 enforcement hashes.
    assert_eq!(p.consensus.superblock_start.1 != Hash256::ZERO, main, "{network:?}");
    let enforcement_pinned = p.consensus.dip0003_enforcement.1 != Hash256::ZERO;
    assert_eq!(
      enforcement_pinned,
      matches!(network, Network::Main | Network::Testnet3),
      "{network:?}"
    );
    let expected = match network {
      Network::Main => (614_820, 1_047_200),
      Network::Testnet3 => (4200, 7300),
      Network::Devnet => (4200, 2),
      Network::Regtest => (1500, 500),
    };
    assert_eq!(p.consensus.superblock_start.0, h(expected.0), "{network:?}");
    assert_eq!(p.consensus.dip0003_enforcement.0, h(expected.1), "{network:?}");
    let has_25_67 = p.consensus.llmq(LlmqType::Llmq25_67).is_some();
    assert_eq!(has_25_67, network == Network::Testnet3, "{network:?}");
  }
}

#[rstest]
fn llmq_derived_values() {
  let get = |t| available_params(t).unwrap();
  // Rotated: keepOldKeys / signingActiveQuorumCount cycles of dkgInterval.
  assert_eq!(get(LlmqType::Llmq60_75).max_store_depth(), 64 / 32 * 288);
  assert_eq!(get(LlmqType::Llmq400_60).max_store_depth(), 8 * 288);
  assert!(LlmqType::AVAILABLE.iter().all(|t| !get(*t).is_single_member()));
  let types: Vec<u8> = LlmqType::AVAILABLE.iter().map(|t| t.to_base()).collect();
  assert_eq!(types, [100, 104, 102, 103, 106, 101, 105, 107, 1, 5, 2, 3, 4, 6]);
  assert_eq!(available_params(LlmqType::LlmqNone), None);
  assert_eq!(available_params(LlmqType::Unknown(0xfe)), None);
}

#[rstest]
fn default_spork_signers(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let p = build(ChainParamsBuilder::new(network, release));
  assert_eq!(p.spork_signers.key_ids.len(), 1);
  assert_eq!(p.spork_signers.min_spork_keys, (release == Release::V23_1).then_some(1));
  assert_eq!(p.spork_signers.warning, None);
  let named = build(ChainParamsBuilder::new(network, release).arg(ChainOption::SporkAddr, p.spork_address));
  assert_eq!(named.spork_signers, p.spork_signers);
}

const REGTEST_SIGNER: &str = "yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW";
const TESTNET_SIGNER: &str = "yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55";

#[rstest]
fn spork_overrides_follow_the_release() {
  let two = |release| {
    regtest(release)
      .arg(ChainOption::SporkAddr, REGTEST_SIGNER)
      .arg(ChainOption::SporkAddr, TESTNET_SIGNER)
  };
  // v23: a set of signers, whose threshold must be a majority of them.
  assert_eq!(two(Release::V23_1).build().unwrap_err(), ParamsError::MinSporkKeys);
  let p = build(two(Release::V23_1).arg(ChainOption::MinSporkKeys, "2"));
  assert_eq!(
    (p.spork_signers.key_ids.len(), p.spork_signers.min_spork_keys),
    (2, Some(2))
  );
  assert!(p.spork_signers.key_ids.is_sorted());
  let err = two(Release::V23_1)
    .arg(ChainOption::MinSporkKeys, "3")
    .build()
    .unwrap_err();
  assert_eq!(
    err.to_string(),
    "Invalid minimum number of spork signers specified with -minsporkkeys"
  );
  // v24: the last address, with Core's warning, and no threshold option.
  let p = build(two(Release::V24_0));
  assert_eq!(p.spork_signers.key_ids.len(), 1);
  let warning = format!("More than one spork address is provided. Using {TESTNET_SIGNER}.");
  assert_eq!(p.spork_signers.warning, Some(warning));
  let err = two(Release::V24_0)
    .arg(ChainOption::MinSporkKeys, "2")
    .build()
    .unwrap_err();
  assert_eq!(err.to_string(), "Invalid parameter -minsporkkeys=2");
  let err = regtest(Release::V24_0)
    .negate(ChainOption::MinSporkKeys)
    .build()
    .unwrap_err();
  assert_eq!(err.to_string(), "Invalid parameter -nominsporkkeys");
  for release in Release::ALL {
    for invalid in ["invalid", "", "tdash1qqqqqqqq", "yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW\0"] {
      let err = regtest(release)
        .arg(ChainOption::SporkAddr, invalid)
        .build()
        .unwrap_err();
      assert_eq!(
        err.to_string(),
        "Invalid spork address specified with -sporkaddr",
        "{invalid}"
      );
    }
    // A mainnet address on regtest.
    let err = regtest(release)
      .arg(ChainOption::SporkAddr, "Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh")
      .build()
      .unwrap_err();
    assert_eq!(err, ParamsError::SporkAddress);
    // Core's whitespace around a base58 address is skipped.
    let spaced = build(regtest(release).arg(ChainOption::SporkAddr, format!(" {TESTNET_SIGNER}\t")));
    let plain = build(regtest(release).arg(ChainOption::SporkAddr, TESTNET_SIGNER));
    assert_eq!(spaced.spork_signers, plain.spork_signers);
    // Chain params errors come before spork errors (startup order).
    let err = regtest(release)
      .arg(ChainOption::SporkAddr, "invalid")
      .arg(ChainOption::Dip3Params, "x")
      .build()
      .unwrap_err();
    assert_eq!(err, ParamsError::Dip3Malformed);
  }
}
