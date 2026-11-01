//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The builder's options beyond the reference dumps, its typed setters and
//! the inputs this crate refuses where the reference accepts them or fails
//! an assertion.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_num::Hash256;
use dash_params::{
  BuriedDeployment, ChainOption, ChainParams, ChainParamsBuilder, ChainSetup, ConsensusParams, DeploymentPos,
  LlmqSizes, LlmqType, Network, ParamsError, Release,
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

/// The [`ChainParams`] that `Deref` and coercion reach.
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

  let p = build(devnet(release).devnet_name("alpha").pow_target_spacing(60));
  assert_eq!(p.consensus.pow_target_spacing, 60);
  assert_eq!(p.devnet_name(), Some("devnet-alpha"));
  assert_eq!(p.data_dir(), "devnet-alpha");
}

/// Options write the one [`ChainParams`] the setup holds, the LLMQ size
/// overrides included.
#[rstest]
fn options_write_the_chain_parameters(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let p = build(
    regtest(release)
      .arg(ChainOption::VbParams, "v24:5:9:10")
      .arg(ChainOption::LlmqTestParams, "5:4")
      .dip3(h(105), h(106))
      .fast_prune(true),
  );
  let v24 = chain(&p).consensus.deployments.v24;
  assert_eq!((v24.start_time, v24.timeout, v24.min_activation_height), (5, 9, h(10)));
  assert_eq!(p.deployment(DeploymentPos::V24), Some(&v24));
  assert_eq!(chain(&p).consensus.dip0003_height, h(105));
  assert_eq!(chain(&p).prune_after_height, 100);
  let q = p.consensus.llmq(LlmqType::LlmqTest).unwrap();
  assert_eq!(
    (q.size, q.min_size, q.threshold, q.dkg_bad_votes_threshold),
    (5, 4, 4, 4)
  );
  assert_eq!(p.consensus.llmq_sizes.test, Some((5, 4)));
  // A reader of the consensus parameters alone sees the override.
  let consensus: &ConsensusParams = &p.consensus;
  assert_eq!(consensus.llmq(LlmqType::LlmqTest), Some(q));
  // Types the option does not name keep the table's values.
  let is = LlmqType::LlmqTestInstantsend;
  assert_eq!(p.consensus.llmq(is), is.params());

  let p = build(
    devnet(release)
      .devnet_name("alpha")
      .arg(ChainOption::LlmqChainLocks, "llmq_50_60")
      .arg(ChainOption::HighSubsidyBlocks, "7"),
  );
  assert_eq!(chain(&p).consensus.llmq_type_chain_locks, LlmqType::Llmq50_60);
  assert_eq!(chain(&p).consensus.high_subsidy_blocks, 7);
}

/// Without size overrides, the setup's LLMQs are the static table's.
#[rstest]
fn llmqs_are_the_table_without_overrides(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let c = build(ChainParamsBuilder::new(network, release)).consensus;
  assert_eq!(c.llmq_sizes, LlmqSizes::NONE);
  for &t in c.llmqs {
    assert_eq!(c.llmq(t), t.params());
  }
  assert_eq!(c.llmq(LlmqType::LlmqNone), None);
}

/// A named devnet's checkpoints hold its own devnet genesis block.
#[rstest]
fn named_devnet_checkpoints(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let unnamed = build(devnet(release));
  let p = build(devnet(release).devnet_name("alpha"));
  let devnet_genesis = p.devnet_genesis().unwrap();
  assert_eq!(devnet_genesis.name, "devnet-alpha");
  assert_ne!(devnet_genesis.hash, unnamed.consensus.hash_devnet_genesis_block);
  assert_eq!(p.consensus.hash_devnet_genesis_block, devnet_genesis.hash);
  let checkpoints: Vec<_> = p.all_checkpoints().collect();
  assert_eq!(
    checkpoints,
    [(h(0), p.consensus.hash_genesis_block), (h(1), devnet_genesis.hash)]
  );
  assert_eq!(p.checkpoints, unnamed.checkpoints);
  assert_eq!(p.chain_tx_data.timestamp, i64::from(devnet_genesis.time));
  // An empty name is the unnamed devnet.
  assert_eq!(build(devnet(release).devnet_name("")), unnamed);
}

/// Off devnets, every checkpoint is in the table.
#[rstest]
fn only_devnets_add_a_checkpoint(
  #[values(Network::Main, Network::Testnet3, Network::Regtest)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let p = build(ChainParamsBuilder::new(network, release));
  assert_eq!(p.consensus.hash_devnet_genesis_block, Hash256::ZERO);
  assert!(p.all_checkpoints().eq(p.checkpoints.iter().copied()));
}

#[rstest]
fn activation_height_without_option_name_is_the_references_error() {
  let err = regtest(Release::V24_0)
    .activation_height(BuriedDeployment::Dip0003, h(5))
    .build()
    .unwrap_err();
  assert_eq!(
    err.to_string(),
    "Invalid name (dip0003@5) for -testactivationheight=name@height."
  );
}

/// The reference accepts negative `-dip3params`, `-budgetparams` and
/// `-vbparams` heights. A budget start of -1 pays the treasury at block 1,
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

/// The reference's own errors come before the negative height refusal,
/// within one option and across options read later.
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
fn reference_errors_come_first(#[case] args: &[(ChainOption, &str)], #[case] error: &str) {
  let mut builder = regtest(Release::V24_0);
  for (option, value) in args {
    builder = builder.arg(*option, *value);
  }
  assert_eq!(builder.build().unwrap_err().to_string(), error);
}

#[rstest]
fn negation_follows_the_settings() {
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
fn only_pow_target_spacing_forbids_negation() {
  let forbidden: Vec<ChainOption> = ChainOption::ALL.into_iter().filter(|o| !o.negatable()).collect();
  assert_eq!(forbidden, [ChainOption::PowTargetSpacing]);
}

#[rstest]
fn negated_pow_target_spacing_is_refused_on_every_chain(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let forbidden = ParamsError::NegationForbidden(ChainOption::PowTargetSpacing);
  let err = ChainParamsBuilder::new(network, release)
    .negate(ChainOption::PowTargetSpacing)
    .build()
    .unwrap_err();
  assert_eq!(err, forbidden);
  assert_eq!(
    err.to_string(),
    "Negating of -powtargetspacing is meaningless and therefore forbidden"
  );
  // The arguments are parsed before the chain parameters are built, and a
  // later value does not lift the refusal.
  let err = ChainParamsBuilder::new(network, release)
    .arg(ChainOption::Dip3Params, "x")
    .arg(ChainOption::LlmqDevnetParams, "x")
    .arg(ChainOption::LlmqTestParams, "-1:2")
    .negate(ChainOption::PowTargetSpacing)
    .pow_target_spacing(60)
    .build()
    .unwrap_err();
  assert_eq!(err, forbidden);
}

#[rstest]
fn zero_adjustment_interval_is_none() {
  let spaced = |s| build(devnet(Release::V24_0).pow_target_spacing(s));
  assert_eq!(spaced(150).consensus.difficulty_adjustment_interval(), Some(576));
  assert_eq!(spaced(86_401).consensus.difficulty_adjustment_interval(), None);
}

/// The reference asserts that regtest's V20 height is at least DIP0003's
/// and its MN_RR height at least V20's. The builder reports them instead.
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
  // The order is checked on the signed heights, before a negative one is
  // refused.
  let err = regtest(Release::V24_0)
    .arg(ChainOption::VbParams, "v24:0:9:-1")
    .dip3(h(600), h(600))
    .build()
    .unwrap_err();
  assert_eq!(err, ParamsError::V20BelowDip3);
}

/// An argument naming no chain option gives the builder back unchanged, so
/// the options around it still apply.
#[rstest]
fn unknown_arguments_keep_the_builder(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let mut builder = regtest(release);
  for arg in ["-fastprune", "-listen", "-dip3params=105:106"] {
    builder = builder.parse_arg(arg).unwrap_or_else(|unchanged| unchanged);
  }
  let p = build(builder.clone());
  assert_eq!(p.prune_after_height, 100);
  assert_eq!(p.consensus.dip0003_height, h(105));
  let unchanged = builder.clone().parse_arg("-listen").unwrap_err();
  assert_eq!(unchanged, builder);
}

/// A raw argument keeps its spelling and reads as the reference reads it.
#[rstest]
fn raw_arguments_follow_the_reference(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let parsed = |args: &[&str]| {
    args
      .iter()
      .try_fold(regtest(release), |b, arg| b.parse_arg(arg).ok())
      .map(|b| b.build())
  };
  let pruned = |args: &[&str]| parsed(args).unwrap().unwrap().prune_after_height == 100;
  assert!(pruned(&["-fastprune"]));
  assert!(pruned(&["--fastprune=1"]));
  assert!(pruned(&["-nofastprune=0"]));
  assert!(pruned(&["-nofastprune=x"]));
  assert!(!pruned(&["-fastprune", "-nofastprune"]));
  assert!(!pruned(&["-fastprune", "-nofastprune=1"]));
  assert!(!pruned(&["-fastprune", "-nofastprune="]));
  // A double negation of a repeatable option is a value, not a reset.
  let err = parsed(&["-vbparams=x", "-novbparams=0"]).unwrap().unwrap_err();
  assert_eq!(err, ParamsError::VbParamsMalformed);
  assert_eq!(
    parsed(&["-vbparams=x", "-novbparams"]).unwrap(),
    Ok(build(regtest(release)))
  );
  // Every negation of -powtargetspacing is refused, a double one included.
  let forbidden = Err(ParamsError::NegationForbidden(ChainOption::PowTargetSpacing));
  assert_eq!(parsed(&["-nopowtargetspacing=0"]).unwrap(), forbidden);
  // Arguments naming no chain option.
  for arg in ["-listen", "fastprune", "-regtest.fastprune", "-", "-no"] {
    assert_eq!(parsed(&[arg]), None, "{arg}");
  }
}

#[rstest]
fn options_of_other_chains_are_ignored(
  #[values(Network::Main, Network::Testnet3)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let mut builder = ChainParamsBuilder::new(network, release);
  for option in ChainOption::ALL {
    builder = builder.arg(option, "x");
  }
  assert_eq!(build(builder), build(ChainParamsBuilder::new(network, release)));
}

/// An LLMQ role option names one of the types the chain runs, by name.
/// `llmq_none` and types the chain does not run are invalid.
#[rstest]
#[case::devnet_none(Network::Devnet, ChainOption::LlmqChainLocks, "llmq_none", false)]
#[case::devnet_not_run(Network::Devnet, ChainOption::LlmqPlatform, "llmq_test_platform", false)]
#[case::devnet_unknown(Network::Devnet, ChainOption::LlmqMnhf, "llmq_x", false)]
#[case::devnet_run(Network::Devnet, ChainOption::LlmqMnhf, "llmq_400_85", true)]
#[case::regtest_none(Network::Regtest, ChainOption::LlmqTestInstantSendDip0024, "llmq_none", false)]
#[case::regtest_not_run(Network::Regtest, ChainOption::LlmqTestInstantSendDip0024, "llmq_devnet", false)]
#[case::regtest_run(Network::Regtest, ChainOption::LlmqTestInstantSendDip0024, "llmq_test", true)]
fn llmq_roles_name_types_the_chain_runs(
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
          .llmqs
          .iter()
          .copied()
          .find(|t| t.to_string() == name)
          .unwrap();
        let c = &p.consensus;
        let roles = [
          c.llmq_type_chain_locks,
          c.llmq_type_dip0024_instant_send,
          c.llmq_type_platform,
          c.llmq_type_mnhf,
        ];
        assert!(roles.contains(&t));
      }
      Err(err) => {
        assert!(!found, "{name}: {err}");
        assert_eq!(err, ParamsError::LlmqTypeName(option));
      }
    }
  }
}

#[rstest]
fn llmq_role_rotation_is_checked() {
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

/// An LLMQ size option, the quorum's name in its error text, the type it
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

/// The reference holds an LLMQ's size, minimum size and threshold in `i32`
/// fields and starts with any size or threshold outside `u16` that passes
/// its own checks. This crate refuses them with `LlmqOutOfRange`, after
/// every check the reference makes.
#[rstest]
fn llmq_sizes_outside_u16_are_refused(#[values(Release::V23_1, Release::V24_0)] release: Release) {
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

    // Outside u16, where the reference starts.
    assert_eq!(with("3:65536"), out_of_range(3, 65536));
    assert_eq!(with("-1:2"), out_of_range(-1, 2));
    assert_eq!(with("3:-1"), out_of_range(3, -1));
    assert_eq!(with("-2147483648:2147483647"), out_of_range(i32::MIN, i32::MAX));

    // Sizes above MAX_LLMQ_SIZE are the reference's error at v24 only.
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

    // Within one option, the value is split, then the size and then the
    // threshold are parsed.
    let error = |value: &str| with(value).unwrap_err().to_string();
    assert_eq!(error("-1:2b"), format!("Invalid {name} threshold (2b)"));
    assert_eq!(error("x:70000"), format!("Invalid {name} size (x)"));
    let malformed = format!("{name} parameters malformed, expecting <size>:<threshold>");
    assert_eq!(error("-1"), malformed);
    assert_eq!(error("-1:2:3"), malformed);

    // A later occurrence replaces an out-of-range one.
    let p = builder().arg(option, "-1:2").arg(option, "4:3").build().unwrap();
    assert_eq!(p.consensus.llmq(llmq_type).unwrap().size, 4);
  }
}

/// The reference's errors in options it reads after the size overrides,
/// its assertions and a negative height come before `LlmqOutOfRange`.
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
#[case::first_out_of_range(
  Network::Regtest,
  &[(ChainOption::LlmqTestPlatformParams, "3:70000"), (ChainOption::LlmqTestParams, "-1:2")],
  "LLMQ_TEST size (-1) or threshold (2) outside 0 to 65535"
)]
#[case::negative_height_first(
  Network::Regtest,
  &[(ChainOption::LlmqTestParams, "-1:2"), (ChainOption::Dip3Params, "-1:5")],
  "negative height -1 in -dip3params"
)]
fn out_of_range_sizes_come_last(#[case] network: Network, #[case] args: &[(ChainOption, &str)], #[case] error: &str) {
  for release in Release::ALL {
    let mut builder = ChainParamsBuilder::new(network, release);
    for (option, value) in args {
      builder = builder.arg(*option, *value);
    }
    assert_eq!(builder.build().unwrap_err().to_string(), error, "{release:?}");
  }
}

/// On networks that ignore an LLMQ size option, an out-of-range size is
/// not refused either.
#[rstest]
fn ignored_size_options_are_not_refused(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  for (option, _, _, reads) in LLMQ_SIZE_OPTIONS {
    for network in Network::ALL.into_iter().filter(|n| *n != reads) {
      let plain = build(ChainParamsBuilder::new(network, release));
      let p = build(ChainParamsBuilder::new(network, release).arg(option, "-1:2"));
      assert_eq!(p, plain, "{network:?} {}", option.name());
    }
  }
}

#[rstest]
fn llmq_derived_values() {
  let get = |t: LlmqType| t.params().unwrap();
  // Rotated, keep_old_keys over signing_active_quorum_count DKG intervals.
  assert_eq!(get(LlmqType::Llmq60_75).max_store_depth(), 64 / 32 * 288);
  assert_eq!(get(LlmqType::Llmq400_60).max_store_depth(), 8 * 288);
  assert!(LlmqType::AVAILABLE.iter().all(|t| !get(*t).is_single_member()));
  let types: Vec<u8> = LlmqType::AVAILABLE.iter().map(|t| t.to_base()).collect();
  assert_eq!(types, [100, 104, 102, 103, 106, 101, 105, 107, 1, 5, 2, 3, 4, 6]);
}
