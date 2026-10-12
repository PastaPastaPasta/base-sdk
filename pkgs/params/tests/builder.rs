//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Builder behaviour beyond Core's corpus: typed setters, the inputs this
//! crate refuses where Core accepts or asserts, and the hard-coded pins.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_params::{
  BuriedDeployment, ChainOption, ChainParams, ChainParamsBuilder, DeploymentPos, LlmqParams, NetworkKind, ParamsError,
  Release, AVAILABLE_LLMQS,
};
use dash_primitives::LlmqType;
use dash_types::Numeric;
use rstest::rstest;

type BlockHeight = bitcoin_units::BlockHeight;

const fn h(height: u32) -> BlockHeight {
  BlockHeight::from_u32(height)
}

fn regtest(release: Release) -> ChainParamsBuilder {
  ChainParamsBuilder::new(NetworkKind::Regtest, release)
}

fn build(builder: ChainParamsBuilder) -> ChainParams {
  builder.build().unwrap()
}

#[rstest]
fn network_kind_matches_ffi_network() {
  let ids: Vec<(u8, &str)> = NetworkKind::ALL.iter().map(|n| (*n as u8, n.network_id())).collect();
  assert_eq!(ids, [(0, "main"), (1, "test"), (2, "devnet"), (3, "regtest")]);
  for n in NetworkKind::ALL {
    assert_eq!(NetworkKind::from_network_id(n.network_id()), Some(n));
  }
  for id in ["mainnet", "testnet", "devnet-x", "Main", ""] {
    assert_eq!(NetworkKind::from_network_id(id), None, "{id}");
  }
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
  assert_eq!(v23.consensus.deployment(DeploymentPos::V24).unwrap().bit, 12);
  assert_eq!(v24.consensus.deployment(DeploymentPos::V24).unwrap().bit, 13);
  assert!(v23.consensus.deployment(DeploymentPos::EvoShares).is_none());
  assert_eq!(v24.consensus.deployment(DeploymentPos::EvoShares).unwrap().bit, 14);
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

  let spacing = ChainParamsBuilder::new(NetworkKind::Devnet, release)
    .devnet_name("bs5")
    .pow_target_spacing(60);
  let p = build(spacing);
  assert_eq!(p.consensus.pow_target_spacing, 60);
  assert_eq!(p.devnet_name.as_deref(), Some("devnet-bs5"));
  assert_eq!(p.data_dir(), "devnet-bs5");
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
    let d = p.consensus.deployments[1];
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
  let spaced = |s| build(ChainParamsBuilder::new(NetworkKind::Devnet, Release::V24_0).pow_target_spacing(s));
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
  #[values(NetworkKind::Mainnet, NetworkKind::Testnet)] network: NetworkKind,
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

/// Core's hard-coded network pins, with their rule sites in
/// validation.cpp (ConnectBlock `bad-sb-start`, ContextualCheckBlockHeader
/// `bad-diffbits`, IsQuorumTypeEnabled) and deterministicmns.cpp
/// (`bad-dip3-enf-block`). Each value is checked on all four kinds.
#[rstest]
fn hard_coded_pins(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  for network in NetworkKind::ALL {
    let p = build(ChainParamsBuilder::new(network, release));
    let main = network == NetworkKind::Mainnet;
    // Core's TESTNET_LLMQ_25_67_ACTIVATION_HEIGHT is one global constant.
    assert_eq!(p.pins.llmq_25_67_activation_height, h(847_000), "{network:?}");
    // NetworkIDString() == MAIN && nHeight <= 68589.
    assert_eq!(p.pins.pre_dgw_tolerance_until, main.then_some(h(68_589)), "{network:?}");
    // Only mainnet pins the superblock start and DIP3 enforcement hashes.
    assert_eq!(
      p.consensus.superblock_start.1 != Default::default(),
      main,
      "{network:?}"
    );
    let enforcement_pinned = p.consensus.dip0003_enforcement.1 != Default::default();
    assert_eq!(
      enforcement_pinned,
      matches!(network, NetworkKind::Mainnet | NetworkKind::Testnet),
      "{network:?}"
    );
    let expected = match network {
      NetworkKind::Mainnet => (614_820, 1_047_200),
      NetworkKind::Testnet => (4200, 7300),
      NetworkKind::Devnet => (4200, 2),
      NetworkKind::Regtest => (1500, 500),
    };
    assert_eq!(p.consensus.superblock_start.0, h(expected.0), "{network:?}");
    assert_eq!(p.consensus.dip0003_enforcement.0, h(expected.1), "{network:?}");
    let has_25_67 = p.consensus.llmq(LlmqType::Llmq25_67).is_some();
    assert_eq!(has_25_67, network == NetworkKind::Testnet, "{network:?}");
  }
}

#[rstest]
fn default_spork_signers(
  #[values(
    NetworkKind::Mainnet,
    NetworkKind::Testnet,
    NetworkKind::Devnet,
    NetworkKind::Regtest
  )]
  network: NetworkKind,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let p = build(ChainParamsBuilder::new(network, release));
  assert_eq!(p.spork_signers.key_ids.len(), 1);
  assert_eq!(p.spork_signers.min_spork_keys, (release == Release::V23_1).then_some(1));
  assert_eq!(p.spork_signers.warning, None);
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
  for release in Release::ALL {
    let err = regtest(release)
      .arg(ChainOption::SporkAddr, "invalid")
      .build()
      .unwrap_err();
    assert_eq!(err.to_string(), "Invalid spork address specified with -sporkaddr");
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

#[rstest]
fn llmq_derived_values() {
  let get = |t| LlmqParams::available(t).unwrap();
  // Rotated: keepOldKeys / signingActiveQuorumCount cycles of dkgInterval.
  assert_eq!(get(LlmqType::Llmq60_75).max_store_depth(), 64 / 32 * 288);
  assert_eq!(get(LlmqType::Llmq400_60).max_store_depth(), 8 * 288);
  assert!(AVAILABLE_LLMQS.iter().all(|q| !q.is_single_member()));
  let types: Vec<u8> = AVAILABLE_LLMQS.iter().map(|q| q.llmq_type.to_base()).collect();
  assert_eq!(types, [100, 104, 102, 103, 106, 101, 105, 107, 1, 5, 2, 3, 4, 6]);
  for q in &AVAILABLE_LLMQS {
    assert_eq!(q.name, q.llmq_type.to_string(), "{:?}", q.llmq_type);
  }
}
