//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Builder of the chain parameters a node runs, with the reference
//! implementation's chain-params options applied.

use crate::error::{ParamsError, VbField};
use crate::parse::{int_arg, interpret_bool, parse_i32, parse_i64};
use crate::prelude::*;
use crate::spork::spork_key_id;
use crate::{BuriedDeployment, ChainSetup, DeploymentPos, LlmqType, Network, Release, SporkSigners, MAX_LLMQ_SIZE};

use bitcoin_units::BlockHeight;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// A command-line option of the reference implementation that changes the
/// chain parameters.
///
/// These are its chain-params options, `-fastprune`, which regtest's prune
/// height reads, and the spork signer options, which its startup reads after
/// the chain parameters.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[non_exhaustive]
pub enum ChainOption {
  /// `-budgetparams=<masternode>:<budget>:<superblock>` (regtest).
  BudgetParams,
  /// `-devnet=<name>` (devnet).
  Devnet,
  /// `-dip3params=<activation>:<enforcement>` (regtest).
  Dip3Params,
  /// `-fastprune` (regtest).
  FastPrune,
  /// `-highsubsidyblocks=<n>` (devnet).
  HighSubsidyBlocks,
  /// `-highsubsidyfactor=<n>` (devnet).
  HighSubsidyFactor,
  /// `-llmqchainlocks=<quorum name>` (devnet).
  LlmqChainLocks,
  /// `-llmqdevnetparams=<size>:<threshold>` (devnet).
  LlmqDevnetParams,
  /// `-llmqinstantsenddip0024=<quorum name>` (devnet).
  LlmqInstantSendDip0024,
  /// `-llmqmnhf=<quorum name>` (devnet).
  LlmqMnhf,
  /// `-llmqplatform=<quorum name>` (devnet).
  LlmqPlatform,
  /// `-llmqtestinstantsenddip0024=<quorum name>` (regtest).
  LlmqTestInstantSendDip0024,
  /// `-llmqtestinstantsendparams=<size>:<threshold>` (regtest).
  LlmqTestInstantSendParams,
  /// `-llmqtestparams=<size>:<threshold>` (regtest).
  LlmqTestParams,
  /// `-llmqtestplatformparams=<size>:<threshold>` (regtest).
  LlmqTestPlatformParams,
  /// `-minimumdifficultyblocks=<n>` (devnet).
  MinimumDifficultyBlocks,
  /// `-minsporkkeys=<n>` (every chain, v23.1 only).
  MinSporkKeys,
  /// `-powtargetspacing=<n>` (devnet).
  PowTargetSpacing,
  /// `-sporkaddr=<address>` (every chain, repeatable at v23.1).
  SporkAddr,
  /// `-testactivationheight=name@height` (regtest, repeatable).
  TestActivationHeight,
  /// `-vbparams=<deployment>:<start>:<end>...` (regtest, repeatable).
  VbParams,
}

impl ChainOption {
  /// Every option, in name order.
  pub const ALL: [Self; 21] = [
    Self::BudgetParams,
    Self::Devnet,
    Self::Dip3Params,
    Self::FastPrune,
    Self::HighSubsidyBlocks,
    Self::HighSubsidyFactor,
    Self::LlmqChainLocks,
    Self::LlmqDevnetParams,
    Self::LlmqInstantSendDip0024,
    Self::LlmqMnhf,
    Self::LlmqPlatform,
    Self::LlmqTestInstantSendDip0024,
    Self::LlmqTestInstantSendParams,
    Self::LlmqTestParams,
    Self::LlmqTestPlatformParams,
    Self::MinimumDifficultyBlocks,
    Self::MinSporkKeys,
    Self::PowTargetSpacing,
    Self::SporkAddr,
    Self::TestActivationHeight,
    Self::VbParams,
  ];

  /// The option's name with its leading dash.
  pub const fn name(self) -> &'static str {
    match self {
      Self::BudgetParams => "-budgetparams",
      Self::Devnet => "-devnet",
      Self::Dip3Params => "-dip3params",
      Self::FastPrune => "-fastprune",
      Self::HighSubsidyBlocks => "-highsubsidyblocks",
      Self::HighSubsidyFactor => "-highsubsidyfactor",
      Self::LlmqChainLocks => "-llmqchainlocks",
      Self::LlmqDevnetParams => "-llmqdevnetparams",
      Self::LlmqInstantSendDip0024 => "-llmqinstantsenddip0024",
      Self::LlmqMnhf => "-llmqmnhf",
      Self::LlmqPlatform => "-llmqplatform",
      Self::LlmqTestInstantSendDip0024 => "-llmqtestinstantsenddip0024",
      Self::LlmqTestInstantSendParams => "-llmqtestinstantsendparams",
      Self::LlmqTestParams => "-llmqtestparams",
      Self::LlmqTestPlatformParams => "-llmqtestplatformparams",
      Self::MinimumDifficultyBlocks => "-minimumdifficultyblocks",
      Self::MinSporkKeys => "-minsporkkeys",
      Self::PowTargetSpacing => "-powtargetspacing",
      Self::SporkAddr => "-sporkaddr",
      Self::TestActivationHeight => "-testactivationheight",
      Self::VbParams => "-vbparams",
    }
  }

  /// The option named `name`, with its leading dash.
  pub fn from_name(name: &str) -> Option<Self> {
    Self::ALL.into_iter().find(|o| o.name() == name)
  }

  /// Whether the reference accepts `-no<option>`.
  ///
  /// It forbids every negation of `-powtargetspacing` on every chain, the
  /// double negative `-nopowtargetspacing=0` included.
  pub const fn negatable(self) -> bool {
    !matches!(self, Self::PowTargetSpacing)
  }
}

/// Which rotation an LLMQ role option requires of the type it names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
enum Rotation {
  Any,
  Required,
  Forbidden,
}

/// One occurrence of an option on the command line.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
struct Occurrence {
  /// The option.
  option: ChainOption,
  /// Whether it is spelled `-no<option>`.
  negated: bool,
  /// The text after the first `=`, if there is one.
  value: Option<String>,
  /// The argument as the caller spelled it, for the reference's error texts.
  arg: String,
}

impl Occurrence {
  /// The setting it gives, or `None` for a negation.
  ///
  /// A bare option is the empty string. A negation with a false value, such
  /// as `-nofastprune=0`, is the double negation `1`, but only for a
  /// [`negatable`](ChainOption::negatable) option.
  fn setting(&self) -> Option<&str> {
    match (self.negated, self.value.as_deref()) {
      (false, value) => Some(value.unwrap_or("")),
      (true, Some(v)) if self.option.negatable() && !interpret_bool(v) => Some("1"),
      (true, _) => None,
    }
  }
}

/// Builds the [`ChainSetup`] of a network at a release, with the reference
/// implementation's chain-params options applied as it applies them.
///
/// Options are kept as command-line settings. Each [`arg`](Self::arg),
/// [`negate`](Self::negate) or [`parse_arg`](Self::parse_arg) is one
/// occurrence. A single-valued option reads its last occurrence and a
/// repeatable one the values after its last negation. The reference refuses
/// any negation of an option that is not
/// [`negatable`](ChainOption::negatable) before it reads the value.
///
/// The occurrences have command-line semantics only. The reference merges
/// other sources by other rules (a config file keeps its first value,
/// network sections apply to their chain). A caller with other sources
/// passes the resolved settings, one occurrence per single-valued option and
/// the resolved list for each repeatable one.
///
/// [`build`](Self::build) applies the options of the chain's kind in the
/// reference's order and ignores the others, as the reference does, so an
/// error the reference reports is reported first.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct ChainParamsBuilder {
  network: Network,
  release: Release,
  args: Vec<Occurrence>,
}

impl ChainParamsBuilder {
  /// A builder for `network` at `release` with no options.
  pub const fn new(network: Network, release: Release) -> Self {
    Self {
      network,
      release,
      args: Vec::new(),
    }
  }

  /// Adds one occurrence of `option` with `value`, as
  /// `<option>=<value>`.
  pub fn arg(mut self, option: ChainOption, value: impl Into<String>) -> Self {
    let value = value.into();
    let arg = format!("{}={value}", option.name());
    self.args.push(Occurrence {
      option,
      negated: false,
      value: Some(value),
      arg,
    });
    self
  }

  /// Adds one negated occurrence of `option`, as `-no<option>`.
  pub fn negate(mut self, option: ChainOption) -> Self {
    let arg = format!("-no{}", option.name().trim_start_matches('-'));
    self.args.push(Occurrence {
      option,
      negated: true,
      value: None,
      arg,
    });
    self
  }

  /// Adds the command-line argument `arg`, such as `-nofastprune=0`, as the
  /// reference parses it on this platform.
  ///
  /// The argument keeps its spelling, which the reference's error texts
  /// quote. A leading `--` reads as `-`, and `-no<option>` is a negation.
  /// On Windows the name before any `=` reads in ASCII lowercase and a
  /// leading `/` reads as `-`, as the reference's Windows builds read it.
  /// The value keeps its case.
  ///
  /// # Errors
  ///
  /// The builder, unchanged, if `arg` names no [`ChainOption`]. A caller
  /// passing a node's whole command line keeps it and goes on, up to a bare
  /// `-`, where the reference stops reading. Outside Windows a name in
  /// another case, such as `-DIP3PARAMS`, or with a leading `/` names no
  /// option, and the node refuses it at startup.
  pub fn parse_arg(self, arg: &str) -> Result<Self, Self> {
    self.parse_arg_on(arg, cfg!(windows))
  }

  /// [`parse_arg`](Self::parse_arg) as the reference parses `arg` on
  /// Windows if `windows`, and elsewhere if not.
  fn parse_arg_on(mut self, arg: &str, windows: bool) -> Result<Self, Self> {
    let (key, value) = match arg.split_once('=') {
      Some((key, value)) => (key, Some(value)),
      None => (arg, None),
    };
    let key = if windows { windows_key(key) } else { String::from(key) };
    let Some(name) = key.strip_prefix("--").or_else(|| key.strip_prefix('-')) else {
      return Err(self);
    };
    let (negated, name) = match name.strip_prefix("no") {
      Some(name) => (true, name),
      None => (false, name),
    };
    let Some(option) = ChainOption::from_name(&format!("-{name}")) else {
      return Err(self);
    };
    self.args.push(Occurrence {
      option,
      negated,
      value: value.map(String::from),
      arg: arg.into(),
    });
    Ok(self)
  }

  /// `-devnet=<name>`. The devnet is `devnet-<name>`, or `devnet` if `name`
  /// is empty.
  ///
  /// A caller passes one name. The node's startup refuses a repeated
  /// `-devnet` among checks of options outside the chain parameters, so
  /// the builder reads the last, as the chain parameters do.
  pub fn devnet_name(self, name: &str) -> Self {
    self.arg(ChainOption::Devnet, name)
  }

  /// `-fastprune`.
  pub fn fast_prune(self, enabled: bool) -> Self {
    self.arg(ChainOption::FastPrune, if enabled { "1" } else { "0" })
  }

  /// `-testactivationheight=<name>@<height>` for `deployment`.
  ///
  /// A deployment the option cannot move gives the reference's invalid
  /// name error.
  pub fn activation_height(self, deployment: BuriedDeployment, height: BlockHeight) -> Self {
    let name = deployment.test_activation_name().unwrap_or(deployment.name());
    self.arg(ChainOption::TestActivationHeight, format!("{name}@{}", height.to_u32()))
  }

  /// `-dip3params=<activation>:<enforcement>`.
  pub fn dip3(self, activation: BlockHeight, enforcement: BlockHeight) -> Self {
    let value = format!("{}:{}", activation.to_u32(), enforcement.to_u32());
    self.arg(ChainOption::Dip3Params, value)
  }

  /// `-budgetparams=<masternode>:<budget>:<superblock>`.
  pub fn budget(self, masternode: BlockHeight, budget: BlockHeight, superblock: BlockHeight) -> Self {
    let value = format!("{}:{}:{}", masternode.to_u32(), budget.to_u32(), superblock.to_u32());
    self.arg(ChainOption::BudgetParams, value)
  }

  /// `-powtargetspacing=<seconds>`.
  pub fn pow_target_spacing(self, seconds: i64) -> Self {
    self.arg(ChainOption::PowTargetSpacing, format!("{seconds}"))
  }

  /// The chain parameters with the options applied.
  ///
  /// # Errors
  ///
  /// The reference's refusal of an option, or one of the inputs this crate
  /// refuses where the reference accepts them or fails an assertion (see
  /// [`ParamsError`]).
  ///
  /// The steps follow the reference's startup. The arguments are parsed
  /// first (an option the release lacks or a forbidden negation is refused
  /// here, in argument order), then the chain parameters are built and the
  /// spork signers resolved. A height still negative and an LLMQ size
  /// override outside `u16` are refused last, once the reference's own
  /// checks have passed.
  pub fn build(&self) -> Result<ChainSetup, ParamsError> {
    for o in &self.args {
      if o.option == ChainOption::MinSporkKeys && self.release.min_spork_keys().is_none() {
        return Err(ParamsError::InvalidParameter(o.arg.clone()));
      }
      if o.negated && !o.option.negatable() {
        return Err(ParamsError::NegationForbidden(o.option));
      }
    }
    let mut setup = ChainSetup::new(self.network, self.release);
    let mut late = Late::default();
    match self.network {
      Network::Main | Network::Testnet3 => {}
      Network::Devnet => self.devnet(&mut setup, &mut late)?,
      Network::Regtest => self.regtest(&mut setup, &mut late)?,
    }
    setup.spork_signers = self.spork_signers(&setup)?;
    late.check()?;
    Ok(setup)
  }

  /// `-sporkaddr` and `-minsporkkeys`.
  fn spork_signers(&self, setup: &ChainSetup) -> Result<SporkSigners, ParamsError> {
    let hrp = setup.platform_hrp();
    let key = |a: &str| spork_key_id(a, setup.addr_params.pubkey_addr, hrp).ok_or(ParamsError::SporkAddress);
    if let Some(default) = self.release.min_spork_keys() {
      let addresses: Vec<&str> = if self.args.iter().any(|o| o.option == ChainOption::SporkAddr) {
        self.all(ChainOption::SporkAddr).collect()
      } else {
        vec![setup.spork_address]
      };
      let mut key_ids = BTreeSet::new();
      for address in addresses {
        key_ids.insert(key(address)?);
      }
      let min = self.last(ChainOption::MinSporkKeys).map_or(default, int_arg);
      let max = i32::try_from(key_ids.len()).unwrap_or(i32::MAX);
      if min <= max / 2 || min > max {
        return Err(ParamsError::MinSporkKeys);
      }
      return Ok(SporkSigners {
        key_ids: key_ids.into_iter().collect(),
        min_spork_keys: Some(min),
        warning: None,
      });
    }
    let address = self.last(ChainOption::SporkAddr).unwrap_or(setup.spork_address);
    let warning = (self.all(ChainOption::SporkAddr).count() > 1)
      .then(|| format!("More than one spork address is provided. Using {address}."));
    Ok(SporkSigners {
      key_ids: vec![key(address)?],
      min_spork_keys: None,
      warning,
    })
  }

  /// The last setting of `option`. A negation reads `0`.
  fn last(&self, option: ChainOption) -> Option<&str> {
    let o = self.args.iter().rev().find(|o| o.option == option)?;
    Some(o.setting().unwrap_or("0"))
  }

  /// The values of `option` after its last negation, in order.
  fn all(&self, option: ChainOption) -> impl Iterator<Item = &str> {
    let settings: Vec<Option<&str>> = self
      .args
      .iter()
      .filter(|o| o.option == option)
      .map(Occurrence::setting)
      .collect();
    let live = settings.iter().rposition(Option::is_none).map_or(0, |i| i + 1);
    settings.into_iter().skip(live).flatten()
  }

  /// The devnet options, in the reference's order.
  fn devnet(&self, setup: &mut ChainSetup, late: &mut Late) -> Result<(), ParamsError> {
    if let Some(name) = self.last(ChainOption::Devnet).filter(|n| !n.is_empty()) {
      setup.name_devnet(format!("devnet-{name}"))?;
    }
    let c = &mut setup.chain_mut().consensus;
    if let Some(v) = self.last(ChainOption::MinimumDifficultyBlocks) {
      c.minimum_difficulty_blocks = int_arg(v);
    }
    if let Some(v) = self.last(ChainOption::HighSubsidyBlocks) {
      c.high_subsidy_blocks = int_arg(v);
    }
    if let Some(v) = self.last(ChainOption::HighSubsidyFactor) {
      c.high_subsidy_factor = int_arg(v);
    }
    if let Some(t) = self.llmq_role(setup, ChainOption::LlmqChainLocks, Rotation::Forbidden)? {
      setup.chain_mut().consensus.llmq_type_chain_locks = t;
    }
    if let Some(t) = self.llmq_role(setup, ChainOption::LlmqInstantSendDip0024, Rotation::Required)? {
      setup.chain_mut().consensus.llmq_type_dip0024_instant_send = t;
    }
    if let Some(t) = self.llmq_role(setup, ChainOption::LlmqPlatform, Rotation::Any)? {
      setup.chain_mut().consensus.llmq_type_platform = t;
    }
    if let Some(t) = self.llmq_role(setup, ChainOption::LlmqMnhf, Rotation::Any)? {
      setup.chain_mut().consensus.llmq_type_mnhf = t;
    }
    self.llmq_size(
      setup,
      late,
      ChainOption::LlmqDevnetParams,
      "LLMQ_DEVNET",
      LlmqType::LlmqDevnet,
    )?;
    if let Some(v) = self.last(ChainOption::PowTargetSpacing) {
      let spacing = int64(v, ParamsError::PowTargetSpacingParse)?;
      if spacing < 1 {
        return Err(ParamsError::PowTargetSpacingValue(v.into()));
      }
      setup.chain_mut().consensus.pow_target_spacing = spacing;
    }
    Ok(())
  }

  /// The regtest options, in the reference's order.
  ///
  /// Heights the reference reads as an `i32` stay signed while the options
  /// are replayed, so a later occurrence can replace a negative one, and the
  /// height order is checked on the signed values. A height still negative
  /// in the final parameters is refused after every check the reference
  /// makes itself, so its errors come first.
  fn regtest(&self, setup: &mut ChainSetup, late: &mut Late) -> Result<(), ParamsError> {
    if self.last(ChainOption::FastPrune).is_some_and(interpret_bool) {
      setup.chain_mut().prune_after_height = 100;
    }
    self.activation_heights(setup)?;
    let mut min_heights: Vec<(DeploymentPos, i32)> = setup
      .deployments()
      .map(|(pos, d)| (pos, i32::try_from(d.min_activation_height.to_u32()).unwrap_or(i32::MAX)))
      .collect();
    self.version_bits(setup, &mut min_heights)?;
    let mut dip3 = None;
    if let Some(v) = self.last(ChainOption::Dip3Params) {
      let [activation, enforcement] = fields(v).ok_or(ParamsError::Dip3Malformed)?;
      let activation = int32(activation, ParamsError::Dip3Activation)?;
      let enforcement = int32(enforcement, ParamsError::Dip3Enforcement)?;
      dip3 = Some([activation, enforcement]);
    }
    let mut budget_starts = None;
    if let Some(v) = self.last(ChainOption::BudgetParams) {
      let [mn, budget, superblock] = fields(v).ok_or(ParamsError::BudgetMalformed)?;
      let mn = int32(mn, ParamsError::BudgetMasternode)?;
      let budget = int32(budget, ParamsError::BudgetBudget)?;
      let superblock = int32(superblock, ParamsError::BudgetSuperblock)?;
      budget_starts = Some([mn, budget, superblock]);
    }
    self.llmq_size(
      setup,
      late,
      ChainOption::LlmqTestParams,
      "LLMQ_TEST",
      LlmqType::LlmqTest,
    )?;
    self.llmq_size(
      setup,
      late,
      ChainOption::LlmqTestInstantSendParams,
      "LLMQ_TEST_INSTANTSEND",
      LlmqType::LlmqTestInstantsend,
    )?;
    self.llmq_size(
      setup,
      late,
      ChainOption::LlmqTestPlatformParams,
      "LLMQ_TEST_PLATFORM",
      LlmqType::LlmqTestPlatform,
    )?;
    if let Some(t) = self.llmq_role(setup, ChainOption::LlmqTestInstantSendDip0024, Rotation::Any)? {
      setup.chain_mut().consensus.llmq_type_dip0024_instant_send = t;
    }
    for (pos, h) in min_heights {
      if let Some(d) = setup.deployment_mut(pos) {
        late.set_height(&mut d.min_activation_height, ChainOption::VbParams, h);
      }
    }
    let c = &mut setup.chain_mut().consensus;
    let mut dip3_height = i64::from(c.dip0003_height.to_u32());
    if let Some([activation, enforcement]) = dip3 {
      late.set_height(&mut c.dip0003_height, ChainOption::Dip3Params, activation);
      late.set_height(&mut c.dip0003_enforcement.0, ChainOption::Dip3Params, enforcement);
      dip3_height = i64::from(activation);
    }
    if let Some([mn, budget, superblock]) = budget_starts {
      late.set_height(&mut c.masternode_payments_start_block, ChainOption::BudgetParams, mn);
      late.set_height(&mut c.budget_payments_start_block, ChainOption::BudgetParams, budget);
      late.set_height(&mut c.superblock_start.0, ChainOption::BudgetParams, superblock);
    }
    if i64::from(c.v20_height.to_u32()) < dip3_height {
      return Err(ParamsError::V20BelowDip3);
    }
    if c.mn_rr_height < c.v20_height {
      return Err(ParamsError::MnRrBelowV20);
    }
    Ok(())
  }

  /// `-testactivationheight`.
  fn activation_heights(&self, setup: &mut ChainSetup) -> Result<(), ParamsError> {
    for arg in self.all(ChainOption::TestActivationHeight) {
      let (name, value) = arg
        .split_once('@')
        .ok_or_else(|| ParamsError::ActivationHeightFormat(arg.into()))?;
      let h = parse_i32(value)
        .filter(|h| (0..i32::MAX).contains(h))
        .and_then(|h| u32::try_from(h).ok())
        .map(BlockHeight::from_u32)
        .ok_or_else(|| ParamsError::ActivationHeightValue(arg.into()))?;
      let deployment = BuriedDeployment::ALL
        .into_iter()
        .find(|d| d.test_activation_name() == Some(name))
        .ok_or_else(|| ParamsError::ActivationHeightName(arg.into()))?;
      let c = &mut setup.chain_mut().consensus;
      match deployment {
        BuriedDeployment::Bip147 => c.bip147_height = h,
        BuriedDeployment::HeightInCoinbase => c.bip34.0 = h,
        BuriedDeployment::DerSig => c.bip66_height = h,
        BuriedDeployment::Cltv => c.bip65_height = h,
        BuriedDeployment::Csv => c.csv_height = h,
        BuriedDeployment::Brr => c.brr_height = h,
        BuriedDeployment::Dip0001 => c.dip0001_height = h,
        BuriedDeployment::Dip0008 => c.dip0008_height = h,
        BuriedDeployment::Dip0024 => {
          c.dip0024_height = h;
          c.dip0024_quorums_height = h;
        }
        BuriedDeployment::V19 => c.v19_height = h,
        BuriedDeployment::V20 => c.v20_height = h,
        BuriedDeployment::MnRr => c.mn_rr_height = h,
        BuriedDeployment::Dip0003 | BuriedDeployment::Dip0020 | BuriedDeployment::Withdrawals => {}
      }
    }
    Ok(())
  }

  /// `-vbparams`.
  ///
  /// Minimum activation heights go to `min_heights`, one per deployment, as
  /// the reference's signed `i32`.
  fn version_bits(&self, setup: &mut ChainSetup, min_heights: &mut [(DeploymentPos, i32)]) -> Result<(), ParamsError> {
    for arg in self.all(ChainOption::VbParams) {
      let f: Vec<&str> = arg.split(':').collect();
      if !matches!(f.len(), 3 | 4 | 6 | 9) {
        return Err(ParamsError::VbParamsMalformed);
      }
      let field = |field| move |v| ParamsError::VbParamsField(field, v);
      let start = int64(f[1], field(VbField::StartTime))?;
      let timeout = int64(f[2], field(VbField::Timeout))?;
      let min_height = if f.len() >= 4 {
        int32(f[3], field(VbField::MinActivationHeight))?
      } else {
        0
      };
      let (window, threshold_start) = if f.len() >= 6 {
        (
          int64(f[4], field(VbField::WindowSize))?,
          int64(f[5], field(VbField::ThresholdStart))?,
        )
      } else {
        (-1, -1)
      };
      let (threshold_min, falloff, use_ehf) = if f.len() == 9 {
        (
          int64(f[6], field(VbField::ThresholdMin))?,
          int64(f[7], field(VbField::FalloffCoeff))?,
          int64(f[8], field(VbField::UseEhf))?,
        )
      } else {
        (-1, -1, -1)
      };
      let (pos, min) = min_heights
        .iter_mut()
        .find(|(pos, _)| pos.name() == f[0])
        .ok_or_else(|| ParamsError::VbParamsDeployment(f[0].into()))?;
      let Some(d) = setup.deployment_mut(*pos) else {
        return Err(ParamsError::VbParamsDeployment(f[0].into()));
      };
      // A field of -1 is left unchanged.
      d.start_time = start;
      d.timeout = timeout;
      *min = min_height;
      if window != -1 {
        d.window_size = window;
      }
      if threshold_start != -1 {
        d.threshold_start = threshold_start;
      }
      if threshold_min != -1 {
        d.threshold_min = threshold_min;
      }
      if falloff != -1 {
        d.falloff_coeff = falloff;
      }
      if use_ehf != -1 {
        d.use_ehf = use_ehf > 0;
      }
    }
    Ok(())
  }

  /// An LLMQ `<size>:<threshold>` override of `llmq_type`, named `quorum` in
  /// the reference's error text.
  ///
  /// Every chain that reads the option runs `llmq_type`. A size or threshold
  /// outside `u16`, which the reference's `i32` fields take, is left in
  /// `late` for [`build`](Self::build) to refuse once the reference's own
  /// checks have passed.
  fn llmq_size(
    &self,
    setup: &mut ChainSetup,
    late: &mut Late,
    option: ChainOption,
    quorum: &'static str,
    llmq_type: LlmqType,
  ) -> Result<(), ParamsError> {
    let Some(v) = self.last(option) else {
      return Ok(());
    };
    let [size, threshold] = fields(v).ok_or(ParamsError::LlmqParamsMalformed(quorum))?;
    let size = int32(size, |v| ParamsError::LlmqSize(quorum, v))?;
    let threshold = int32(threshold, |v| ParamsError::LlmqThreshold(quorum, v))?;
    if self.release.caps_llmq_size() && size > i32::from(MAX_LLMQ_SIZE) {
      return Err(ParamsError::LlmqSizeTooLarge(quorum, size));
    }
    let (Ok(size_u16), Ok(threshold_u16)) = (u16::try_from(size), u16::try_from(threshold)) else {
      late
        .out_of_range
        .get_or_insert(ParamsError::LlmqOutOfRange(quorum, size, threshold));
      return Ok(());
    };
    let c = &mut setup.chain_mut().consensus;
    if let Some(slot) = c
      .llmq_sizes
      .slot_mut(llmq_type)
      .filter(|_| c.llmqs.contains(&llmq_type))
    {
      *slot = Some((size_u16, threshold_u16));
    }
    Ok(())
  }

  /// The LLMQ type an LLMQ role option names, if it is set.
  ///
  /// The name is looked up over the types the chain runs only, as the
  /// reference looks it up.
  fn llmq_role(
    &self,
    setup: &ChainSetup,
    option: ChainOption,
    rotation: Rotation,
  ) -> Result<Option<LlmqType>, ParamsError> {
    let Some(name) = self.last(option) else {
      return Ok(None);
    };
    let mut found = None;
    let c = &setup.consensus;
    for (llmq_type, q) in c.llmqs.iter().filter_map(|&t| Some((t, c.llmq(t)?))) {
      if llmq_type.to_string() != name {
        continue;
      }
      if matches!(
        (rotation, q.use_rotation),
        (Rotation::Required, false) | (Rotation::Forbidden, true)
      ) {
        return Err(ParamsError::LlmqRotation(option));
      }
      found = Some(llmq_type);
    }
    found.map(Some).ok_or(ParamsError::LlmqTypeName(option))
  }
}

/// Refusals of this crate that wait until the reference's own checks have
/// passed, the first of each kind.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
struct Late {
  /// A height still negative in the final parameters.
  negative_height: Option<ParamsError>,
  /// An LLMQ size override outside `u16`.
  out_of_range: Option<ParamsError>,
}

impl Late {
  /// Writes the signed `value` of `option` to `height`, or keeps a negative
  /// one to refuse.
  fn set_height(&mut self, height: &mut BlockHeight, option: ChainOption, value: i32) {
    match u32::try_from(value) {
      Ok(value) => *height = BlockHeight::from_u32(value),
      Err(_) => {
        self
          .negative_height
          .get_or_insert(ParamsError::NegativeHeight(option, i64::from(value)));
      }
    }
  }

  /// The first refusal kept, a negative height before a size out of range.
  fn check(self) -> Result<(), ParamsError> {
    match self.negative_height.or(self.out_of_range) {
      Some(err) => Err(err),
      None => Ok(()),
    }
  }
}

/// `value` split at each `:`, when it has exactly `N` fields.
fn fields<const N: usize>(value: &str) -> Option<[&str; N]> {
  let parts: Vec<&str> = value.split(':').collect();
  parts.try_into().ok()
}

/// The strict `i32` parse of `v`, or the error `err` makes of `v`.
fn int32(v: &str, err: impl FnOnce(String) -> ParamsError) -> Result<i32, ParamsError> {
  parse_i32(v).ok_or_else(|| err(v.into()))
}

/// The strict `i64` parse of `v`, or the error `err` makes of `v`.
fn int64(v: &str, err: impl FnOnce(String) -> ParamsError) -> Result<i64, ParamsError> {
  parse_i64(v).ok_or_else(|| err(v.into()))
}

/// The option name `key` as the reference reads it on Windows, in ASCII
/// lowercase with a leading `/` read as `-`.
fn windows_key(key: &str) -> String {
  let key = key.to_ascii_lowercase();
  match key.strip_prefix('/') {
    Some(rest) => format!("-{rest}"),
    None => key,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  /// The setup after `args`, each read as the reference reads it on Windows
  /// if `windows`. `None` if one names no chain option.
  fn parsed(
    network: Network,
    release: Release,
    windows: bool,
    args: &[&str],
  ) -> Option<Result<ChainSetup, ParamsError>> {
    args
      .iter()
      .try_fold(ChainParamsBuilder::new(network, release), |b, arg| {
        b.parse_arg_on(arg, windows).ok()
      })
      .map(|b| b.build())
  }

  /// On Windows a chain option reads in any case and with a leading `/`,
  /// negations included, just as its lowercase spelling reads.
  #[rstest]
  fn windows_reads_names_in_any_case(#[values(Release::V23_1, Release::V24_0)] release: Release) {
    let lower = ["-dip3params=105:106", "-fastprune", "-nofastprune", "--fastprune"];
    let mixed = ["/DIP3PARAMS=105:106", "-FastPrune", "/NoFastPrune", "/-FASTPRUNE"];
    let want = parsed(Network::Regtest, release, false, &lower);
    let dip3 = want
      .as_ref()
      .and_then(|s| s.as_ref().ok())
      .map(|s| s.consensus.dip0003_height);
    assert_eq!(dip3, Some(BlockHeight::from_u32(105)));
    assert_eq!(parsed(Network::Regtest, release, true, &mixed), want);
    assert_eq!(parsed(Network::Regtest, release, true, &lower), want);
  }

  /// Outside Windows a name in another case or with a leading `/` is no
  /// chain option, so the builder comes back unchanged.
  #[rstest]
  #[case("/dip3params=105:106")]
  #[case("-DIP3PARAMS=105:106")]
  #[case("/NoFastPrune")]
  fn elsewhere_mixed_names_are_no_option(#[case] arg: &str) {
    let builder = ChainParamsBuilder::new(Network::Regtest, Release::V24_0);
    assert_eq!(builder.clone().parse_arg_on(arg, false), Err(builder));
  }

  /// On Windows a value keeps its case.
  #[rstest]
  fn windows_keeps_value_case() {
    let devnet = parsed(Network::Devnet, Release::V24_0, true, &["/DEVNET=MyNet"]);
    let name = devnet
      .as_ref()
      .and_then(|s| s.as_ref().ok())
      .and_then(ChainSetup::devnet_name);
    assert_eq!(name, Some("devnet-MyNet"));
  }

  /// On Windows an error text quotes the argument as given.
  #[rstest]
  fn windows_error_texts_keep_the_spelling() {
    let refused = parsed(Network::Regtest, Release::V24_0, true, &["/MINSPORKKEYS=2"]);
    assert_eq!(
      refused,
      Some(Err(ParamsError::InvalidParameter("/MINSPORKKEYS=2".into())))
    );
  }
}
