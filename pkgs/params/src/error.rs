//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Errors building chain parameters from the reference implementation's
//! command-line options.

use crate::builder::ChainOption;
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// A version-bits field `-vbparams` failed to parse.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum VbField {
  /// `<start>`.
  StartTime,
  /// `<end>`.
  Timeout,
  /// `<min_activation_height>`.
  MinActivationHeight,
  /// `<window>`.
  WindowSize,
  /// `<threshold/thresholdstart>`.
  ThresholdStart,
  /// `<thresholdmin>`.
  ThresholdMin,
  /// `<falloffcoeff>`.
  FalloffCoeff,
  /// `<useehf>`.
  UseEhf,
}

impl VbField {
  /// The field's name in the reference implementation's error text.
  const fn text_name(self) -> &'static str {
    match self {
      Self::StartTime => "nStartTime",
      Self::Timeout => "nTimeout",
      Self::MinActivationHeight => "min_activation_height",
      Self::WindowSize => "nWindowSize",
      Self::ThresholdStart => "nThresholdStart",
      Self::ThresholdMin => "nThresholdMin",
      Self::FalloffCoeff => "nFalloffCoeff",
      Self::UseEhf => "nUseEHF",
    }
  }
}

/// Why chain parameters could not be built.
///
/// The variants before [`NegativeHeight`](Self::NegativeHeight) are the
/// reference implementation's own refusals. Their `Display` is its error
/// text, byte for byte, at both releases. The rest are inputs it accepts or
/// stops on with a failed assertion, which this crate refuses.
#[derive(Clone, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[non_exhaustive]
pub enum ParamsError {
  /// A `-testactivationheight` value without `@`.
  #[error("Invalid format ({0}) for -testactivationheight=name@height.")]
  ActivationHeightFormat(String),
  /// A `-testactivationheight` height outside `[0, i32::MAX)`.
  #[error("Invalid height value ({0}) for -testactivationheight=name@height.")]
  ActivationHeightValue(String),
  /// A `-testactivationheight` name the option does not know.
  #[error("Invalid name ({0}) for -testactivationheight=name@height.")]
  ActivationHeightName(String),
  /// A `-vbparams` value without 3, 4, 6 or 9 fields.
  #[error("{}", VB_MALFORMED)]
  VbParamsMalformed,
  /// A `-vbparams` field that is not an integer of its type.
  #[error("Invalid {field} ({1})", field = .0.text_name())]
  VbParamsField(VbField, String),
  /// A `-vbparams` deployment the release does not have.
  #[error("Invalid deployment ({0})")]
  VbParamsDeployment(String),
  /// A `-dip3params` value without 2 fields.
  #[error("DIP3 parameters malformed, expecting <activation>:<enforcement>")]
  Dip3Malformed,
  /// A `-dip3params` activation height that is not an `i32`.
  #[error("Invalid activation height ({0})")]
  Dip3Activation(String),
  /// A `-dip3params` enforcement height that is not an `i32`.
  #[error("Invalid enforcement height ({0})")]
  Dip3Enforcement(String),
  /// A `-budgetparams` value without 3 fields.
  #[error("Budget parameters malformed, expecting <masternode>:<budget>:<superblock>")]
  BudgetMalformed,
  /// A `-budgetparams` masternode start that is not an `i32`.
  #[error("Invalid masternode start height ({0})")]
  BudgetMasternode(String),
  /// A `-budgetparams` budget start that is not an `i32`.
  #[error("Invalid budget start block ({0})")]
  BudgetBudget(String),
  /// A `-budgetparams` superblock start that is not an `i32`.
  #[error("Invalid superblock start height ({0})")]
  BudgetSuperblock(String),
  /// An LLMQ size override without 2 fields, with the quorum's name in the
  /// error text.
  #[error("{0} parameters malformed, expecting <size>:<threshold>")]
  LlmqParamsMalformed(&'static str),
  /// An LLMQ size override whose size is not an `i32`.
  #[error("Invalid {0} size ({1})")]
  LlmqSize(&'static str, String),
  /// An LLMQ size override whose threshold is not an `i32`.
  #[error("Invalid {0} threshold ({1})")]
  LlmqThreshold(&'static str, String),
  /// An LLMQ size above [`MAX_LLMQ_SIZE`](crate::MAX_LLMQ_SIZE) (v24).
  #[error("Invalid {0} size ({1}), must not exceed the maximum supported quorum size ({max})", max = crate::MAX_LLMQ_SIZE)]
  LlmqSizeTooLarge(&'static str, i32),
  /// An LLMQ role option naming no quorum type the chain runs.
  #[error("Invalid LLMQ type specified for {}.", .0.name())]
  LlmqTypeName(ChainOption),
  /// An LLMQ role option naming a type whose rotation does not suit it.
  #[error("LLMQ type specified for {} must {}use rotation", .0.name(), rotation_negation(*.0))]
  LlmqRotation(ChainOption),
  /// A `-powtargetspacing` that is not an `i64`.
  #[error("Invalid parsing of powTargetSpacing ({0})")]
  PowTargetSpacingParse(String),
  /// A `-powtargetspacing` below 1.
  #[error("Invalid value of powTargetSpacing ({0})")]
  PowTargetSpacingValue(String),
  /// A negation of an option that is not
  /// [`negatable`](ChainOption::negatable), refused while the arguments
  /// are parsed.
  #[error("Negating of {} is meaningless and therefore forbidden", .0.name())]
  NegationForbidden(ChainOption),
  /// A height the reference reads as an `i32` without a range check is
  /// negative in the final parameters. That is a `-vbparams` minimum
  /// activation height, a `-dip3params` or a `-budgetparams` height.
  ///
  /// Heights here are unsigned, so this crate refuses what the reference
  /// accepts.
  #[error("negative height {1} in {option}", option = .0.name())]
  NegativeHeight(ChainOption, i64),
  /// Regtest's V20 height is below DIP0003's, where the reference fails an
  /// assertion.
  #[error("v20 height below dip0003 height")]
  V20BelowDip3,
  /// Regtest's MN_RR height is below V20's, where the reference fails an
  /// assertion.
  #[error("mn_rr height below v20 height")]
  MnRrBelowV20,
  /// No devnet genesis block exists for the name, where the reference fails
  /// an assertion.
  #[error("no devnet genesis block for {0}")]
  DevnetGenesis(String),
  /// An LLMQ size override whose size or threshold is outside `u16`, which
  /// the reference's `i32` fields hold and start with.
  ///
  /// It is reported only once the reference's own checks have passed.
  #[error("{0} size ({1}) or threshold ({2}) outside 0 to {max}", max = u16::MAX)]
  LlmqOutOfRange(&'static str, i32, i32),
}

/// The reference's text for a malformed `-vbparams`.
const VB_MALFORMED: &str = concat!(
  "Version bits parameters malformed, expecting ",
  "<deployment>:<start>:<end> or ",
  "<deployment>:<start>:<end>:<min_activation_height> or ",
  "<deployment>:<start>:<end>:<min_activation_height>:<window>:<threshold> or ",
  "<deployment>:<start>:<end>:<min_activation_height>:<window>:<thresholdstart>:",
  "<thresholdmin>:<falloffcoeff>:<useehf>"
);

/// `NOT ` where an LLMQ role option forbids rotation, which the reference's
/// rotation error text then says.
fn rotation_negation(option: ChainOption) -> &'static str {
  if option == ChainOption::LlmqChainLocks {
    "NOT "
  } else {
    ""
  }
}
