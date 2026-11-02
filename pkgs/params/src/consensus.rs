//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Consensus parameters of a network.

use crate::{Bip9Deployments, LlmqParams, LlmqType};

use bitcoin_units::BlockHeight;
use dash_num::{Arith256, Hash256};
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// Block height paired with its block hash.
pub type Checkpoint = (BlockHeight, Hash256);

/// The masternode share of the block value, in permille, for each block reward
/// reallocation period of three superblock cycles, until
/// [`ConsensusParams::v20_height`].
///
/// The first period starts with the first superblock cycle after
/// [`ConsensusParams::brr_height`], and the last share then holds. The shares
/// are the same on every network.
pub const BRR_PERIODS_PERMILLE: [u16; 19] = [
  513, 526, 533, 540, 546, 552, 557, 562, 567, 572, 577, 582, 585, 588, 591, 594, 597, 599, 600,
];

/// Buried deployment positions with hardcoded activation heights.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum BuriedDeployment {
  /// BIP34 (height in coinbase).
  HeightInCoinbase,
  /// BIP66 (strict DER signatures).
  DerSig,
  /// BIP65 (CHECKLOCKTIMEVERIFY).
  Cltv,
  /// BIP147 (NULLDUMMY).
  Bip147,
  /// BIP68, BIP112, BIP113 (sequence locks).
  Csv,
  /// DIP0001 (2 MB block size increase).
  Dip0001,
  /// DIP0003 (deterministic masternode lists).
  Dip0003,
  /// DIP0008 (ChainLocks).
  Dip0008,
  /// DIP0020 (Dash opcode additions).
  Dip0020,
  /// DIP0024 (LLMQ rotation).
  Dip0024,
  /// Block reward reallocation.
  Brr,
  /// v19 hard fork.
  V19,
  /// v20 hard fork.
  V20,
  /// Masternode reward location reallocation.
  MnRr,
  /// Credit withdrawal transactions.
  Withdrawals,
}

/// Parameters that influence chain consensus.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct ConsensusParams {
  /// Hash of the genesis block.
  pub hash_genesis_block: Hash256,
  /// Number of blocks between subsidy halvings.
  pub subsidy_halving_interval: i32,
  /// Block height at which masternode payments
  /// begin.
  pub masternode_payments_start_block: BlockHeight,
  /// Block height at which masternode payment
  /// amount first increases.
  pub masternode_payments_increase_block: BlockHeight,
  /// Interval between masternode payment amount
  /// increases.
  pub masternode_payments_increase_period: i32,
  /// Number of confirmations required for
  /// InstantSend locks.
  pub instant_send_confirmations_required: i32,
  /// Number of blocks an InstantSend lock remains
  /// valid.
  pub instant_send_keep_lock: i32,
  /// Block height at which budget payments begin.
  pub budget_payments_start_block: BlockHeight,
  /// Number of blocks in a budget payment cycle.
  pub budget_payments_cycle_blocks: i32,
  /// Proposal voting window in blocks.
  pub budget_payments_window_blocks: i32,
  /// Height and hash at which superblocks begin.
  pub superblock_start: Checkpoint,
  /// Number of blocks between superblocks.
  pub superblock_cycle: i32,
  /// Maturity window for superblock proposals.
  pub superblock_maturity_window: i32,
  /// Minimum quorum for governance object
  /// acceptance.
  pub governance_min_quorum: i32,
  /// Maximum governance filter elements for bloom
  /// filters.
  pub governance_filter_elements: i32,
  /// Confirmations a masternode collateral
  /// transaction must have.
  pub masternode_minimum_confirmations: i32,
  /// BIP34 activation checkpoint.
  pub bip34: Checkpoint,
  /// BIP65 (CLTV) activation height.
  pub bip65_height: BlockHeight,
  /// BIP66 (strict DER) activation height.
  pub bip66_height: BlockHeight,
  /// BIP147 (NULLDUMMY) activation height.
  pub bip147_height: BlockHeight,
  /// BIP68/112/113 (CSV) activation height.
  pub csv_height: BlockHeight,
  /// DIP0001 activation height.
  pub dip0001_height: BlockHeight,
  /// DIP0003 activation height.
  pub dip0003_height: BlockHeight,
  /// DIP0003 enforcement checkpoint.
  pub dip0003_enforcement: Checkpoint,
  /// DIP0008 (ChainLocks) activation height.
  pub dip0008_height: BlockHeight,
  /// Block reward reallocation activation height.
  pub brr_height: BlockHeight,
  /// DIP0020 activation height.
  pub dip0020_height: BlockHeight,
  /// DIP0024 activation height.
  pub dip0024_height: BlockHeight,
  /// Height at which DIP0024 quorums begin.
  pub dip0024_quorums_height: BlockHeight,
  /// v19 activation height.
  pub v19_height: BlockHeight,
  /// v20 activation height.
  pub v20_height: BlockHeight,
  /// Masternode reward reallocation activation
  /// height.
  pub mn_rr_height: BlockHeight,
  /// Credit withdrawal activation height.
  pub withdrawals_height: BlockHeight,
  /// Minimum height before BIP9 warning triggers.
  pub min_bip9_warning_height: BlockHeight,
  /// Threshold of blocks in a window that must
  /// signal for a rule change to lock in.
  pub rule_change_activation_threshold: u32,
  /// Size of the BIP9 signalling window in blocks.
  pub miner_confirmation_window: u32,
  /// BIP9 version-bits deployments.
  pub deployments: Bip9Deployments,
  /// Maximum proof-of-work target (lowest
  /// difficulty).
  pub pow_limit: Arith256,
  /// Whether blocks may use the minimum difficulty
  /// rule.
  pub pow_allow_min_difficulty_blocks: bool,
  /// Whether difficulty retargeting is disabled.
  pub pow_no_retargeting: bool,
  /// Target spacing between blocks in seconds.
  pub pow_target_spacing: i64,
  /// Timespan over which difficulty is retargeted.
  pub pow_target_timespan: i64,
  /// Height at which KGW difficulty adjustment
  /// activates.
  pub pow_kgw_height: BlockHeight,
  /// Height at which DGW difficulty adjustment
  /// activates.
  pub pow_dgw_height: BlockHeight,
  /// Minimum total chain work for a valid chain.
  pub minimum_chain_work: Arith256,
  /// Block hash assumed valid for fast initial
  /// sync.
  pub default_assume_valid: Hash256,
  /// LLMQ types the chain runs, in the reference implementation's order.
  pub llmqs: &'static [LlmqType],
  /// LLMQ type used for ChainLocks.
  pub llmq_type_chain_locks: LlmqType,
  /// LLMQ type used for DIP0024 InstantSend.
  pub llmq_type_dip0024_instant_send: LlmqType,
  /// LLMQ type used by Platform.
  pub llmq_type_platform: LlmqType,
  /// LLMQ type used for masternode hard-fork
  /// signalling.
  pub llmq_type_mnhf: LlmqType,
}

impl ConsensusParams {
  /// Returns the activation height for a buried deployment.
  pub const fn deployment_height(&self, dep: BuriedDeployment) -> BlockHeight {
    match dep {
      BuriedDeployment::HeightInCoinbase => self.bip34.0,
      BuriedDeployment::DerSig => self.bip66_height,
      BuriedDeployment::Cltv => self.bip65_height,
      BuriedDeployment::Bip147 => self.bip147_height,
      BuriedDeployment::Csv => self.csv_height,
      BuriedDeployment::Dip0001 => self.dip0001_height,
      BuriedDeployment::Dip0003 => self.dip0003_height,
      BuriedDeployment::Dip0008 => self.dip0008_height,
      BuriedDeployment::Dip0020 => self.dip0020_height,
      BuriedDeployment::Dip0024 => self.dip0024_height,
      BuriedDeployment::Brr => self.brr_height,
      BuriedDeployment::V19 => self.v19_height,
      BuriedDeployment::V20 => self.v20_height,
      BuriedDeployment::MnRr => self.mn_rr_height,
      BuriedDeployment::Withdrawals => self.withdrawals_height,
    }
  }

  /// Returns the parameters of an LLMQ type the chain runs, or `None` if the
  /// chain does not run it.
  pub fn llmq(&self, llmq_type: LlmqType) -> Option<LlmqParams> {
    llmq_type.params().filter(|_| self.llmqs.contains(&llmq_type))
  }
}
