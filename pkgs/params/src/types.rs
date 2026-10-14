//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared type definitions for chain parameters.

pub(crate) use bitcoin_units::BlockHeight;
use dash_num::{Arith256, Hash256};
use dash_primitives::LlmqType;
use dash_script::AddrParams;

/// P2P network message start bytes (magic).
pub type MessageStart = [u8; 4];

/// Block height paired with block hash, mirroring C++
/// `std::pair<int, uint256>` from `MapCheckpoints`.
pub type Checkpoint = (BlockHeight, Hash256);

/// Transaction statistics for chain sync progress estimation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChainTxData {
  /// Unix timestamp of the last known block.
  pub timestamp: i64,
  /// Total number of transactions in the chain.
  pub tx_count: i64,
  /// Estimated transactions per second after that
  /// timestamp.
  pub tx_rate: f64,
}

/// Version bits deployment for a consensus rule change (BIP9).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Bip9Deployment {
  /// Bit position in the block version field.
  pub bit: i32,
  /// Earliest median-time-past for activation
  /// signalling.
  pub start_time: i64,
  /// Median-time-past after which the deployment
  /// fails.
  pub timeout: i64,
  /// Earliest block height at which the deployment
  /// can activate.
  pub min_activation_height: BlockHeight,
  /// Number of blocks in a signalling window.
  pub window_size: i64,
  /// Initial signalling threshold for the first
  /// window.
  pub threshold_start: i64,
  /// Minimum signalling threshold after decay.
  pub threshold_min: i64,
  /// Decay coefficient applied to the threshold
  /// each window.
  pub falloff_coeff: i64,
  /// Whether this deployment requires an
  /// extended-header-field activation.
  pub use_ehf: bool,
}

impl Bip9Deployment {
  pub const NO_TIMEOUT: i64 = i64::MAX;
  pub const ALWAYS_ACTIVE: i64 = -1;
  pub const NEVER_ACTIVE: i64 = -2;
}

/// Version bits deployments indexed by deployment position.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Bip9Deployments {
  /// Reserved deployment used only for testing.
  pub test_dummy: Bip9Deployment,
  /// Deployment parameters for the v24 upgrade.
  pub v24: Bip9Deployment,
}

/// Buried deployment positions with hardcoded activation heights.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
}

/// Complete chain parameters for a network.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChainParams {
  /// Consensus rules for this chain.
  pub consensus: ConsensusParams,
  /// Four-byte magic identifying network messages.
  pub message_start: MessageStart,
  /// Default P2P listen port.
  pub default_port: u16,
  /// Default Platform P2P port.
  pub default_platform_p2p_port: u16,
  /// Default Platform HTTP API port.
  pub default_platform_http_port: u16,
  /// Default JSON-RPC port.
  pub rpc_port: u16,
  /// Tor onion service target port.
  pub onion_service_target_port: u16,
  /// Height after which pruning may discard blocks.
  pub prune_after_height: u64,
  /// Estimated full blockchain size in gigabytes.
  pub assumed_blockchain_size_gb: u64,
  /// Estimated chain-state size in gigabytes.
  pub assumed_chain_state_size_gb: u64,
  /// DNS seed hostnames for peer discovery.
  pub dns_seeds: &'static [&'static str],
  /// Address encoding parameters.
  pub addr_params: AddrParams,
  /// Human-readable network identifier string.
  pub network_id: &'static str,
  /// Whether this is a test network.
  pub is_test_chain: bool,
  /// Whether non-standard transactions are
  /// rejected.
  pub require_standard: bool,
  /// Whether internal consistency checks run by
  /// default.
  pub default_consistency_checks: bool,
  /// Whether the chain allows mock time and state.
  pub is_mockable_chain: bool,
  /// Minimum participants for a CoinJoin session.
  pub pool_min_participants: i32,
  /// Maximum participants for a CoinJoin session.
  pub pool_max_participants: i32,
  /// Number of blocks in a credit-pool accounting
  /// period.
  pub credit_pool_period_blocks: i32,
  /// Hard-coded checkpoints for fast validation.
  pub checkpoints: &'static [Checkpoint],
  /// Transaction statistics for progress estimation.
  pub chain_tx_data: ChainTxData,
}
