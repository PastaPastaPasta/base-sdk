//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared type definitions for chain parameters.

use crate::llmq::LlmqParams;
use crate::network::{NetworkKind, Release};
use crate::prelude::*;

pub(crate) use bitcoin_units::BlockHeight;
use dash_num::{Arith256, Hash256};
use dash_primitives::{Block, LlmqType};
use dash_script::{AddrParams, PubKeyHash};

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

/// Position of a version-bits deployment, Core's `DeploymentPos`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeploymentPos {
  /// `testdummy`, used only for testing.
  TestDummy = 0,
  /// `v24`, the v24 upgrade.
  V24 = 1,
  /// `evo_shares`, EvoNode shared collateral (v24 release only).
  EvoShares = 2,
}

impl DeploymentPos {
  /// Index into [`ConsensusParams::deployments`].
  pub const fn index(self) -> usize {
    self as usize
  }

  /// Core's `VersionBitsDeploymentInfo` name, used by `-vbparams` and RPC.
  pub const fn name(self) -> &'static str {
    match self {
      Self::TestDummy => "testdummy",
      Self::V24 => "v24",
      Self::EvoShares => "evo_shares",
    }
  }

  /// Core's `VersionBitsDeploymentInfo` `gbt_force`.
  pub const fn gbt_force(self) -> bool {
    true
  }
}

/// Version bits deployment for a consensus rule change (BIP9 with Dash's
/// dynamic threshold and EHF fields).
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

impl BuriedDeployment {
  /// Every buried deployment, in Core's `BuriedDeployment` order.
  pub const ALL: [Self; 15] = [
    Self::HeightInCoinbase,
    Self::Cltv,
    Self::DerSig,
    Self::Bip147,
    Self::Csv,
    Self::Dip0001,
    Self::Dip0003,
    Self::Dip0008,
    Self::Dip0020,
    Self::Dip0024,
    Self::Brr,
    Self::V19,
    Self::V20,
    Self::MnRr,
    Self::Withdrawals,
  ];

  /// Core's `DeploymentName`, as `getdeploymentinfo` reports it.
  pub const fn name(self) -> &'static str {
    match self {
      Self::HeightInCoinbase => "bip34",
      Self::Cltv => "bip65",
      Self::DerSig => "bip66",
      Self::Bip147 => "bip147",
      Self::Csv => "csv",
      Self::Dip0001 => "dip0001",
      Self::Dip0003 => "dip0003",
      Self::Dip0008 => "dip0008",
      Self::Dip0020 => "dip0020",
      Self::Dip0024 => "dip0024",
      Self::Brr => "realloc",
      Self::V19 => "v19",
      Self::V20 => "v20",
      Self::MnRr => "mn_rr",
      Self::Withdrawals => "withdrawals",
    }
  }

  /// The name regtest's `-testactivationheight` accepts, if it moves this
  /// deployment.
  pub const fn test_activation_name(self) -> Option<&'static str> {
    match self {
      Self::Bip147 => Some("bip147"),
      Self::HeightInCoinbase => Some("bip34"),
      Self::DerSig => Some("dersig"),
      Self::Cltv => Some("cltv"),
      Self::Csv => Some("csv"),
      Self::Brr => Some("brr"),
      Self::Dip0001 => Some("dip0001"),
      Self::Dip0008 => Some("dip0008"),
      Self::Dip0024 => Some("dip0024"),
      Self::V19 => Some("v19"),
      Self::V20 => Some("v20"),
      Self::MnRr => Some("mn_rr"),
      Self::Dip0003 | Self::Dip0020 | Self::Withdrawals => None,
    }
  }
}

/// Parameters that influence chain consensus.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct ConsensusParams {
  /// Hash of the genesis block.
  pub hash_genesis_block: Hash256,
  /// Hash of the devnet genesis block (height 1), zero off devnets.
  pub hash_devnet_genesis_block: Hash256,
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
  /// Height and hash at which superblocks begin. A non-zero hash is Core's
  /// hard-coded `bad-sb-start` pin.
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
  /// DIP0003 enforcement checkpoint. A non-zero hash is Core's hard-coded
  /// `bad-dip3-enf-block` pin.
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
  /// Version-bits deployments, indexed by [`DeploymentPos::index`], one per
  /// [`Release::deployments`] entry.
  pub deployments: Vec<Bip9Deployment>,
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
  /// Blocks mined at minimum difficulty at the start of a devnet. Core's
  /// `int`, unchecked, so it may be negative.
  pub minimum_difficulty_blocks: i32,
  /// Blocks with a raised subsidy at the start of a devnet. Core's `int`,
  /// unchecked, so it may be negative.
  pub high_subsidy_blocks: i32,
  /// Subsidy multiplier for those blocks. Core's `int`, unchecked, so it may
  /// be zero or negative.
  pub high_subsidy_factor: i32,
  /// Configured LLMQ types, in Core's order.
  pub llmqs: Vec<LlmqParams>,
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

  /// The version-bits deployment at `pos`, if this release has it.
  pub fn deployment(&self, pos: DeploymentPos) -> Option<&Bip9Deployment> {
    self.deployments.get(pos.index())
  }

  /// The configured parameters of `llmq_type` (Core's `GetLLMQ`).
  pub fn llmq(&self, llmq_type: LlmqType) -> Option<&LlmqParams> {
    self.llmqs.iter().find(|q| q.llmq_type == llmq_type)
  }

  /// Core's `DifficultyAdjustmentInterval`, or `None` where it is 0.
  ///
  /// A devnet spacing above the timespan makes it 0, and Core's
  /// `% DifficultyAdjustmentInterval()` then divides by zero.
  pub const fn difficulty_adjustment_interval(&self) -> Option<i64> {
    match self.pow_target_timespan.checked_div(self.pow_target_spacing) {
      Some(0) | None => None,
      interval => interval,
    }
  }
}

/// The spork signers a chain trusts by default.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct SporkParams {
  /// Base58 addresses of the spork signers (v23 `vSporkAddresses`, v24's
  /// single `strSporkAddress`).
  pub addresses: &'static [&'static str],
  /// Signatures needed for a spork (v23 `nMinSporkKeys`); v24 has a single
  /// signer and no threshold.
  pub min_spork_keys: Option<i32>,
}

/// The spork signers a node trusts once Core's startup has applied
/// `-sporkaddr` and `-minsporkkeys` to the chain's [`SporkParams`], as
/// `CSporkManager` holds them. Verifying sporks is not this crate's job.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct SporkSigners {
  /// Signer key IDs; v23 holds a set (ascending, distinct), v24 one key.
  pub key_ids: Vec<PubKeyHash>,
  /// Signatures a spork needs (v23 `nMinSporkKeys`); `None` at v24.
  pub min_spork_keys: Option<i32>,
  /// Core's startup warning when v24 is given several `-sporkaddr` values.
  pub warning: Option<String>,
}

/// An assumeutxo snapshot Core trusts (`AssumeutxoData`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AssumeutxoData {
  /// Height of the snapshot base block.
  pub height: BlockHeight,
  /// Expected hash of the serialized UTXO set.
  pub hash_serialized: Hash256,
  /// Expected hash of the evo section (v24 release only).
  pub evo_hash: Option<Hash256>,
  /// Transactions up to and including the base block.
  pub chain_tx: u32,
}

/// Network values Core hard-codes outside `CChainParams`.
///
/// The `bad-sb-start` and `bad-dip3-enf-block` pins are chain parameters
/// already, [`ConsensusParams::superblock_start`] and
/// [`ConsensusParams::dip0003_enforcement`].
///
/// Deliberately absent: Core literals that decide a rule's path by network
/// rather than pin a height of one, which stay at their rule sites. These
/// are the mainnet `nPrevHeight <= 4500` subsidy branch, the devnet subsidy
/// path and the `LLMQ_50_60` testnet and devnet branch of
/// `IsQuorumTypeEnabled`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct HardCodedPins {
  /// Last height whose header nBits only needs to be within 50% of DGW's
  /// (`bad-diffbits`); Core applies it on mainnet only.
  ///
  /// Core: validation.cpp ContextualCheckBlockHeader, `nHeight <= 68589`
  /// (v23.1.8 :4110, v24.0.0-rc.3 :4476).
  pub pre_dgw_tolerance_until: Option<BlockHeight>,
  /// `LLMQ_25_67` is enabled once the previous block is at this height.
  /// Core applies it on any chain that configures the type; only testnet
  /// does.
  ///
  /// Core: validation.cpp IsQuorumTypeEnabled,
  /// `TESTNET_LLMQ_25_67_ACTIVATION_HEIGHT` (v23.1.8 :6078, v24.0.0-rc.3
  /// :6670).
  pub llmq_25_67_activation_height: BlockHeight,
}

/// Complete chain parameters for a network, as Core's `CChainParams` plus
/// its `CBaseChainParams`.
///
/// Built by [`ChainParamsBuilder`](crate::ChainParamsBuilder) only; fields
/// stay public to read and to adjust in tests.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ChainParams {
  /// Kind of chain.
  pub network: NetworkKind,
  /// Core release whose parameters these are.
  pub release: Release,
  /// Core's `GetDevNetName()` on a devnet (`devnet` or `devnet-<name>`),
  /// `None` elsewhere.
  pub devnet_name: Option<String>,
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
  /// BIP155-serialized fixed seed addresses (`chainparamsseeds.h`).
  pub fixed_seeds: &'static [u8],
  /// Address encoding parameters.
  pub addr_params: AddrParams,
  /// DIP-18 Platform address bech32m HRP (v24 release only).
  pub platform_hrp: Option<&'static str>,
  /// Whether this is a test network.
  pub is_test_chain: bool,
  /// Whether non-standard transactions are rejected by default (v23 release
  /// only).
  pub require_standard: Option<bool>,
  /// Whether internal consistency checks run by
  /// default.
  pub default_consistency_checks: bool,
  /// Whether the chain allows mock time and state.
  pub is_mockable_chain: bool,
  /// Whether a masternode's external IP must be routable.
  pub require_routable_external_ip: bool,
  /// Whether several masternode addresses may share a network group.
  pub allow_multiple_addresses_from_group: bool,
  /// Seconds before an LLMQ connection is retried.
  pub llmq_connection_retry_timeout: i32,
  /// Minimum participants for a CoinJoin session.
  pub pool_min_participants: i32,
  /// Maximum participants for a CoinJoin session.
  pub pool_max_participants: i32,
  /// Seconds until a fulfilled request expires.
  pub fulfilled_request_expire_time: i32,
  /// Number of blocks in a credit-pool accounting period.
  pub credit_pool_period_blocks: i32,
  /// Default spork signers, as the chain parameters hold them.
  pub spork: SporkParams,
  /// Spork signers after the spork options.
  pub spork_signers: SporkSigners,
  /// Hard-coded checkpoints for fast validation.
  pub checkpoints: Vec<Checkpoint>,
  /// Trusted assumeutxo snapshots.
  pub assumeutxo: &'static [AssumeutxoData],
  /// Transaction statistics for progress estimation.
  pub chain_tx_data: ChainTxData,
  /// Genesis block.
  pub genesis: Block,
  /// Devnet genesis block (height 1), on devnets.
  pub devnet_genesis: Option<Block>,
  /// Values Core hard-codes outside its chain parameters.
  pub pins: HardCodedPins,
}

impl ChainParams {
  /// Core's `NetworkIDString()`.
  pub const fn network_id(&self) -> &'static str {
    self.network.network_id()
  }

  /// Core's `CBaseChainParams::DataDir()`: the data directory suffix.
  pub fn data_dir(&self) -> &str {
    match self.network {
      NetworkKind::Mainnet => "",
      NetworkKind::Testnet => "testnet3",
      NetworkKind::Devnet => self.devnet_name.as_deref().unwrap_or("devnet"),
      NetworkKind::Regtest => "regtest",
    }
  }

  /// Core's `MineBlocksOnDemand()`.
  pub const fn mine_blocks_on_demand(&self) -> bool {
    self.consensus.pow_no_retargeting
  }

  /// Core's `ExtCoinType()`: the BIP44 coin type.
  pub const fn ext_coin_type(&self) -> u32 {
    self.addr_params.bip44_idx
  }
}

/// Core's `vecPeriods`: the masternode share of the block value, in permille,
/// for each block reward reallocation period of three superblock cycles, in
/// the classic reward era. The first period starts with the first superblock
/// cycle after [`ConsensusParams::brr_height`]; the last share then holds.
///
/// The same at both releases and on every network. Core: `GetMasternodePayment`
/// (v23.1.8 validation.cpp:1606, v24.0.0-rc.3 masternode/payments.cpp:103).
pub const BRR_PERIODS_PERMILLE: [u16; 19] = [
  513, 526, 533, 540, 546, 552, 557, 562, 567, 572, 577, 582, 585, 588, 591, 594, 597, 599, 600,
];
