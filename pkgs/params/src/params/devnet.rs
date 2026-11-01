//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Devnet chain parameters, of the devnet named `devnet`.

use crate::{
  AddrParams, Bip9Deployment, Bip9Deployments, ChainParams, ChainTxData, Checkpoint, ConsensusParams, GenesisParams,
  LlmqSizes, LlmqType,
};

use bitcoin_units::{Amount, BlockHeight};
use dash_num::{Arith256, Hash256};
use dash_types::Numeric;
use hex_conservative::hex;

/// Hash of the genesis block, which is regtest's.
const GENESIS_HASH: Hash256 =
  Hash256::from_bendian(hex!("000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"));

/// Hash of the devnet genesis block (height 1) of the devnet named `devnet`.
const DEVNET_GENESIS_HASH: Hash256 =
  Hash256::from_bendian(hex!("65aeaff7fc5bae2bdf1604f5498108317a79ac56624cffe78e77adc206fe1c8b"));

pub static PARAMS: ChainParams = ChainParams {
  consensus: ConsensusParams {
    hash_genesis_block: GENESIS_HASH,
    hash_devnet_genesis_block: DEVNET_GENESIS_HASH,
    subsidy_halving_interval: 210_240,
    masternode_payments_start_block: BlockHeight::from_u32(4010),
    masternode_payments_increase_block: BlockHeight::from_u32(4030),
    masternode_payments_increase_period: 10,
    instant_send_confirmations_required: 2,
    instant_send_keep_lock: 6,
    budget_payments_start_block: BlockHeight::from_u32(4100),
    budget_payments_cycle_blocks: 50,
    budget_payments_window_blocks: 10,
    superblock_start: (BlockHeight::from_u32(4200), Hash256::ZERO),
    superblock_cycle: 24,
    superblock_maturity_window: 8,
    governance_min_quorum: 1,
    governance_filter_elements: 500,
    masternode_minimum_confirmations: 1,
    bip34: (BlockHeight::from_u32(1), Hash256::ZERO),
    bip65_height: BlockHeight::from_u32(1),
    bip66_height: BlockHeight::from_u32(1),
    bip147_height: BlockHeight::from_u32(1),
    csv_height: BlockHeight::from_u32(1),
    dip0001_height: BlockHeight::from_u32(2),
    dip0003_height: BlockHeight::from_u32(2),
    dip0003_enforcement: (BlockHeight::from_u32(2), Hash256::ZERO),
    dip0008_height: BlockHeight::from_u32(2),
    brr_height: BlockHeight::from_u32(2),
    dip0020_height: BlockHeight::from_u32(2),
    dip0024_height: BlockHeight::from_u32(2),
    dip0024_quorums_height: BlockHeight::from_u32(2),
    v19_height: BlockHeight::from_u32(2),
    v20_height: BlockHeight::from_u32(2),
    mn_rr_height: BlockHeight::from_u32(2),
    withdrawals_height: BlockHeight::from_u32(2),
    min_bip9_warning_height: BlockHeight::from_u32(2 + 2016), // withdrawals_height + miner_confirmation_window
    rule_change_activation_threshold: 1512,                   // 75% of 2016
    miner_confirmation_window: 2016,
    deployments: Bip9Deployments {
      test_dummy: Bip9Deployment {
        bit: 28,
        start_time: Bip9Deployment::NEVER_ACTIVE,
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 0,
        threshold_start: 0,
        threshold_min: 0,
        falloff_coeff: 0,
        use_ehf: false,
      },
      v24: Bip9Deployment {
        bit: 13,
        start_time: 1_751_328_000, // July 1, 2025
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 120,
        threshold_start: 96, // 80% of 120
        threshold_min: 72,   // 60% of 120
        falloff_coeff: 5,
        use_ehf: true,
      },
      evo_shares: Bip9Deployment {
        bit: 14,
        start_time: 1_751_328_000, // July 1, 2025
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 120,
        threshold_start: 96, // 80% of 120
        threshold_min: 72,   // 60% of 120
        falloff_coeff: 5,
        use_ehf: true,
      },
    },
    pow_limit: Arith256::from_bendian(hex!("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
    pow_allow_min_difficulty_blocks: true,
    pow_no_retargeting: false,
    pow_target_spacing: 150,     // 2.5 minutes
    pow_target_timespan: 86_400, // 1 day
    pow_kgw_height: BlockHeight::from_u32(4001),
    pow_dgw_height: BlockHeight::from_u32(4001),
    minimum_chain_work: Arith256::ZERO,
    default_assume_valid: Hash256::ZERO,
    minimum_difficulty_blocks: 0,
    high_subsidy_blocks: 0,
    high_subsidy_factor: 1,
    llmqs: &[
      LlmqType::Llmq50_60,
      LlmqType::Llmq60_75,
      LlmqType::Llmq400_60,
      LlmqType::Llmq400_85,
      LlmqType::Llmq100_67,
      LlmqType::LlmqDevnet,
      LlmqType::LlmqDevnetDip0024,
      LlmqType::LlmqDevnetPlatform,
    ],
    llmq_sizes: LlmqSizes::NONE,
    llmq_type_chain_locks: LlmqType::LlmqDevnet,
    llmq_type_dip0024_instant_send: LlmqType::LlmqDevnetDip0024,
    llmq_type_platform: LlmqType::LlmqDevnetPlatform,
    llmq_type_mnhf: LlmqType::LlmqDevnet,
  },
  genesis: GenesisParams {
    version: 1,
    time: 1_417_713_337,
    bits: 0x207f_ffff,
    nonce: 1_096_447,
    script_sig: GenesisParams::COINBASE_SCRIPT_SIG,
    script_pubkey: GenesisParams::COINBASE_SCRIPT_PUBKEY,
    reward: Amount::from_btc_u16(50),
  },
  message_start: [0xe2, 0xca, 0xff, 0xce],
  default_port: 19799,
  default_platform_p2p_port: 22100,
  default_platform_http_port: 22101,
  rpc_port: 19798,
  onion_service_target_port: 19796,
  prune_after_height: 3000,
  min_blocks_to_keep: 2304,
  assumed_blockchain_size_gb: 0,
  assumed_chain_state_size_gb: 0,
  dns_seeds: &[],
  addr_params: AddrParams {
    pubkey_addr: 140,                     // addresses start with 'y'
    script_addr: 19,                      // addresses start with '8' or '9'
    secret_key: 239,                      // keys start with '9' or 'c'
    ext_pubkey: [0x04, 0x35, 0x87, 0xCF], // tpub
    ext_secret: [0x04, 0x35, 0x83, 0x94], // tprv
    bip44_idx: 1,
    bech32_hrp: "tdash",
  },
  network_id: "devnet",
  is_test_chain: true,
  default_consistency_checks: false,
  is_mockable_chain: false,
  pool_min_participants: 2,
  pool_max_participants: 20,
  spork_address: "yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55",
  credit_pool_period_blocks: 576,
  checkpoints: &CHECKPOINTS,
  chain_tx_data: ChainTxData {
    timestamp: 1_417_713_338, // the devnet genesis block's time
    tx_count: 2,
    tx_rate: 0.01,
  },
};

// The devnet genesis block at height 1 depends on the devnet's name, so
// the chain parameters' all_checkpoints adds it from the consensus values.
const CHECKPOINTS: [Checkpoint; 1] = [(BlockHeight::from_u32(0), GENESIS_HASH)];
