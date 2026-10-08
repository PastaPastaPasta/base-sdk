//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Regtest chain parameters (Core's `CRegTestParams`, before its overrides).

use crate::data::{
  deployments, llmqs, regtest_genesis, v23_only, v24_only, REGTEST_GENESIS_HASH, TEST_ADDR_PARAMS, TEST_PINS,
};
use crate::network::{NetworkKind, Release};
use crate::prelude::*;
use crate::types::*;

use dash_num::{Arith256, Hash256};
use dash_primitives::LlmqType;
use dash_types::Numeric;
use hex_conservative::hex;

/// Regtest parameters of `release`, before the regtest options apply.
pub(crate) fn params(release: Release) -> ChainParams {
  ChainParams {
    network: NetworkKind::Regtest,
    release,
    devnet_name: None,
    consensus: ConsensusParams {
      hash_genesis_block: REGTEST_GENESIS_HASH,
      hash_devnet_genesis_block: Hash256::default(),
      subsidy_halving_interval: 150,
      masternode_payments_start_block: BlockHeight::from_u32(240),
      masternode_payments_increase_block: BlockHeight::from_u32(350),
      masternode_payments_increase_period: 10,
      instant_send_confirmations_required: 2,
      instant_send_keep_lock: 6,
      budget_payments_start_block: BlockHeight::from_u32(1000),
      budget_payments_cycle_blocks: 50,
      budget_payments_window_blocks: 10,
      superblock_start: (BlockHeight::from_u32(1500), Hash256::default()),
      superblock_cycle: 20,
      superblock_maturity_window: 10,
      governance_min_quorum: 1,
      governance_filter_elements: 100,
      masternode_minimum_confirmations: 1,
      bip34: (BlockHeight::from_u32(1), Hash256::default()),
      bip65_height: BlockHeight::from_u32(1),
      bip66_height: BlockHeight::from_u32(1),
      bip147_height: BlockHeight::from_u32(0),
      csv_height: BlockHeight::from_u32(1),
      dip0001_height: BlockHeight::from_u32(1),
      dip0003_height: BlockHeight::from_u32(432),
      dip0003_enforcement: (BlockHeight::from_u32(500), Hash256::default()),
      dip0008_height: BlockHeight::from_u32(1),
      brr_height: BlockHeight::from_u32(1),
      dip0020_height: BlockHeight::from_u32(1),
      dip0024_height: BlockHeight::from_u32(1),
      dip0024_quorums_height: BlockHeight::from_u32(1),
      v19_height: BlockHeight::from_u32(1),
      // Core sets V20 to DIP0003's height and MN_RR to V20's before the
      // options move any of them.
      v20_height: BlockHeight::from_u32(432),
      mn_rr_height: BlockHeight::from_u32(432),
      withdrawals_height: BlockHeight::from_u32(600),
      min_bip9_warning_height: BlockHeight::from_u32(0),
      rule_change_activation_threshold: 108,
      miner_confirmation_window: 144,
      deployments: deployments(release, 0, 0, [250, 200, 150]),
      pow_limit: Arith256::from_bendian(hex!("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
      pow_allow_min_difficulty_blocks: true,
      pow_no_retargeting: true,
      pow_target_spacing: 150,
      pow_target_timespan: 86_400,
      pow_kgw_height: BlockHeight::from_u32(15_200),
      pow_dgw_height: BlockHeight::from_u32(34_140),
      minimum_chain_work: Arith256::ZERO,
      default_assume_valid: Hash256::default(),
      minimum_difficulty_blocks: 0,
      high_subsidy_blocks: 0,
      high_subsidy_factor: 1,
      llmqs: llmqs(&[
        LlmqType::LlmqTest,
        LlmqType::LlmqTestInstantsend,
        LlmqType::LlmqTestV17,
        LlmqType::LlmqTestDip0024,
        LlmqType::LlmqTestPlatform,
      ]),
      llmq_type_chain_locks: LlmqType::LlmqTest,
      llmq_type_dip0024_instant_send: LlmqType::LlmqTestDip0024,
      llmq_type_platform: LlmqType::LlmqTestPlatform,
      llmq_type_mnhf: LlmqType::LlmqTest,
    },
    message_start: [0xfc, 0xc1, 0xb7, 0xdc],
    default_port: 19899,
    default_platform_p2p_port: 22200,
    default_platform_http_port: 22201,
    rpc_port: 19898,
    onion_service_target_port: 19896,
    prune_after_height: 1000,
    assumed_blockchain_size_gb: 0,
    assumed_chain_state_size_gb: 0,
    dns_seeds: &["dummySeed.invalid."],
    fixed_seeds: &[],
    addr_params: TEST_ADDR_PARAMS,
    platform_hrp: v24_only(release, "tdash"),
    is_test_chain: true,
    require_standard: v23_only(release, true),
    default_consistency_checks: true,
    is_mockable_chain: true,
    require_routable_external_ip: false,
    allow_multiple_addresses_from_group: true,
    llmq_connection_retry_timeout: 1,
    pool_min_participants: 2,
    pool_max_participants: 20,
    fulfilled_request_expire_time: 5 * 60,
    credit_pool_period_blocks: 100,
    spork: SporkParams {
      addresses: &["yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW"],
      min_spork_keys: v23_only(release, 1),
    },
    checkpoints: vec![(BlockHeight::from_u32(0), REGTEST_GENESIS_HASH)],
    assumeutxo: match release {
      Release::V23_1 => &ASSUMEUTXO_V23,
      Release::V24_0 => &ASSUMEUTXO_V24,
    },
    chain_tx_data: ChainTxData {
      timestamp: 0,
      tx_count: 0,
      tx_rate: 0.0,
    },
    genesis: regtest_genesis(),
    devnet_genesis: None,
    pins: TEST_PINS,
  }
}

/// Regtest snapshot at `height` with UTXO-set hash `hash` and evo-section
/// hash `evo_hash`.
const fn assumeutxo(height: u32, hash: [u8; 32], evo_hash: Option<Hash256>) -> AssumeutxoData {
  AssumeutxoData {
    height: BlockHeight::from_u32(height),
    hash_serialized: Hash256::from_bendian(hash),
    evo_hash,
    chain_tx: height,
  }
}

const SNAPSHOT_110: [u8; 32] = hex!("9b2a277a3e3b979f1a539d57e949495d7f8247312dbc32bce6619128c192b44b");
const SNAPSHOT_200: [u8; 32] = hex!("8a5bdd92252fc6b24663244bbe958c947bb036dc1f94ccd15439f48d8d1cb4e3");
const ZERO: Option<Hash256> = Some(Hash256::ZERO);

static ASSUMEUTXO_V23: [AssumeutxoData; 2] = [assumeutxo(110, SNAPSHOT_110, None), assumeutxo(200, SNAPSHOT_200, None)];
static ASSUMEUTXO_V24: [AssumeutxoData; 2] = [assumeutxo(110, SNAPSHOT_110, ZERO), assumeutxo(200, SNAPSHOT_200, ZERO)];
