//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Devnet chain parameters (Core's `CDevNetParams`, before its overrides).

use crate::data::{
  deployments, llmqs, regtest_genesis, v23_only, v24_only, REGTEST_GENESIS_HASH, TEST_ADDR_PARAMS, TEST_PINS,
};
use crate::genesis::find_devnet_genesis;
use crate::network::{NetworkKind, Release};
use crate::prelude::*;
use crate::types::*;

use dash_num::{Arith256, Hash256};
use dash_primitives::LlmqType;
use dash_types::{Hashable, Numeric};
use hex_conservative::hex;

/// Devnet parameters of `release` for Core's devnet name `name` (`devnet`
/// or `devnet-<-devnet value>`), before the devnet options apply.
///
/// `None` if no devnet genesis nonce exists, where Core asserts.
pub(crate) fn params(release: Release, name: String) -> Option<ChainParams> {
  let genesis = regtest_genesis();
  let devnet_genesis = find_devnet_genesis(&genesis, &name)?;
  let devnet_hash = Hash256::from(devnet_genesis.header.hash());
  let devnet_time = i64::from(devnet_genesis.header.time);
  Some(ChainParams {
    network: NetworkKind::Devnet,
    release,
    devnet_name: Some(name),
    consensus: ConsensusParams {
      hash_genesis_block: REGTEST_GENESIS_HASH,
      hash_devnet_genesis_block: devnet_hash,
      subsidy_halving_interval: 210_240,
      masternode_payments_start_block: BlockHeight::from_u32(4010),
      masternode_payments_increase_block: BlockHeight::from_u32(4030),
      masternode_payments_increase_period: 10,
      instant_send_confirmations_required: 2,
      instant_send_keep_lock: 6,
      budget_payments_start_block: BlockHeight::from_u32(4100),
      budget_payments_cycle_blocks: 50,
      budget_payments_window_blocks: 10,
      superblock_start: (BlockHeight::from_u32(4200), Hash256::default()),
      superblock_cycle: 24,
      superblock_maturity_window: 8,
      governance_min_quorum: 1,
      governance_filter_elements: 500,
      masternode_minimum_confirmations: 1,
      bip34: (BlockHeight::from_u32(1), Hash256::default()),
      bip65_height: BlockHeight::from_u32(1),
      bip66_height: BlockHeight::from_u32(1),
      bip147_height: BlockHeight::from_u32(1),
      csv_height: BlockHeight::from_u32(1),
      dip0001_height: BlockHeight::from_u32(2),
      dip0003_height: BlockHeight::from_u32(2),
      dip0003_enforcement: (BlockHeight::from_u32(2), Hash256::default()),
      dip0008_height: BlockHeight::from_u32(2),
      brr_height: BlockHeight::from_u32(2),
      dip0020_height: BlockHeight::from_u32(2),
      dip0024_height: BlockHeight::from_u32(2),
      dip0024_quorums_height: BlockHeight::from_u32(2),
      v19_height: BlockHeight::from_u32(2),
      v20_height: BlockHeight::from_u32(2),
      mn_rr_height: BlockHeight::from_u32(2),
      withdrawals_height: BlockHeight::from_u32(2),
      min_bip9_warning_height: BlockHeight::from_u32(2 + 2016),
      rule_change_activation_threshold: 1512,
      miner_confirmation_window: 2016,
      deployments: deployments(release, Bip9Deployment::NEVER_ACTIVE, 1_751_328_000, [120, 96, 72]),
      pow_limit: Arith256::from_bendian(hex!("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
      pow_allow_min_difficulty_blocks: true,
      pow_no_retargeting: false,
      pow_target_spacing: 150,
      pow_target_timespan: 86_400,
      pow_kgw_height: BlockHeight::from_u32(4001),
      pow_dgw_height: BlockHeight::from_u32(4001),
      minimum_chain_work: Arith256::ZERO,
      default_assume_valid: Hash256::default(),
      minimum_difficulty_blocks: 0,
      high_subsidy_blocks: 0,
      high_subsidy_factor: 1,
      llmqs: llmqs(&[
        LlmqType::Llmq50_60,
        LlmqType::Llmq60_75,
        LlmqType::Llmq400_60,
        LlmqType::Llmq400_85,
        LlmqType::Llmq100_67,
        LlmqType::LlmqDevnet,
        LlmqType::LlmqDevnetDip0024,
        LlmqType::LlmqDevnetPlatform,
      ]),
      llmq_type_chain_locks: LlmqType::LlmqDevnet,
      llmq_type_dip0024_instant_send: LlmqType::LlmqDevnetDip0024,
      llmq_type_platform: LlmqType::LlmqDevnetPlatform,
      llmq_type_mnhf: LlmqType::LlmqDevnet,
    },
    message_start: [0xe2, 0xca, 0xff, 0xce],
    default_port: 19799,
    default_platform_p2p_port: 22100,
    default_platform_http_port: 22101,
    rpc_port: 19798,
    onion_service_target_port: 19796,
    prune_after_height: 1000,
    assumed_blockchain_size_gb: 0,
    assumed_chain_state_size_gb: 0,
    dns_seeds: &[],
    fixed_seeds: &[],
    addr_params: TEST_ADDR_PARAMS,
    platform_hrp: v24_only(release, "tdash"),
    is_test_chain: true,
    require_standard: v23_only(release, false),
    default_consistency_checks: false,
    is_mockable_chain: false,
    require_routable_external_ip: true,
    allow_multiple_addresses_from_group: true,
    llmq_connection_retry_timeout: 60,
    pool_min_participants: 2,
    pool_max_participants: 20,
    fulfilled_request_expire_time: 5 * 60,
    credit_pool_period_blocks: 576,
    spork: SporkParams {
      addresses: &["yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55"],
      min_spork_keys: v23_only(release, 1),
    },
    checkpoints: vec![
      (BlockHeight::from_u32(0), REGTEST_GENESIS_HASH),
      (BlockHeight::from_u32(1), devnet_hash),
    ],
    assumeutxo: &[],
    chain_tx_data: ChainTxData {
      timestamp: devnet_time,
      tx_count: 2,
      tx_rate: 0.01,
    },
    genesis,
    devnet_genesis: Some(devnet_genesis),
    pins: TEST_PINS,
  })
}
