//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Chain parameters against the reference vectors.

use dash_dev::Corpus;
use dash_num::Hash256;
use dash_params::{Bip9Deployment, Bip9Deployments, ChainParams, ChainTxData, Checkpoint, ConsensusParams, Network};
use dash_script::AddrParams;
use hex_conservative::DisplayHex;
use rstest::rstest;
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ChainVector {
  network_id: String,
  consensus: ConsensusVector,
  message_start: String,
  default_port: u16,
  default_platform_p2p_port: u16,
  default_platform_http_port: u16,
  rpc_port: u16,
  onion_service_target_port: u16,
  prune_after_height: u64,
  assumed_blockchain_size_gb: u64,
  assumed_chain_state_size_gb: u64,
  addr_params: AddrVector,
  is_test_chain: bool,
  default_consistency_checks: bool,
  is_mockable_chain: bool,
  pool_min_participants: i32,
  pool_max_participants: i32,
  credit_pool_period_blocks: i32,
  checkpoints: Vec<(u32, String)>,
  chain_tx_data: TxDataVector,
}

impl From<&ChainParams> for ChainVector {
  fn from(chain: &ChainParams) -> Self {
    let ChainParams {
      consensus,
      message_start,
      default_port,
      default_platform_p2p_port,
      default_platform_http_port,
      rpc_port,
      onion_service_target_port,
      prune_after_height,
      assumed_blockchain_size_gb,
      assumed_chain_state_size_gb,
      dns_seeds: _,
      addr_params,
      network_id,
      is_test_chain,
      require_standard: _,
      default_consistency_checks,
      is_mockable_chain,
      pool_min_participants,
      pool_max_participants,
      credit_pool_period_blocks,
      checkpoints,
      chain_tx_data,
    } = *chain;
    Self {
      network_id: network_id.into(),
      consensus: ConsensusVector::from(&consensus),
      message_start: message_start.to_lower_hex_string(),
      default_port,
      default_platform_p2p_port,
      default_platform_http_port,
      rpc_port,
      onion_service_target_port,
      prune_after_height,
      assumed_blockchain_size_gb,
      assumed_chain_state_size_gb,
      addr_params: AddrVector::from(&addr_params),
      is_test_chain,
      default_consistency_checks,
      is_mockable_chain,
      pool_min_participants,
      pool_max_participants,
      credit_pool_period_blocks,
      checkpoints: checkpoints.iter().copied().map(pair).collect(),
      chain_tx_data: TxDataVector::from(&chain_tx_data),
    }
  }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ConsensusVector {
  hash_genesis_block: String,
  subsidy_halving_interval: i32,
  masternode_payments_start_block: u32,
  masternode_payments_increase_block: u32,
  masternode_payments_increase_period: i32,
  instant_send_confirmations_required: i32,
  instant_send_keep_lock: i32,
  budget_payments_start_block: u32,
  budget_payments_cycle_blocks: i32,
  budget_payments_window_blocks: i32,
  superblock_start: (u32, String),
  superblock_cycle: i32,
  superblock_maturity_window: i32,
  governance_min_quorum: i32,
  governance_filter_elements: i32,
  masternode_minimum_confirmations: i32,
  bip34: (u32, String),
  bip65_height: u32,
  bip66_height: u32,
  bip147_height: u32,
  csv_height: u32,
  dip0001_height: u32,
  dip0003_height: u32,
  dip0003_enforcement: (u32, String),
  dip0008_height: u32,
  brr_height: u32,
  dip0020_height: u32,
  dip0024_height: u32,
  dip0024_quorums_height: u32,
  v19_height: u32,
  v20_height: u32,
  mn_rr_height: u32,
  withdrawals_height: u32,
  min_bip9_warning_height: u32,
  rule_change_activation_threshold: u32,
  miner_confirmation_window: u32,
  deployments: DeploymentsVector,
  pow_limit: String,
  pow_allow_min_difficulty_blocks: bool,
  pow_no_retargeting: bool,
  pow_target_spacing: i64,
  pow_target_timespan: i64,
  pow_kgw_height: u32,
  pow_dgw_height: u32,
  minimum_chain_work: String,
  default_assume_valid: String,
  llmq_type_chain_locks: String,
  llmq_type_dip0024_instant_send: String,
  llmq_type_platform: String,
  llmq_type_mnhf: String,
}

impl From<&ConsensusParams> for ConsensusVector {
  fn from(consensus: &ConsensusParams) -> Self {
    let ConsensusParams {
      hash_genesis_block,
      subsidy_halving_interval,
      masternode_payments_start_block,
      masternode_payments_increase_block,
      masternode_payments_increase_period,
      instant_send_confirmations_required,
      instant_send_keep_lock,
      budget_payments_start_block,
      budget_payments_cycle_blocks,
      budget_payments_window_blocks,
      superblock_start,
      superblock_cycle,
      superblock_maturity_window,
      governance_min_quorum,
      governance_filter_elements,
      masternode_minimum_confirmations,
      bip34,
      bip65_height,
      bip66_height,
      bip147_height,
      csv_height,
      dip0001_height,
      dip0003_height,
      dip0003_enforcement,
      dip0008_height,
      brr_height,
      dip0020_height,
      dip0024_height,
      dip0024_quorums_height,
      v19_height,
      v20_height,
      mn_rr_height,
      withdrawals_height,
      min_bip9_warning_height,
      rule_change_activation_threshold,
      miner_confirmation_window,
      deployments,
      pow_limit,
      pow_allow_min_difficulty_blocks,
      pow_no_retargeting,
      pow_target_spacing,
      pow_target_timespan,
      pow_kgw_height,
      pow_dgw_height,
      minimum_chain_work,
      default_assume_valid,
      llmq_type_chain_locks,
      llmq_type_dip0024_instant_send,
      llmq_type_platform,
      llmq_type_mnhf,
    } = *consensus;
    Self {
      hash_genesis_block: hash_genesis_block.to_string(),
      subsidy_halving_interval,
      masternode_payments_start_block: masternode_payments_start_block.to_u32(),
      masternode_payments_increase_block: masternode_payments_increase_block.to_u32(),
      masternode_payments_increase_period,
      instant_send_confirmations_required,
      instant_send_keep_lock,
      budget_payments_start_block: budget_payments_start_block.to_u32(),
      budget_payments_cycle_blocks,
      budget_payments_window_blocks,
      superblock_start: pair(superblock_start),
      superblock_cycle,
      superblock_maturity_window,
      governance_min_quorum,
      governance_filter_elements,
      masternode_minimum_confirmations,
      bip34: pair(bip34),
      bip65_height: bip65_height.to_u32(),
      bip66_height: bip66_height.to_u32(),
      bip147_height: bip147_height.to_u32(),
      csv_height: csv_height.to_u32(),
      dip0001_height: dip0001_height.to_u32(),
      dip0003_height: dip0003_height.to_u32(),
      dip0003_enforcement: pair(dip0003_enforcement),
      dip0008_height: dip0008_height.to_u32(),
      brr_height: brr_height.to_u32(),
      dip0020_height: dip0020_height.to_u32(),
      dip0024_height: dip0024_height.to_u32(),
      dip0024_quorums_height: dip0024_quorums_height.to_u32(),
      v19_height: v19_height.to_u32(),
      v20_height: v20_height.to_u32(),
      mn_rr_height: mn_rr_height.to_u32(),
      withdrawals_height: withdrawals_height.to_u32(),
      min_bip9_warning_height: min_bip9_warning_height.to_u32(),
      rule_change_activation_threshold,
      miner_confirmation_window,
      deployments: DeploymentsVector::from(&deployments),
      pow_limit: Hash256::from(pow_limit).to_string(),
      pow_allow_min_difficulty_blocks,
      pow_no_retargeting,
      pow_target_spacing,
      pow_target_timespan,
      pow_kgw_height: pow_kgw_height.to_u32(),
      pow_dgw_height: pow_dgw_height.to_u32(),
      minimum_chain_work: Hash256::from(minimum_chain_work).to_string(),
      default_assume_valid: default_assume_valid.to_string(),
      llmq_type_chain_locks: llmq_type_chain_locks.to_string(),
      llmq_type_dip0024_instant_send: llmq_type_dip0024_instant_send.to_string(),
      llmq_type_platform: llmq_type_platform.to_string(),
      llmq_type_mnhf: llmq_type_mnhf.to_string(),
    }
  }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct DeploymentsVector {
  test_dummy: DeploymentVector,
}

impl From<&Bip9Deployments> for DeploymentsVector {
  fn from(deployments: &Bip9Deployments) -> Self {
    let Bip9Deployments { test_dummy, v24: _ } = *deployments;
    Self {
      test_dummy: DeploymentVector::from(&test_dummy),
    }
  }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct DeploymentVector {
  bit: i32,
  start_time: i64,
  timeout: i64,
  min_activation_height: u32,
  window_size: i64,
  threshold_start: i64,
  threshold_min: i64,
  falloff_coeff: i64,
  use_ehf: bool,
}

impl From<&Bip9Deployment> for DeploymentVector {
  fn from(deployment: &Bip9Deployment) -> Self {
    let Bip9Deployment {
      bit,
      start_time,
      timeout,
      min_activation_height,
      window_size,
      threshold_start,
      threshold_min,
      falloff_coeff,
      use_ehf,
    } = *deployment;
    Self {
      bit,
      start_time,
      timeout,
      min_activation_height: min_activation_height.to_u32(),
      window_size,
      threshold_start,
      threshold_min,
      falloff_coeff,
      use_ehf,
    }
  }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct AddrVector {
  pubkey_addr: String,
  script_addr: String,
  secret_key: String,
  ext_pubkey: String,
  ext_secret: String,
  bip44_idx: u32,
}

impl From<&AddrParams> for AddrVector {
  fn from(addr: &AddrParams) -> Self {
    let AddrParams {
      pubkey_addr,
      script_addr,
      secret_key,
      ext_pubkey,
      ext_secret,
      bip44_idx,
    } = *addr;
    Self {
      pubkey_addr: format!("{pubkey_addr:02x}"),
      script_addr: format!("{script_addr:02x}"),
      secret_key: format!("{secret_key:02x}"),
      ext_pubkey: ext_pubkey.to_lower_hex_string(),
      ext_secret: ext_secret.to_lower_hex_string(),
      bip44_idx,
    }
  }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct TxDataVector {
  timestamp: i64,
  tx_count: i64,
  tx_rate: f64,
}

impl From<&ChainTxData> for TxDataVector {
  fn from(data: &ChainTxData) -> Self {
    let ChainTxData {
      timestamp,
      tx_count,
      tx_rate,
    } = *data;
    Self {
      timestamp,
      tx_count,
      tx_rate,
    }
  }
}

fn pair((height, hash): Checkpoint) -> (u32, String) {
  (height.to_u32(), hash.to_string())
}

const NETWORKS: [Network; 3] = [Network::Main, Network::Testnet3, Network::Regtest];

fn corpus() -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "chainparams")
}

#[rstest]
fn chains_match_vectors() {
  let vectors = corpus().vectors::<ChainVector>("chains");
  assert_eq!(vectors.len(), NETWORKS.len());
  for (network, vector) in NETWORKS.into_iter().zip(vectors) {
    assert_eq!(ChainVector::from(network.chain()), vector, "{network:?}");
  }
}
