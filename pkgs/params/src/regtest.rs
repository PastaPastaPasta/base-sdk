//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Regtest chain parameters.

use crate::prelude::*;
use crate::types::*;

use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use dash_num::{Arith256, Hash256};
use dash_primitives::{
  Block, BlockHash, BlockHeader, LlmqType, MerkleRoot, OutPoint, Transaction, TxHash, TxIn, TxOut, TxType,
};
use dash_script::AddrParams;
use dash_types::Numeric;
use hex_conservative::hex;

/// Returns the regtest genesis block.
pub fn genesis() -> Block {
  let coinbase = Transaction {
    version: 1,
    tx_type: TxType::Spend,
    inputs: vec![TxIn {
      prevout: OutPoint {
        hash: TxHash::default(),
        index: 0xFFFF_FFFF,
      },
      script_sig: ScriptSigBuf::from_bytes(
        hex!(concat!(
          "04ffff001d01044c5957697265642030392f4a616e2f323031342054686520",
          "4772616e64204578706572696d656e7420476f6573204c6976653a204f7665",
          "7273746f636b2e636f6d204973204e6f7720416363657074696e6720426974",
          "636f696e73"
        ))
        .to_vec(),
      ),
      sequence: 0xFFFF_FFFF,
    }],
    outputs: vec![TxOut {
      value: bitcoin_units::Amount::from_btc_u16(50),
      script_pubkey: ScriptPubKeyBuf::from_bytes(
        hex!(concat!(
          "41040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4",
          "d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070",
          "ac7b03a9ac"
        ))
        .to_vec(),
      ),
    }],
    lock_time: 0,
    extra_payload: Vec::new(),
  };

  let mut block = Block {
    header: BlockHeader {
      version: 1,
      prev_hash: BlockHash::default(),
      merkle_root: MerkleRoot::default(),
      time: 1_417_713_337,
      bits: 0x207f_ffff,
      nonce: 1_096_447,
    },
    transactions: vec![coinbase],
  };
  block.header.merkle_root = block.merkle().0;
  block
}

pub static PARAMS: ChainParams = ChainParams {
  consensus: ConsensusParams {
    hash_genesis_block: Hash256::from_bendian(hex!("000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e")),
    subsidy_halving_interval: 150,
    masternode_payments_start_block: BlockHeight::from_u32(240),
    masternode_payments_increase_block: BlockHeight::from_u32(350),
    masternode_payments_increase_period: 10,
    instant_send_confirmations_required: 2,
    instant_send_keep_lock: 6,
    budget_payments_start_block: BlockHeight::from_u32(1000),
    budget_payments_cycle_blocks: 50,
    budget_payments_window_blocks: 10,
    superblock_start: (BlockHeight::from_u32(1500), Hash256::ZERO),
    superblock_cycle: 20,
    superblock_maturity_window: 10,
    governance_min_quorum: 1,
    governance_filter_elements: 100,
    masternode_minimum_confirmations: 1,
    bip34: (BlockHeight::from_u32(1), Hash256::ZERO),
    bip65_height: BlockHeight::from_u32(1),
    bip66_height: BlockHeight::from_u32(1),
    bip147_height: BlockHeight::from_u32(0),
    csv_height: BlockHeight::from_u32(1),
    dip0001_height: BlockHeight::from_u32(1),
    dip0003_height: BlockHeight::from_u32(432),
    dip0003_enforcement: (BlockHeight::from_u32(500), Hash256::ZERO),
    dip0008_height: BlockHeight::from_u32(1),
    brr_height: BlockHeight::from_u32(1),
    dip0020_height: BlockHeight::from_u32(1),
    dip0024_height: BlockHeight::from_u32(1),
    dip0024_quorums_height: BlockHeight::from_u32(1),
    v19_height: BlockHeight::from_u32(1),
    v20_height: BlockHeight::from_u32(432),   // same as dip0003_height
    mn_rr_height: BlockHeight::from_u32(432), // same as v20_height
    withdrawals_height: BlockHeight::from_u32(600),
    min_bip9_warning_height: BlockHeight::from_u32(0),
    rule_change_activation_threshold: 108, // 75% of 144
    miner_confirmation_window: 144,
    deployments: Bip9Deployments {
      test_dummy: Bip9Deployment {
        bit: 28,
        start_time: 0,
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 0,
        threshold_start: 0,
        threshold_min: 0,
        falloff_coeff: 0,
        use_ehf: false,
      },
      v24: Bip9Deployment {
        bit: 12,
        start_time: 0,
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 250,
        threshold_start: 200, // 80% of 250
        threshold_min: 150,   // 60% of 250
        falloff_coeff: 5,
        use_ehf: true,
      },
    },
    // ~uint256(0) >> 1
    pow_limit: Arith256::from_bendian(hex!("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
    pow_allow_min_difficulty_blocks: true,
    pow_no_retargeting: true,
    pow_target_spacing: 150,     // 2.5 minutes
    pow_target_timespan: 86_400, // 1 day
    pow_kgw_height: BlockHeight::from_u32(15_200),
    pow_dgw_height: BlockHeight::from_u32(34_140),
    minimum_chain_work: Arith256::ZERO,
    default_assume_valid: Hash256::ZERO,
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
  dns_seeds: &[],
  addr_params: AddrParams {
    pubkey_addr: 140,                     // addresses start with 'y'
    script_addr: 19,                      // addresses start with '8' or '9'
    secret_key: 239,                      // keys start with '9' or 'c'
    ext_pubkey: [0x04, 0x35, 0x87, 0xCF], // tpub
    ext_secret: [0x04, 0x35, 0x83, 0x94], // tprv
    bip44_idx: 1,
  },
  network_id: "regtest",
  is_test_chain: true,
  require_standard: true,
  default_consistency_checks: true,
  is_mockable_chain: true,
  pool_min_participants: 2,
  pool_max_participants: 20,
  credit_pool_period_blocks: 100,
  checkpoints: &CHECKPOINTS,
  chain_tx_data: ChainTxData {
    timestamp: 0,
    tx_count: 0,
    tx_rate: 0.0,
  },
};

#[rustfmt::skip]
const CHECKPOINTS: [Checkpoint; 1] = [
  (BlockHeight::from_u32(0), Hash256::from_bendian(hex!("000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"))),
];
