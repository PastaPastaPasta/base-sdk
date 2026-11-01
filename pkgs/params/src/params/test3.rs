//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Testnet (v3) chain parameters.

use crate::{
  AddrParams, Bip9Deployment, Bip9Deployments, ChainParams, ChainTxData, Checkpoint, ConsensusParams, GenesisParams,
  LlmqSizes, LlmqType,
};

use bitcoin_units::{Amount, BlockHeight};
use dash_num::{Arith256, Hash256};
use dash_types::Numeric;
use hex_conservative::hex;

pub static PARAMS: ChainParams = ChainParams {
  consensus: ConsensusParams {
    hash_genesis_block: Hash256::from_bendian(hex!("00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c")),
    hash_devnet_genesis_block: Hash256::ZERO,
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
    bip34: (
      BlockHeight::from_u32(76),
      Hash256::from_bendian(hex!("000008ebb1db2598e897d17275285767717c6acfeac4c73def49fbea1ddcbcb6")),
    ),
    bip65_height: BlockHeight::from_u32(2431),
    bip66_height: BlockHeight::from_u32(2075),
    bip147_height: BlockHeight::from_u32(4300),
    csv_height: BlockHeight::from_u32(8064),
    dip0001_height: BlockHeight::from_u32(5500),
    dip0003_height: BlockHeight::from_u32(7000),
    dip0003_enforcement: (
      BlockHeight::from_u32(7300),
      Hash256::from_bendian(hex!("00000055ebc0e974ba3a3fb785c5ad4365a39637d4df168169ee80d313612f8f")),
    ),
    dip0008_height: BlockHeight::from_u32(78_800),
    brr_height: BlockHeight::from_u32(387_500),
    dip0020_height: BlockHeight::from_u32(414_100),
    dip0024_height: BlockHeight::from_u32(769_700),
    dip0024_quorums_height: BlockHeight::from_u32(770_730),
    v19_height: BlockHeight::from_u32(850_100),
    v20_height: BlockHeight::from_u32(905_100),
    mn_rr_height: BlockHeight::from_u32(1_066_900),
    withdrawals_height: BlockHeight::from_u32(1_148_500),
    min_bip9_warning_height: BlockHeight::from_u32(1_148_500 + 2016),
    rule_change_activation_threshold: 1512, // 75% for testchains
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
        start_time: 1_790_208_000, // 24 September 2026, midnight UTC
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 100,
        threshold_start: 80, // 80% of 100
        threshold_min: 60,   // 60% of 100
        falloff_coeff: 5,
        use_ehf: true,
      },
      evo_shares: Bip9Deployment {
        bit: 14,
        start_time: 1_790_208_000, // 24 September 2026, midnight UTC
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 100,
        threshold_start: 80, // 80% of 100
        threshold_min: 60,   // 60% of 100
        falloff_coeff: 5,
        use_ehf: true,
      },
    },
    pow_limit: Arith256::from_bendian(hex!("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
    pow_allow_min_difficulty_blocks: true,
    pow_no_retargeting: false,
    pow_target_spacing: 150,     // 2.5 minutes
    pow_target_timespan: 86_400, // 1 day
    pow_kgw_height: BlockHeight::from_u32(4002),
    pow_dgw_height: BlockHeight::from_u32(4002),
    minimum_chain_work: Arith256::from_bendian(hex!(
      "00000000000000000000000000000000000000000000000003ed573a939487fc"
    )),
    default_assume_valid: Hash256::from_bendian(hex!(
      "000000116cd3c11d44c88cbc0a26804bd277a5d790f684ec3a8aaa820690318c"
    )),
    minimum_difficulty_blocks: 0,
    high_subsidy_blocks: 0,
    high_subsidy_factor: 1,
    llmqs: &[
      LlmqType::Llmq50_60,
      LlmqType::Llmq60_75,
      LlmqType::Llmq400_60,
      LlmqType::Llmq400_85,
      LlmqType::Llmq100_67,
      LlmqType::Llmq25_67,
    ],
    llmq_sizes: LlmqSizes::NONE,
    llmq_type_chain_locks: LlmqType::Llmq50_60,
    llmq_type_dip0024_instant_send: LlmqType::Llmq60_75,
    llmq_type_platform: LlmqType::Llmq25_67,
    llmq_type_mnhf: LlmqType::Llmq50_60,
  },
  genesis: GenesisParams {
    version: 1,
    time: 1_390_666_206,
    bits: 0x1e0f_fff0,
    nonce: 3_861_367_235,
    script_sig: GenesisParams::COINBASE_SCRIPT_SIG,
    script_pubkey: GenesisParams::COINBASE_SCRIPT_PUBKEY,
    reward: Amount::from_btc_u16(50),
  },
  message_start: [0xce, 0xe2, 0xca, 0xff],
  default_port: 19999,
  default_platform_p2p_port: 22000,
  default_platform_http_port: 22001,
  rpc_port: 19998,
  onion_service_target_port: 19996,
  prune_after_height: 3000,
  min_blocks_to_keep: 2304,
  assumed_blockchain_size_gb: 10,
  assumed_chain_state_size_gb: 1,
  dns_seeds: &["testnet-seed.dashdot.io."],
  addr_params: AddrParams {
    pubkey_addr: 140,                     // addresses start with 'y'
    script_addr: 19,                      // addresses start with '8' or '9'
    secret_key: 239,                      // keys start with '9' or 'c'
    ext_pubkey: [0x04, 0x35, 0x87, 0xCF], // tpub
    ext_secret: [0x04, 0x35, 0x83, 0x94], // tprv
    bip44_idx: 1,
    bech32_hrp: "tdash",
  },
  network_id: "test",
  is_test_chain: true,
  default_consistency_checks: false,
  is_mockable_chain: false,
  pool_min_participants: 2,
  pool_max_participants: 20,
  spork_address: "yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55",
  credit_pool_period_blocks: 576,
  checkpoints: &CHECKPOINTS,
  chain_tx_data: ChainTxData {
    timestamp: 1_788_899_589,
    tx_count: 8_494_561,
    tx_rate: 0.0139463532250889,
  },
};

#[rustfmt::skip]
const CHECKPOINTS: [Checkpoint; 20] = [
  (BlockHeight::from_u32(     255), Hash256::from_bendian(hex!("0000080b600e06f4c07880673f027210f9314575f5f875fafe51971e268b886a"))),
  (BlockHeight::from_u32(     261), Hash256::from_bendian(hex!("00000c26026d0815a7e2ce4fa270775f61403c040647ff2c3091f99e894a4618"))),
  (BlockHeight::from_u32(   1_999), Hash256::from_bendian(hex!("00000052e538d27fa53693efe6fb6892a0c1d26c0235f599171c48a3cce553b1"))),
  (BlockHeight::from_u32(   2_999), Hash256::from_bendian(hex!("0000024bc3f4f4cb30d29827c13d921ad77d2c6072e586c7f60d83c2722cdcc5"))),
  (BlockHeight::from_u32(  96_090), Hash256::from_bendian(hex!("00000000033df4b94d17ab43e999caaf6c4735095cc77703685da81254d09bba"))),
  (BlockHeight::from_u32( 200_000), Hash256::from_bendian(hex!("000000001015eb5ef86a8fe2b3074d947bc972c5befe32b28dd5ce915dc0d029"))),
  (BlockHeight::from_u32( 395_750), Hash256::from_bendian(hex!("000008b78b6aef3fd05ab78db8b76c02163e885305545144420cb08704dce538"))),
  (BlockHeight::from_u32( 470_000), Hash256::from_bendian(hex!("0000009303aeadf8cf3812f5c869691dbd4cb118ad20e9bf553be434bafe6a52"))),
  (BlockHeight::from_u32( 794_950), Hash256::from_bendian(hex!("000001860e4c7248a9c5cc3bc7106041750560dc5cd9b3a2641b49494bcff5f2"))),
  (BlockHeight::from_u32( 808_000), Hash256::from_bendian(hex!("00000104cb60a2b5e00a8a4259582756e5bf0dca201c0993c63f0e54971ea91a"))),
  (BlockHeight::from_u32( 840_000), Hash256::from_bendian(hex!("000000cd7c3084499912ae893125c13e8c3c656abb6e511dcec6619c3d65a510"))),
  (BlockHeight::from_u32( 851_000), Hash256::from_bendian(hex!("0000014d3b875540ff75517b7fbb1714e25d50ce92f65d7086cfce357928bb02"))),
  (BlockHeight::from_u32( 905_100), Hash256::from_bendian(hex!("0000020c5e0f86f385cbf8e90210de9a9fd63633f01433bf47a6b3227a2851fd"))),
  (BlockHeight::from_u32( 960_000), Hash256::from_bendian(hex!("0000000386cf5061ea16404c66deb83eb67892fa4f79b9e58e5eaab097ec2bd6"))),
  (BlockHeight::from_u32(1_069_875), Hash256::from_bendian(hex!("00000034bfeb926662ba547c0b8dd4ba8cbb6e0c581f4e7d1bddce8f9ca3a608"))),
  (BlockHeight::from_u32(1_143_608), Hash256::from_bendian(hex!("000000eef20eb0062abd4e799967e98bdebb165dd1c567ab4118c1c86c6e948f"))),
  (BlockHeight::from_u32(1_189_000), Hash256::from_bendian(hex!("000001690314036dfbbecbdf382b230ead8e9c584241290a51f9f05a87a9cf7e"))),
  (BlockHeight::from_u32(1_295_700), Hash256::from_bendian(hex!("00000107d42829a38e31c1a38c660d621e1ca376a880df1520e85e38af175d3a"))),
  (BlockHeight::from_u32(1_380_000), Hash256::from_bendian(hex!("000000a98084beaf77ed26a905a7d59979009e23367a55b5d634962d7d65a1f9"))),
  (BlockHeight::from_u32(1_550_000), Hash256::from_bendian(hex!("000000116cd3c11d44c88cbc0a26804bd277a5d790f684ec3a8aaa820690318c"))),
];
