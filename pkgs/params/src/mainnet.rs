//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Mainnet chain parameters.

use crate::prelude::*;
use crate::types::*;

use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use dash_num::{Arith256, Hash256};
use dash_primitives::{
  Block, BlockHash, BlockHeader, LlmqType, MerkleRoot, OutPoint, Transaction, TxHash, TxIn, TxOut, TxType,
};
use dash_script::AddrParams;
use hex_conservative::hex;

/// Returns the mainnet genesis block.
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
      time: 1_390_095_618,
      bits: 0x1e0f_fff0,
      nonce: 28_917_698,
    },
    transactions: vec![coinbase],
  };
  block.header.merkle_root = block.merkle().0;
  block
}

pub static PARAMS: ChainParams = ChainParams {
  consensus: ConsensusParams {
    hash_genesis_block: Hash256::from_bendian(hex!("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6")),
    subsidy_halving_interval: 210_240,
    masternode_payments_start_block: BlockHeight::from_u32(100_000),
    masternode_payments_increase_block: BlockHeight::from_u32(158_000),
    masternode_payments_increase_period: 576 * 30, // 17280
    instant_send_confirmations_required: 6,
    instant_send_keep_lock: 24,
    budget_payments_start_block: BlockHeight::from_u32(328_008),
    budget_payments_cycle_blocks: 16_616,
    budget_payments_window_blocks: 100,
    superblock_start: (
      BlockHeight::from_u32(614_820),
      Hash256::from_bendian(hex!("0000000000020cb27c7ef164d21003d5d20cdca2f54dd9a9ca6d45f4d47f8aa3")),
    ),
    superblock_cycle: 16_616,
    superblock_maturity_window: 1_662,
    governance_min_quorum: 10,
    governance_filter_elements: 20_000,
    masternode_minimum_confirmations: 15,
    bip34: (
      BlockHeight::from_u32(951),
      Hash256::from_bendian(hex!("000001f35e70f7c5705f64c6c5cc3dea9449e74d5b5c7cf74dad1bcca14a8012")),
    ),
    bip65_height: BlockHeight::from_u32(619_382),
    bip66_height: BlockHeight::from_u32(245_817),
    bip147_height: BlockHeight::from_u32(939_456),
    csv_height: BlockHeight::from_u32(622_944),
    dip0001_height: BlockHeight::from_u32(782_208),
    dip0003_height: BlockHeight::from_u32(1_028_160),
    dip0003_enforcement: (
      BlockHeight::from_u32(1_047_200),
      Hash256::from_bendian(hex!("000000000000002d1734087b4c5afc3133e4e1c3e1a89218f62bcd9bb3d17f81")),
    ),
    dip0008_height: BlockHeight::from_u32(1_088_640),
    brr_height: BlockHeight::from_u32(1_374_912),
    dip0020_height: BlockHeight::from_u32(1_516_032),
    dip0024_height: BlockHeight::from_u32(1_737_792),
    dip0024_quorums_height: BlockHeight::from_u32(1_738_698),
    v19_height: BlockHeight::from_u32(1_899_072),
    v20_height: BlockHeight::from_u32(1_987_776),
    mn_rr_height: BlockHeight::from_u32(2_128_896),
    withdrawals_height: BlockHeight::from_u32(2_201_472),
    min_bip9_warning_height: BlockHeight::from_u32(2_201_472 + 2016),
    rule_change_activation_threshold: 1815, // 90% of 2016
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
        bit: 12,
        start_time: Bip9Deployment::NEVER_ACTIVE,
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 4032,
        threshold_start: 3226, // 80% of 4032
        threshold_min: 2420,   // 60% of 4032
        falloff_coeff: 5,
        use_ehf: true,
      },
    },
    // ~uint256(0) >> 20
    pow_limit: Arith256::from_bendian(hex!("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
    pow_allow_min_difficulty_blocks: false,
    pow_no_retargeting: false,
    pow_target_spacing: 150,     // 2.5 minutes
    pow_target_timespan: 86_400, // 1 day
    pow_kgw_height: BlockHeight::from_u32(15_200),
    pow_dgw_height: BlockHeight::from_u32(34_140),
    minimum_chain_work: Arith256::from_bendian(hex!(
      "00000000000000000000000000000000000000000000b567e2d53a06de194061"
    )),
    default_assume_valid: Hash256::from_bendian(hex!(
      "00000000000000018fb7d55a2d7ab5f3d1369cf0d7eef25db727bf8c9ca7d4b2"
    )),
    llmq_type_chain_locks: LlmqType::Llmq400_60,
    llmq_type_dip0024_instant_send: LlmqType::Llmq60_75,
    llmq_type_platform: LlmqType::Llmq100_67,
    llmq_type_mnhf: LlmqType::Llmq400_85,
  },
  message_start: [0xbf, 0x0c, 0x6b, 0xbd],
  default_port: 9999,
  default_platform_p2p_port: 26656,
  default_platform_http_port: 443,
  rpc_port: 9998,
  onion_service_target_port: 9996,
  prune_after_height: 100_000,
  assumed_blockchain_size_gb: 57,
  assumed_chain_state_size_gb: 1,
  dns_seeds: &["dnsseed.dash.org."],
  addr_params: AddrParams {
    pubkey_addr: 76,                      // addresses start with 'X'
    script_addr: 16,                      // addresses start with '7'
    secret_key: 204,                      // keys start with '7' or 'X'
    ext_pubkey: [0x04, 0x88, 0xB2, 0x1E], // xpub
    ext_secret: [0x04, 0x88, 0xAD, 0xE4], // xprv
    bip44_idx: 5,
  },
  network_id: "main",
  is_test_chain: false,
  require_standard: true,
  default_consistency_checks: false,
  is_mockable_chain: false,
  pool_min_participants: 3,
  pool_max_participants: 20,
  credit_pool_period_blocks: 576,
  checkpoints: &CHECKPOINTS,
  chain_tx_data: ChainTxData {
    timestamp: 1_770_962_602,
    tx_count: 64_859_329,
    tx_rate: 0.9523581589072819,
  },
};

#[rustfmt::skip]
const CHECKPOINTS: [Checkpoint; 37] = [
  (BlockHeight::from_u32(   1_500), Hash256::from_bendian(hex!("000000aaf0300f59f49bc3e970bad15c11f961fe2347accffff19d96ec9778e3"))),
  (BlockHeight::from_u32(   4_991), Hash256::from_bendian(hex!("000000003b01809551952460744d5dbb8fcbd6cbae3c220267bf7fa43f837367"))),
  (BlockHeight::from_u32(   9_918), Hash256::from_bendian(hex!("00000000213e229f332c0ffbe34defdaa9e74de87f2d8d1f01af8d121c3c170b"))),
  (BlockHeight::from_u32(  16_912), Hash256::from_bendian(hex!("00000000075c0d10371d55a60634da70f197548dbbfa4123e12abfcbc5738af9"))),
  (BlockHeight::from_u32(  23_912), Hash256::from_bendian(hex!("0000000000335eac6703f3b1732ec8b2f89c3ba3a7889e5767b090556bb9a276"))),
  (BlockHeight::from_u32(  35_457), Hash256::from_bendian(hex!("0000000000b0ae211be59b048df14820475ad0dd53b9ff83b010f71a77342d9f"))),
  (BlockHeight::from_u32(  45_479), Hash256::from_bendian(hex!("000000000063d411655d590590e16960f15ceea4257122ac430c6fbe39fbf02d"))),
  (BlockHeight::from_u32(  55_895), Hash256::from_bendian(hex!("0000000000ae4c53a43639a4ca027282f69da9c67ba951768a20415b6439a2d7"))),
  (BlockHeight::from_u32(  68_899), Hash256::from_bendian(hex!("0000000000194ab4d3d9eeb1f2f792f21bb39ff767cb547fe977640f969d77b7"))),
  (BlockHeight::from_u32(  74_619), Hash256::from_bendian(hex!("000000000011d28f38f05d01650a502cc3f4d0e793fbc26e2a2ca71f07dc3842"))),
  (BlockHeight::from_u32(  75_095), Hash256::from_bendian(hex!("0000000000193d12f6ad352a9996ee58ef8bdc4946818a5fec5ce99c11b87f0d"))),
  (BlockHeight::from_u32(  88_805), Hash256::from_bendian(hex!("00000000001392f1652e9bf45cd8bc79dc60fe935277cd11538565b4a94fa85f"))),
  (BlockHeight::from_u32( 107_996), Hash256::from_bendian(hex!("00000000000a23840ac16115407488267aa3da2b9bc843e301185b7d17e4dc40"))),
  (BlockHeight::from_u32( 137_993), Hash256::from_bendian(hex!("00000000000cf69ce152b1bffdeddc59188d7a80879210d6e5c9503011929c3c"))),
  (BlockHeight::from_u32( 167_996), Hash256::from_bendian(hex!("000000000009486020a80f7f2cc065342b0c2fb59af5e090cd813dba68ab0fed"))),
  (BlockHeight::from_u32( 207_992), Hash256::from_bendian(hex!("00000000000d85c22be098f74576ef00b7aa00c05777e966aff68a270f1e01a5"))),
  (BlockHeight::from_u32( 312_645), Hash256::from_bendian(hex!("0000000000059dcb71ad35a9e40526c44e7aae6c99169a9e7017b7d84b1c2daf"))),
  (BlockHeight::from_u32( 407_452), Hash256::from_bendian(hex!("000000000003c6a87e73623b9d70af7cd908ae22fee466063e4ffc20be1d2dbc"))),
  (BlockHeight::from_u32( 523_412), Hash256::from_bendian(hex!("000000000000e54f036576a10597e0e42cc22a5159ce572f999c33975e121d4d"))),
  (BlockHeight::from_u32( 523_930), Hash256::from_bendian(hex!("0000000000000bccdb11c2b1cfb0ecab452abf267d89b7f46eaf2d54ce6e652c"))),
  (BlockHeight::from_u32( 750_000), Hash256::from_bendian(hex!("00000000000000b4181bbbdddbae464ce11fede5d0292fb63fdede1e7c8ab21c"))),
  (BlockHeight::from_u32( 888_900), Hash256::from_bendian(hex!("0000000000000026c29d576073ab51ebd1d3c938de02e9a44c7ee9e16f82db28"))),
  (BlockHeight::from_u32( 967_800), Hash256::from_bendian(hex!("0000000000000024e26c7df7e46d673724d223cf4ca2b2adc21297cc095600f4"))),
  (BlockHeight::from_u32(1_067_570), Hash256::from_bendian(hex!("000000000000001e09926bcf5fa4513d23e870a34f74e38200db99eb3f5b7a70"))),
  (BlockHeight::from_u32(1_167_570), Hash256::from_bendian(hex!("000000000000000fb7b1e9b81700283dff0f7d87cf458e5edfdae00c669de661"))),
  (BlockHeight::from_u32(1_364_585), Hash256::from_bendian(hex!("00000000000000022f355c52417fca9b73306958f7c0832b3a7bce006ca369ef"))),
  (BlockHeight::from_u32(1_450_000), Hash256::from_bendian(hex!("00000000000000105cfae44a995332d8ec256850ea33a1f7b700474e3dad82bc"))),
  (BlockHeight::from_u32(1_796_500), Hash256::from_bendian(hex!("000000000000001d531f36005159f19351bd49ca676398a561e55dcccb84eacd"))),
  (BlockHeight::from_u32(1_850_400), Hash256::from_bendian(hex!("00000000000000261bdbe99c01fcba992e577efa6cc41aae564b8ca9f112b2a3"))),
  (BlockHeight::from_u32(1_889_000), Hash256::from_bendian(hex!("00000000000000075300e852d5bf5380f905b2768241f8b442498442084807a7"))),
  (BlockHeight::from_u32(1_969_000), Hash256::from_bendian(hex!("000000000000000c8b7a3bdcd8b9f516462122314529c8342244c685a4c899bf"))),
  (BlockHeight::from_u32(2_029_000), Hash256::from_bendian(hex!("0000000000000020d5e38b6aef5bc8e430029444d7977b46f710c7d281ef1281"))),
  (BlockHeight::from_u32(2_109_672), Hash256::from_bendian(hex!("000000000000001889bd33ef019065e250d32bd46911f4003d3fdd8128b5358d"))),
  (BlockHeight::from_u32(2_175_051), Hash256::from_bendian(hex!("000000000000001cf26547602d982dcaa909231bbcd1e70c0eb3c65de25473ba"))),
  (BlockHeight::from_u32(2_216_986), Hash256::from_bendian(hex!("0000000000000010b1135dc743f27f6fc8a138c6420a9d963fc676f96c2048f4"))),
  (BlockHeight::from_u32(2_361_500), Hash256::from_bendian(hex!("0000000000000009ba1e8f47851d036bb618a4f6565eb3c32d1f647d450ff195"))),
  (BlockHeight::from_u32(2_421_800), Hash256::from_bendian(hex!("000000000000000718ed026ebd644a8b70b42d4cbd7b25304c066c9bf15f85b7"))),
];
