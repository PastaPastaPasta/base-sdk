//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Per-network values outside [`ChainParams`](crate::ChainParams), the same
//! at v23.1.8 and v24.0.0-rc.3.

use super::{AssumeutxoData, HardCodedPins};
use crate::{Network, Release};

use bitcoin_units::BlockHeight;
use dash_num::Hash256;
use dash_types::type_id::Unencodable;
use dash_types::Numeric;
use hex_conservative::hex;

/// The per-network values a [`ChainSetup`](super::ChainSetup) holds besides
/// the ones of [`ChainParams`](crate::ChainParams).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub(super) struct Extras {
  /// BIP155-serialized fixed seed addresses.
  pub(super) fixed_seeds: &'static [u8],
  /// Whether a masternode's external IP must be routable.
  pub(super) require_routable_external_ip: bool,
  /// Whether several masternode addresses may share a network group.
  pub(super) allow_multiple_addresses_from_group: bool,
  /// Seconds before an LLMQ connection is retried.
  pub(super) llmq_connection_retry_timeout: i32,
  /// Seconds until a fulfilled request expires.
  pub(super) fulfilled_request_expire_time: i32,
  /// Values Core hard-codes outside its chain parameters.
  pub(super) pins: HardCodedPins,
}

/// Core's `TESTNET_LLMQ_25_67_ACTIVATION_HEIGHT` (quirk 34).
const LLMQ_25_67_ACTIVATION_HEIGHT: BlockHeight = BlockHeight::from_u32(847_000);

/// Hard-coded pins of every chain but mainnet.
const TEST_PINS: HardCodedPins = HardCodedPins {
  pre_dgw_tolerance_until: None,
  llmq_25_67_activation_height: LLMQ_25_67_ACTIVATION_HEIGHT,
};

/// The values of `network`.
pub(super) const fn extras(network: Network) -> Extras {
  match network {
    Network::Main => Extras {
      fixed_seeds: &MAINNET_FIXED_SEEDS,
      require_routable_external_ip: true,
      allow_multiple_addresses_from_group: false,
      llmq_connection_retry_timeout: 60,
      fulfilled_request_expire_time: 60 * 60,
      pins: HardCodedPins {
        pre_dgw_tolerance_until: Some(BlockHeight::from_u32(68_589)),
        llmq_25_67_activation_height: LLMQ_25_67_ACTIVATION_HEIGHT,
      },
    },
    Network::Testnet3 => Extras {
      fixed_seeds: &TESTNET_FIXED_SEEDS,
      require_routable_external_ip: true,
      allow_multiple_addresses_from_group: false,
      llmq_connection_retry_timeout: 60,
      fulfilled_request_expire_time: 5 * 60,
      pins: TEST_PINS,
    },
    Network::Devnet => Extras {
      fixed_seeds: &[],
      require_routable_external_ip: true,
      allow_multiple_addresses_from_group: true,
      llmq_connection_retry_timeout: 60,
      fulfilled_request_expire_time: 5 * 60,
      pins: TEST_PINS,
    },
    Network::Regtest => Extras {
      fixed_seeds: &[],
      require_routable_external_ip: false,
      allow_multiple_addresses_from_group: true,
      llmq_connection_retry_timeout: 1,
      fulfilled_request_expire_time: 5 * 60,
      pins: TEST_PINS,
    },
  }
}

/// The assumeutxo snapshots `network` trusts at `release`.
pub(super) const fn assumeutxo(network: Network, release: Release) -> &'static [AssumeutxoData] {
  match (network, release) {
    (Network::Regtest, Release::V23_1) => &ASSUMEUTXO_V23,
    (Network::Regtest, Release::V24_0) => &ASSUMEUTXO_V24,
    _ => &[],
  }
}

/// Regtest snapshot at `height` with UTXO-set hash `hash` and evo-section
/// hash `evo_hash`.
const fn snapshot(height: u32, hash: [u8; 32], evo_hash: Option<Hash256>) -> AssumeutxoData {
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

static ASSUMEUTXO_V23: [AssumeutxoData; 2] = [snapshot(110, SNAPSHOT_110, None), snapshot(200, SNAPSHOT_200, None)];
static ASSUMEUTXO_V24: [AssumeutxoData; 2] = [snapshot(110, SNAPSHOT_110, ZERO), snapshot(200, SNAPSHOT_200, ZERO)];

#[rustfmt::skip]
static MAINNET_FIXED_SEEDS: [u8; 2260] = hex!(concat!(
  "0420ba5bab3a877c7498c27006d1350849b96b17d52621cca8c173319a4476cbd777270f0420b4c38d95481f090029a5",
  "ab00a37aae2d5e30728a3d082fabba6bbfe6fa59b8aa270f04209d329c4d1e352dbd4982b9a5664f455256ac5db3e7e3",
  "393eac8122102f23260d270f04207e87e89bd53f4bb62621ff57a7bef3085e90979dacc987ec5ca6db72b9b67932270f",
  "0420627b986dc470d769116ae85b7eace8a1ed4a67d733109bf1416bda703145ecfe270f04205c0de69424577850c8c3",
  "c0a1e8913f20e02371f2f320caca11f73a820833f8b3270f04205783984d479e719412674376a5625be6a2bc89905465",
  "d404123c04b1535b21e9270f0420574c369aa062ed8658fa037d05832f355675468a049de6d7be1efaf2366f29d0270f",
  "04204c2524e1b55c2c543a236d2faac27e32db1d970fc3cb604a28c85f63853a5d67270f04204a527b624ae4f68fb629",
  "c5f112f3094c18e5938373ac607dad561283ecec47e1270f0420463d6c95fee97af210f0a404783c91bf63c84b012b2b",
  "51a4e4d015b41bcf9ec1270f042044d4098b4679554a85892aee6881aa9a6327285fb0a8da6bac87df38325f2d89270f",
  "042047fb8b8727ca95e877ae41bd72206225e5679841850e9a5d4ab10f8f46a987a4270f04203f2381376b32e603dea5",
  "bcc9e8e698a6dce06cbb075e2364eaa9fa104088fcb7270f04203e84f83123dc6043c5ddd4a643a3956e1c5be18580e4",
  "4b88e72fc6f0854e8298270f0420304dab0f94b0baafdba9ddb9ecc49e8f50e2668b3262851277af2045603936b3270f",
  "04202e5decf0624cca6e90df00651cca4acb66eea2a694278d6cec154be0a486e321270f04202109f10f0d0a69f782fc",
  "e559b0bbe00651fd4030359537d55bf9dd737d2a8133270f0420060f6b3d30e44db0c9619cff8226183d058042410fe6",
  "de742b3f23fba7dab15c270f0420ed7ab30c6e589039cf5061d95c281a258f3e314c627fb996d443162519900f57270f",
  "0420ef3468e6b3c6c4d0cf22dc9209d02a634f6d6afd316ad4e9717306f046cb1713270f0420e0c1c978b5cead3f7f4a",
  "bde0688388a45d39712dce5847ac239fc0145fdde952270f0420dd2a24e18845d1e6f99a7f8b23613755f42200921fc8",
  "e7a36ffa5bbf711dcfb9270f0420d89d506e4d6230388c108cb29eaa2da25f632a843e94970e8de1ea8bab78eafb270f",
  "0420d063bfe7a859b68dc416b2b2d61fcb38b217417dc8e2533140bb65c9bcb1bb29270f0104d99ae714270f0104d8ee",
  "4b2e270f0104d8e6e87d270f0104d48469be270f0104d41868e1270f0104d18d24ce270f0104d057665b270f0104cff4",
  "f728270f0104ca470e4f270f0104ca051021270f0104c3625fd2270f0104c31afee4270f0104c2ee19c7270f0104c287",
  "5464270f0104c2059dd6270f0104c0af7fc6270f0104c0a90657270f0104b9f373db270f0104b9e4539c270f0104b9e4",
  "5384270f0104b9d8b305270f0104b9c113d6270f0104b9b92868270f0104b9a6d99a270f0104b9a5ab75270f0104b9a4",
  "a3da270f0104b9a4a355270f0104b970f935270f0104b970f931270f0104b91c6591270f0104b86bb6c6270f0104b2fd",
  "fd05270f0104b2d7ed87270f0104b2d7ed86270f0104b2d057e2270f0104b2d057d5270f0104b29d5bb1270f0104b23f",
  "7981270f0104b15d8d56270f0104b15d8d3c270f0104b0664191270f0104acee0719270f0104acecf451270f0104ac68",
  "91a6270f0104ac565b9e270f0104ac5649a0270f0104a87757c4270f0104a8775004270f0104a768d81c270f0104a758",
  "a910270f0104a516ea87270f0104a516dd61270f0104a3ac4229270f0104a161a573270f01049f4b79a3270f01049a10",
  "3f70270f010498435fb8270f010497f455db270f010497f455c3270f010497f455b2270f010497f4557b270f01049568",
  "6e77270f0104932d29d2270f0104901fbc2a270f01049018eeb2270f010488f46311270f0104851261e2270f010484f3",
  "c5f0270f010484f3c5b3270f010484f3c563270f010484f3c517270f010482ff9ba3270f010482a2e9ba270f01047bc1",
  "40a6270f010473bef839270f01047284acd7270f01046deb43f6270f01046ca083c0270f01046bbd034a270f01046bb3",
  "ca4a270f01046baecce8270f01046baafea0270f01046a370916270f010468eaa773270f01045d73ac27270f01045d73",
  "ac25270f01045bc795b1270f01045bc66c28270f01045bc66c27270f01045bc66c25270f01045bc66c23270f01045bb8",
  "f9d1270f010459b34960270f0104597dd1c3270f0104597dd16e270f0104597dd145270f01045975391b270f01045975",
  "03f2270f0104592e2ada270f010459238395270f010457e41840270f010455d1f1f5270f010455d1f15d270f010455d1",
  "f157270f010455d1f156270f0104559bbc8a270f010454f7b4c9270f010454f2b3cc270f010454620cc4270f01045409",
  "3211270f010453ef6328270f0104539564ba270f0104539564b9270f0104539564b8270f0104539564b7270f010452ca",
  "e653270f010452b492c0270f010451e3fa33270f010450f99308270f010450f084e7270f010450d0e690270f01044e53",
  "1300270f01044ddf6304270f01044ddd94cc270f01044a325a71270f0104483e3a6c270f0104483c26a0270f0104453d",
  "6bd7270f010442f5c434270f010442f4f346270f010442a37171270f010442a3715b270f010442a37107270f01043eab",
  "857d270f01043e3cf4ae270f01043424665b270f0104342109ac270f0104339ebc58270f0104339ea9ed270f0104339e",
  "a71f270f01042efafe0a270f01042e2428f2270f01042e1ebdbb270f01042e04a27f270f01042d99ba64270f01042d95",
  "9ac2270f01042d809c1e270f01042d4f126a270f01042d3dba79270f01042d3a384f270f01042cf063d6270f01042be5",
  "4d2e270f01042ba7f46d270f01042ba7ef91270f01042b86b471270f01042b85ab65270f010426667d6c270f01042636",
  "0c6f270f01042561e315270f010422f6b019270f01041f946394270f01041f0a6124270f010417a300ae270f010405a1",
  "6e4f270f010405236713270f01040502493a270f0104050243be270f010402e97823270f0104023bdb36270f01040175",
  "4bdc270f",
));

#[rustfmt::skip]
static TESTNET_FIXED_SEEDS: [u8; 152] = hex!(concat!(
  "0104d42f44c74e1f0104b9bba9c14e1f0104cef5a73f4e1f0104935d84094e1f010444437a484e1f010444437a2a4e1f",
  "010444437a214e1f010444437a174e1f01043e3cf4ae4e1f010436d55ed84e1f010436bf92894e1f010436bc45594e1f",
  "010434599a304e1f010423a212744e1f0104235c8f074e1f0104235bc5da4e1f0104235b86594e1f010422dc861e4e1f",
  "010422d21ac34e1f",
));
