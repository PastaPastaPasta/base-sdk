//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Building blocks the per-network parameter tables share.

use crate::genesis::genesis_block;
use crate::llmq::LlmqParams;
use crate::network::Release;
use crate::prelude::*;
use crate::types::{Bip9Deployment, BlockHeight, DeploymentPos, HardCodedPins};

use dash_num::Hash256;
use dash_primitives::{Block, BlockHeader, LlmqType};
use dash_script::AddrParams;
use hex_conservative::hex;

/// Core's `TESTNET_LLMQ_25_67_ACTIVATION_HEIGHT` (quirk 34).
pub(crate) const LLMQ_25_67_ACTIVATION_HEIGHT: BlockHeight = BlockHeight::from_u32(847_000);

/// Hard-coded pins of every chain but mainnet.
pub(crate) const TEST_PINS: HardCodedPins = HardCodedPins {
  pre_dgw_tolerance_until: None,
  llmq_25_67_activation_height: LLMQ_25_67_ACTIVATION_HEIGHT,
};

/// Hash of the regtest genesis block, which devnets build on too.
pub(crate) const REGTEST_GENESIS_HASH: Hash256 =
  Hash256::from_bendian(hex!("000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"));

/// The regtest genesis block, which devnets build on too.
pub(crate) fn regtest_genesis() -> Block {
  genesis_block(BlockHeader {
    time: 1_417_713_337,
    bits: 0x207f_ffff,
    nonce: 1_096_447,
    ..BlockHeader::default()
  })
}

/// Address encoding of every test chain (testnet, devnets, regtest).
pub(crate) const TEST_ADDR_PARAMS: AddrParams = AddrParams {
  pubkey_addr: 140,
  script_addr: 19,
  secret_key: 239,
  ext_pubkey: [0x04, 0x35, 0x87, 0xCF],
  ext_secret: [0x04, 0x35, 0x83, 0x94],
  bip44_idx: 1,
};

/// `value` for a field only the v23 release has.
pub(crate) fn v23_only<T>(release: Release, value: T) -> Option<T> {
  (release == Release::V23_1).then_some(value)
}

/// `value` for a field only the v24 release has.
pub(crate) fn v24_only<T>(release: Release, value: T) -> Option<T> {
  (release == Release::V24_0).then_some(value)
}

/// The version-bits deployments of `release` on one network.
///
/// `testdummy` (bit 28) has no window. `v24` (bit 12 in v23, 13 in v24)
/// and v24's `evo_shares` (bit 14) are EHF deployments sharing `window`
/// (size, start and minimum threshold) and the start time `v24_start`.
pub(crate) fn deployments(release: Release, dummy_start: i64, v24_start: i64, window: [i64; 3]) -> Vec<Bip9Deployment> {
  let ehf = |bit| Bip9Deployment {
    bit,
    start_time: v24_start,
    timeout: Bip9Deployment::NO_TIMEOUT,
    min_activation_height: BlockHeight::from_u32(0),
    window_size: window[0],
    threshold_start: window[1],
    threshold_min: window[2],
    falloff_coeff: 5,
    use_ehf: true,
  };
  let v24_bit = match release {
    Release::V23_1 => 12,
    Release::V24_0 => 13,
  };
  release
    .deployments()
    .iter()
    .map(|pos| match pos {
      DeploymentPos::TestDummy => Bip9Deployment {
        bit: 28,
        start_time: dummy_start,
        timeout: Bip9Deployment::NO_TIMEOUT,
        min_activation_height: BlockHeight::from_u32(0),
        window_size: 0,
        threshold_start: 0,
        threshold_min: 0,
        falloff_coeff: 0,
        use_ehf: false,
      },
      DeploymentPos::V24 => ehf(v24_bit),
      DeploymentPos::EvoShares => ehf(14),
    })
    .collect()
}

/// Core's `AddLLMQ` for each of `types`, in order.
pub(crate) fn llmqs(types: &[LlmqType]) -> Vec<LlmqParams> {
  types
    .iter()
    .filter_map(|t| LlmqParams::available(*t).copied())
    .collect()
}
