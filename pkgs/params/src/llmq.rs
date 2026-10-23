//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ type definitions.

use crate::prelude::*;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_types::codec::BaseCodec;
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_num, Hashable, Numeric};

enum_map! {
  /// LLMQ type (quorum size/threshold configuration).
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum LlmqType, u8, Unknown {
    /// 50 members, 60% threshold.
    Llmq50_60 = 1 => "llmq_50_60",
    /// 400 members, 60% threshold.
    Llmq400_60 = 2 => "llmq_400_60",
    /// 400 members, 85% threshold.
    Llmq400_85 = 3 => "llmq_400_85",
    /// 100 members, 67% threshold.
    Llmq100_67 = 4 => "llmq_100_67",
    /// 60 members, 75% threshold.
    Llmq60_75 = 5 => "llmq_60_75",
    /// 25 members, 67% threshold.
    Llmq25_67 = 6 => "llmq_25_67",
    /// Regtest quorum.
    LlmqTest = 100 => "llmq_test",
    /// Devnet quorum.
    LlmqDevnet = 101 => "llmq_devnet",
    /// Test v17-era quorum.
    LlmqTestV17 = 102 => "llmq_test_v17",
    /// Test DIP-0024 rotated quorum.
    LlmqTestDip0024 = 103 => "llmq_test_dip0024",
    /// Test InstantSend quorum.
    LlmqTestInstantsend = 104 => "llmq_test_instantsend",
    /// Devnet DIP-0024 rotated quorum.
    LlmqDevnetDip0024 = 105 => "llmq_devnet_dip0024",
    /// Test Platform quorum.
    LlmqTestPlatform = 106 => "llmq_test_platform",
    /// Devnet Platform quorum.
    LlmqDevnetPlatform = 107 => "llmq_devnet_platform",
    /// No quorum type.
    LlmqNone = 0xff => "llmq_none",
  }
}

impl_num!(LlmqType, u8);

impl Hashable for LlmqType {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}
