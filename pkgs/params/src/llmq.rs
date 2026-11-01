//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ type definitions.

#[cfg(feature = "codec")]
use crate::prelude::*;

#[cfg(feature = "codec")]
use bitcoin_hashes::sha256d;
#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::codec::BaseCodec;
#[cfg(feature = "codec")]
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num};
#[cfg(feature = "codec")]
use dash_types::{Hashable, Numeric};

enum_map! {
  /// LLMQ type (quorum size/threshold configuration).
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
  #[cfg_attr(feature = "codec", derive(TypeId))]
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

#[cfg(feature = "codec")]
impl Hashable for LlmqType {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl LlmqType {
  /// The types of the reference implementation's LLMQ table, in its order.
  pub const AVAILABLE: [Self; 14] = [
    Self::LlmqTest,
    Self::LlmqTestInstantsend,
    Self::LlmqTestV17,
    Self::LlmqTestDip0024,
    Self::LlmqTestPlatform,
    Self::LlmqDevnet,
    Self::LlmqDevnetDip0024,
    Self::LlmqDevnetPlatform,
    Self::Llmq50_60,
    Self::Llmq60_75,
    Self::Llmq400_60,
    Self::Llmq400_85,
    Self::Llmq100_67,
    Self::Llmq25_67,
  ];

  /// DKG and signing parameters of the type, or `None` for
  /// [`LlmqType::LlmqNone`] and unknown types.
  ///
  /// These are the network table's values. A chain's, with its size options,
  /// come from [`ConsensusParams::llmq`](crate::ConsensusParams::llmq).
  pub const fn params(self) -> Option<LlmqParams> {
    Some(match self {
      Self::Llmq50_60 => LlmqParams::LLMQ_50_60,
      Self::Llmq400_60 => LlmqParams::LLMQ_400_60,
      Self::Llmq400_85 => LlmqParams::LLMQ_400_85,
      Self::Llmq100_67 => LlmqParams::LLMQ_100_67,
      Self::Llmq60_75 => LlmqParams::LLMQ_60_75,
      Self::Llmq25_67 => LlmqParams::LLMQ_25_67,
      Self::LlmqTest | Self::LlmqTestV17 | Self::LlmqTestInstantsend => LlmqParams::LLMQ_TEST,
      Self::LlmqTestPlatform => LlmqParams::LLMQ_TEST_PLATFORM,
      Self::LlmqTestDip0024 => LlmqParams::LLMQ_TEST_DIP0024,
      Self::LlmqDevnet => LlmqParams::LLMQ_DEVNET,
      Self::LlmqDevnetDip0024 => LlmqParams::LLMQ_DEVNET_DIP0024,
      Self::LlmqDevnetPlatform => LlmqParams::LLMQ_DEVNET_PLATFORM,
      Self::LlmqNone | Self::Unknown(_) => return None,
    })
  }
}

/// Largest quorum size the v24 signing protocol supports. The v24 release
/// refuses larger LLMQ size overrides, and v23.1 has no limit.
pub const MAX_LLMQ_SIZE: u16 = 400;

/// DKG and signing parameters of an [`LlmqType`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct LlmqParams {
  /// Whether quorums of the type rotate their members under DIP-0024.
  pub use_rotation: bool,
  /// Number of members.
  pub size: u16,
  /// Fewest valid members and signers a commitment may carry.
  pub min_size: u16,
  /// Number of signature shares that recover the quorum signature.
  pub threshold: u16,
  /// Blocks between the starts of two DKG sessions.
  pub dkg_interval: u16,
  /// Blocks per DKG phase.
  pub dkg_phase_blocks: u16,
  /// First block of the interval that must carry a commitment, inclusive.
  pub dkg_mining_window_start: u16,
  /// Last block of the interval that may carry a commitment, inclusive.
  pub dkg_mining_window_end: u16,
  /// Complaints that mark a member bad for every other member.
  pub dkg_bad_votes_threshold: u16,
  /// Number of recent quorums that take part in signing.
  pub signing_active_quorum_count: u16,
  /// Number of quorums whose intra-quorum connections a member keeps.
  pub keep_old_connections: u16,
  /// Number of quorums whose secret key shares a member keeps.
  pub keep_old_keys: u16,
  /// Members a signer sends its signature shares to before giving up.
  pub recovery_members: u16,
}

impl LlmqParams {
  /// Parameters of [`LlmqType::Llmq50_60`].
  pub const LLMQ_50_60: Self = Self {
    use_rotation: false,
    size: 50,
    min_size: 40,
    threshold: 30,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 10,
    dkg_mining_window_end: 18,
    dkg_bad_votes_threshold: 40,
    signing_active_quorum_count: 24,
    keep_old_connections: 25,
    keep_old_keys: 48,
    recovery_members: 25,
  };

  /// Parameters of [`LlmqType::Llmq400_60`].
  pub const LLMQ_400_60: Self = Self {
    use_rotation: false,
    size: 400,
    min_size: 300,
    threshold: 240,
    dkg_interval: 288,
    dkg_phase_blocks: 4,
    dkg_mining_window_start: 20,
    dkg_mining_window_end: 28,
    dkg_bad_votes_threshold: 300,
    signing_active_quorum_count: 4,
    keep_old_connections: 5,
    keep_old_keys: 8,
    recovery_members: 100,
  };

  /// Parameters of [`LlmqType::Llmq400_85`].
  pub const LLMQ_400_85: Self = Self {
    use_rotation: false,
    size: 400,
    min_size: 350,
    threshold: 340,
    dkg_interval: 576,
    dkg_phase_blocks: 4,
    dkg_mining_window_start: 20,
    dkg_mining_window_end: 48,
    dkg_bad_votes_threshold: 300,
    signing_active_quorum_count: 4,
    keep_old_connections: 5,
    keep_old_keys: 8,
    recovery_members: 100,
  };

  /// Parameters of [`LlmqType::Llmq100_67`].
  pub const LLMQ_100_67: Self = Self {
    use_rotation: false,
    size: 100,
    min_size: 80,
    threshold: 67,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 10,
    dkg_mining_window_end: 18,
    dkg_bad_votes_threshold: 80,
    signing_active_quorum_count: 24,
    keep_old_connections: 25,
    keep_old_keys: 1440,
    recovery_members: 50,
  };

  /// Parameters of [`LlmqType::Llmq60_75`].
  pub const LLMQ_60_75: Self = Self {
    use_rotation: true,
    size: 60,
    min_size: 50,
    threshold: 45,
    dkg_interval: 288,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 42,
    dkg_mining_window_end: 50,
    dkg_bad_votes_threshold: 48,
    signing_active_quorum_count: 32,
    keep_old_connections: 64,
    keep_old_keys: 64,
    recovery_members: 25,
  };

  /// Parameters of [`LlmqType::Llmq25_67`].
  pub const LLMQ_25_67: Self = Self {
    use_rotation: false,
    size: 25,
    min_size: 22,
    threshold: 17,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 10,
    dkg_mining_window_end: 18,
    dkg_bad_votes_threshold: 22,
    signing_active_quorum_count: 24,
    keep_old_connections: 25,
    keep_old_keys: 1440,
    recovery_members: 12,
  };

  /// Parameters of [`LlmqType::LlmqTest`], [`LlmqType::LlmqTestV17`] and
  /// [`LlmqType::LlmqTestInstantsend`].
  pub const LLMQ_TEST: Self = Self {
    use_rotation: false,
    size: 3,
    min_size: 2,
    threshold: 2,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 10,
    dkg_mining_window_end: 18,
    dkg_bad_votes_threshold: 2,
    signing_active_quorum_count: 2,
    keep_old_connections: 3,
    keep_old_keys: 4,
    recovery_members: 3,
  };

  /// Parameters of [`LlmqType::LlmqTestPlatform`].
  pub const LLMQ_TEST_PLATFORM: Self = Self {
    use_rotation: false,
    size: 3,
    min_size: 2,
    threshold: 2,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 10,
    dkg_mining_window_end: 18,
    dkg_bad_votes_threshold: 2,
    signing_active_quorum_count: 2,
    keep_old_connections: 4,
    keep_old_keys: 1440,
    recovery_members: 3,
  };

  /// Parameters of [`LlmqType::LlmqTestDip0024`].
  pub const LLMQ_TEST_DIP0024: Self = Self {
    use_rotation: true,
    size: 4,
    min_size: 4,
    threshold: 3,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 12,
    dkg_mining_window_end: 20,
    dkg_bad_votes_threshold: 2,
    signing_active_quorum_count: 2,
    keep_old_connections: 4,
    keep_old_keys: 4,
    recovery_members: 3,
  };

  /// Parameters of [`LlmqType::LlmqDevnet`].
  pub const LLMQ_DEVNET: Self = Self {
    use_rotation: false,
    size: 12,
    min_size: 7,
    threshold: 6,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 10,
    dkg_mining_window_end: 18,
    dkg_bad_votes_threshold: 7,
    signing_active_quorum_count: 4,
    keep_old_connections: 5,
    keep_old_keys: 8,
    recovery_members: 6,
  };

  /// Parameters of [`LlmqType::LlmqDevnetDip0024`].
  pub const LLMQ_DEVNET_DIP0024: Self = Self {
    use_rotation: true,
    size: 8,
    min_size: 6,
    threshold: 4,
    dkg_interval: 48,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 12,
    dkg_mining_window_end: 20,
    dkg_bad_votes_threshold: 7,
    signing_active_quorum_count: 2,
    keep_old_connections: 4,
    keep_old_keys: 4,
    recovery_members: 4,
  };

  /// Parameters of [`LlmqType::LlmqDevnetPlatform`].
  pub const LLMQ_DEVNET_PLATFORM: Self = Self {
    use_rotation: false,
    size: 12,
    min_size: 9,
    threshold: 8,
    dkg_interval: 24,
    dkg_phase_blocks: 2,
    dkg_mining_window_start: 10,
    dkg_mining_window_end: 18,
    dkg_bad_votes_threshold: 7,
    signing_active_quorum_count: 4,
    keep_old_connections: 5,
    keep_old_keys: 1440,
    recovery_members: 6,
  };

  /// DKG cycles covering `quorums_count` quorums.
  ///
  /// Zero for a rotated type with no active quorums, where the reference
  /// divides by zero. No table entry has that.
  pub const fn max_cycles(&self, quorums_count: i32) -> i32 {
    if self.use_rotation {
      match quorums_count.checked_div(self.signing_active_quorum_count as i32) {
        Some(cycles) => cycles,
        None => 0,
      }
    } else {
      quorums_count
    }
  }

  /// Blocks of recent DKG data a node keeps for the type.
  pub const fn max_store_depth(&self) -> i32 {
    self
      .max_cycles(self.keep_old_keys as i32)
      .wrapping_mul(self.dkg_interval as i32)
  }

  /// Whether quorums of the type have a single member.
  pub const fn is_single_member(&self) -> bool {
    self.size == 1
  }
}

/// Size overrides of the LLMQ types an option resizes, each a size and a
/// threshold.
///
/// [`ConsensusParams::llmq`](crate::ConsensusParams::llmq) applies them. The
/// threshold is also the type's minimum size and bad-votes threshold.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct LlmqSizes {
  /// [`LlmqType::LlmqTest`], from `-llmqtestparams`.
  pub test: Option<(u16, u16)>,
  /// [`LlmqType::LlmqTestInstantsend`], from `-llmqtestinstantsendparams`.
  pub test_instant_send: Option<(u16, u16)>,
  /// [`LlmqType::LlmqTestPlatform`], from `-llmqtestplatformparams`.
  pub test_platform: Option<(u16, u16)>,
  /// [`LlmqType::LlmqDevnet`], from `-llmqdevnetparams`.
  pub devnet: Option<(u16, u16)>,
}

impl LlmqSizes {
  /// No overrides, as every network's table has.
  pub const NONE: Self = Self {
    test: None,
    test_instant_send: None,
    test_platform: None,
    devnet: None,
  };

  /// The size and threshold override of `llmq_type`, if it has one.
  pub const fn get(&self, llmq_type: LlmqType) -> Option<(u16, u16)> {
    match llmq_type {
      LlmqType::LlmqTest => self.test,
      LlmqType::LlmqTestInstantsend => self.test_instant_send,
      LlmqType::LlmqTestPlatform => self.test_platform,
      LlmqType::LlmqDevnet => self.devnet,
      _ => None,
    }
  }

  /// The override slot of `llmq_type`, if an option can resize it.
  pub(crate) const fn slot_mut(&mut self, llmq_type: LlmqType) -> Option<&mut Option<(u16, u16)>> {
    match llmq_type {
      LlmqType::LlmqTest => Some(&mut self.test),
      LlmqType::LlmqTestInstantsend => Some(&mut self.test_instant_send),
      LlmqType::LlmqTestPlatform => Some(&mut self.test_platform),
      LlmqType::LlmqDevnet => Some(&mut self.devnet),
      _ => None,
    }
  }
}
