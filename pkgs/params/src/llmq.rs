//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Long-living masternode quorum (LLMQ) parameters.

use dash_primitives::LlmqType;

/// Largest quorum size the v24 signing protocol supports. v24 refuses larger
/// `-llmqtestparams` and `-llmqdevnetparams` sizes; v23 has no such limit.
pub const MAX_LLMQ_SIZE: i32 = 400;

/// Parameters of one LLMQ type and its DKG, as Core's `Consensus::LLMQParams`.
///
/// Fields keep Core's `int` so every value an override can set is
/// representable. Core checks none of them, so after `-llmqtestparams` or
/// `-llmqdevnetparams` a size may be 0 or negative and a threshold may exceed
/// the size. The defaults are in [`AVAILABLE_LLMQS`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LlmqParams {
  /// Quorum type.
  pub llmq_type: LlmqType,
  /// Core's name for the type, used by the LLMQ role options.
  pub name: &'static str,
  /// Whether this is a rotated (DIP0024) quorum.
  pub use_rotation: bool,
  /// Number of members.
  pub size: i32,
  /// Minimum number of valid members after the DKG.
  pub min_size: i32,
  /// Signature shares needed to recover a signature.
  pub threshold: i32,
  /// Blocks between DKG sessions.
  pub dkg_interval: i32,
  /// Blocks per DKG phase.
  pub dkg_phase_blocks: i32,
  /// First block of the commitment mining window, inclusive.
  pub dkg_mining_window_start: i32,
  /// Last block of the commitment mining window, inclusive.
  pub dkg_mining_window_end: i32,
  /// Complaint votes that mark a member bad.
  pub dkg_bad_votes_threshold: i32,
  /// Quorums active for signing sessions.
  pub signing_active_quorum_count: i32,
  /// Quorums whose intra-quorum connections are kept.
  pub keep_old_connections: i32,
  /// Quorums whose keys are kept.
  pub keep_old_keys: i32,
  /// Members to send all signature shares to before giving up.
  pub recovery_members: i32,
}

impl LlmqParams {
  /// Core's `max_cycles`: DKG cycles covering `quorums_count` quorums.
  ///
  /// Zero for a rotated type with no active quorums, where Core divides by
  /// zero; no table entry has that.
  pub const fn max_cycles(&self, quorums_count: i32) -> i32 {
    if self.use_rotation {
      match quorums_count.checked_div(self.signing_active_quorum_count) {
        Some(cycles) => cycles,
        None => 0,
      }
    } else {
      quorums_count
    }
  }

  /// Core's `max_store_depth`: blocks of recent DKG data to keep.
  pub const fn max_store_depth(&self) -> i32 {
    self.max_cycles(self.keep_old_keys).wrapping_mul(self.dkg_interval)
  }

  /// Core's `is_single_member`.
  pub const fn is_single_member(&self) -> bool {
    self.size == 1
  }

  /// The [`AVAILABLE_LLMQS`] entry for `llmq_type`.
  pub fn available(llmq_type: LlmqType) -> Option<&'static LlmqParams> {
    AVAILABLE_LLMQS.iter().find(|q| q.llmq_type == llmq_type)
  }
}

/// Core's `available_llmqs`: every LLMQ type with its default parameters, in
/// Core's order. Equal at both pinned releases.
pub static AVAILABLE_LLMQS: [LlmqParams; 14] = [
  LlmqParams {
    llmq_type: LlmqType::LlmqTest,
    name: "llmq_test",
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
  },
  LlmqParams {
    llmq_type: LlmqType::LlmqTestInstantsend,
    name: "llmq_test_instantsend",
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
  },
  LlmqParams {
    llmq_type: LlmqType::LlmqTestV17,
    name: "llmq_test_v17",
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
  },
  LlmqParams {
    llmq_type: LlmqType::LlmqTestDip0024,
    name: "llmq_test_dip0024",
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
  },
  LlmqParams {
    llmq_type: LlmqType::LlmqTestPlatform,
    name: "llmq_test_platform",
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
  },
  LlmqParams {
    llmq_type: LlmqType::LlmqDevnet,
    name: "llmq_devnet",
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
  },
  LlmqParams {
    llmq_type: LlmqType::LlmqDevnetDip0024,
    name: "llmq_devnet_dip0024",
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
  },
  LlmqParams {
    llmq_type: LlmqType::LlmqDevnetPlatform,
    name: "llmq_devnet_platform",
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
  },
  LlmqParams {
    llmq_type: LlmqType::Llmq50_60,
    name: "llmq_50_60",
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
  },
  LlmqParams {
    llmq_type: LlmqType::Llmq60_75,
    name: "llmq_60_75",
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
  },
  LlmqParams {
    llmq_type: LlmqType::Llmq400_60,
    name: "llmq_400_60",
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
  },
  LlmqParams {
    llmq_type: LlmqType::Llmq400_85,
    name: "llmq_400_85",
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
  },
  LlmqParams {
    llmq_type: LlmqType::Llmq100_67,
    name: "llmq_100_67",
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
  },
  LlmqParams {
    llmq_type: LlmqType::Llmq25_67,
    name: "llmq_25_67",
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
  },
];
