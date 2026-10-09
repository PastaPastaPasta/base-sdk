//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Quorum rotation messages.

use crate::codec::{codec_p2p, decode_flag, impl_p2p, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::msg::mn_list::{MnListDiff, MnListFormat};
use crate::prelude::*;

use dash_primitives::{hash_impl, BlockHash, Commitment, DynBitset};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::CompactSize;
use dash_types::{enum_map, impl_num};

use core::fmt;

/// Most base block hashes Core reads in a `getqrinfo` request,
/// `MAX_BASE_BLOCK_HASHES`.
pub const MAX_QRINFO_BASE_HASHES: usize = 4096;

enum_map! {
  /// How a quorum snapshot lists skipped members, Core's
  /// `SnapshotSkipMode`.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum SnapshotSkipMode, i32, Unknown {
    /// No member is skipped.
    NoSkipping = 0 => "no_skipping",
    /// The list holds the skipped members.
    SkippingEntries = 1 => "skipping_entries",
    /// The list holds the members not skipped.
    NoSkippingEntries = 2 => "no_skipping_entries",
    /// Every member is skipped.
    AllSkipped = 3 => "all_skipped",
  }
}

impl_num!(SnapshotSkipMode, i32);

hash_impl!(SnapshotSkipMode);

/// A quorum snapshot (Core's `CQuorumSnapshot`).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct QuorumSnapshot {
  /// How `skip_list` is read; Core reads any value.
  pub skip_list_mode: SnapshotSkipMode,
  /// Which of the cycle's members were active.
  pub active_quorum_members: DynBitset,
  /// Skipped, or not skipped, member indexes.
  pub skip_list: Vec<i32>,
}

codec_p2p!(QuorumSnapshot {
  skip_list_mode,
  active_quorum_members,
  skip_list
});

/// Requests quorum rotation info, the `getqrinfo` payload (Core's
/// `CGetQuorumRotationInfo`).
///
/// Core refuses to read more than [`MAX_QRINFO_BASE_HASHES`] base hashes but
/// writes any number, as does the encoder.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GetQrInfo {
  /// Blocks the requester has masternode lists for.
  pub base_block_hashes: Vec<BlockHash>,
  /// Block the rotation info is asked for.
  pub block_request_hash: BlockHash,
  /// Whether the cycle at H-4C is asked for too, read as 0 or 1: Core reads
  /// any other byte as `true` and serves the request, which here is
  /// `DecodeError::NonCanonicalBool`.
  pub extra_share: bool,
}

impl_p2p!(GetQrInfo);

impl BaseCodec for GetQrInfo {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    // Core checks the count against the limit before reading any entry.
    CompactSize::decode_size(&mut &data[..])?.into_len(MAX_QRINFO_BASE_HASHES)?;
    Ok(Self {
      base_block_hashes: Vec::<BlockHash>::decode(data)?,
      block_request_hash: BlockHash::decode(data)?,
      extra_share: decode_flag(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.base_block_hashes.encode(buf);
    self.block_request_hash.encode(buf);
    u8::from(self.extra_share).encode(buf);
  }
}

hash_impl!(GetQrInfo);

impl fmt::Display for GetQrInfo {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "getqrinfo({}, {} bases)",
      self.block_request_hash,
      self.base_block_hashes.len()
    )
  }
}

/// The snapshot and list diff of one rotation cycle.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CycleInfo {
  /// Quorum snapshot at the cycle.
  pub snapshot: QuorumSnapshot,
  /// Masternode list diff to the cycle's work block.
  pub diff: MnListDiff,
}

/// Quorum rotation info, the `qrinfo` payload (Core's
/// `CQuorumRotationInfo`).
///
/// Its diffs are in the layout of the negotiated protocol version; the codec
/// reads the current layout, [`MsgDecode`] the negotiated one, and each diff
/// is written in its own, so a peer reads them back only when they share one.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct QrInfo {
  /// Snapshot at H-C.
  pub snapshot_h_c: QuorumSnapshot,
  /// Snapshot at H-2C.
  pub snapshot_h_2c: QuorumSnapshot,
  /// Snapshot at H-3C.
  pub snapshot_h_3c: QuorumSnapshot,
  /// Diff to the chain tip.
  pub diff_tip: MnListDiff,
  /// Diff to the requested block.
  pub diff_h: MnListDiff,
  /// Diff to H-C.
  pub diff_h_c: MnListDiff,
  /// Diff to H-2C.
  pub diff_h_2c: MnListDiff,
  /// Diff to H-3C.
  pub diff_h_3c: MnListDiff,
  /// The cycle at H-4C, present when the extra share flag is set. The flag
  /// is read as 0 or 1: Core reads any other byte as `true`, which here is
  /// `DecodeError::NonCanonicalBool`.
  pub cycle_h_4c: Option<CycleInfo>,
  /// Last commitment of each quorum index.
  pub last_commitment_per_index: Vec<Commitment>,
  /// Snapshots for the requester's base blocks.
  pub quorum_snapshot_list: Vec<QuorumSnapshot>,
  /// Diffs for the requester's base blocks.
  pub mn_list_diff_list: Vec<MnListDiff>,
}

impl_p2p!(QrInfo);

impl BaseCodec for QrInfo {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_as(data, MnListFormat::CURRENT)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.snapshot_h_c.encode(buf);
    self.snapshot_h_2c.encode(buf);
    self.snapshot_h_3c.encode(buf);
    self.diff_tip.encode(buf);
    self.diff_h.encode(buf);
    self.diff_h_c.encode(buf);
    self.diff_h_2c.encode(buf);
    self.diff_h_3c.encode(buf);
    u8::from(self.cycle_h_4c.is_some()).encode(buf);
    if let Some(cycle) = &self.cycle_h_4c {
      cycle.snapshot.encode(buf);
      cycle.diff.encode(buf);
    }
    self.last_commitment_per_index.encode(buf);
    self.quorum_snapshot_list.encode(buf);
    self.mn_list_diff_list.encode(buf);
  }
}

hash_impl!(QrInfo);

impl QrInfo {
  /// Decodes rotation info whose diffs are in `format`.
  ///
  /// # Errors
  ///
  /// Returns a `DecodeError` where Core's read throws.
  pub fn decode_as(data: &mut &[u8], format: MnListFormat) -> Result<Self, DecodeError> {
    let snapshot_h_c = QuorumSnapshot::decode(data)?;
    let snapshot_h_2c = QuorumSnapshot::decode(data)?;
    let snapshot_h_3c = QuorumSnapshot::decode(data)?;
    let diff_tip = MnListDiff::decode_as(data, format)?;
    let diff_h = MnListDiff::decode_as(data, format)?;
    let diff_h_c = MnListDiff::decode_as(data, format)?;
    let diff_h_2c = MnListDiff::decode_as(data, format)?;
    let diff_h_3c = MnListDiff::decode_as(data, format)?;
    let cycle_h_4c = if decode_flag(data)? {
      Some(CycleInfo {
        snapshot: QuorumSnapshot::decode(data)?,
        diff: MnListDiff::decode_as(data, format)?,
      })
    } else {
      None
    };
    let last_commitment_per_index = Vec::<Commitment>::decode(data)?;
    let quorum_snapshot_list = Vec::<QuorumSnapshot>::decode(data)?;
    let count = CompactSize::decode_size(data)?.into_len(data.len())?;
    let mut mn_list_diff_list = Vec::new();
    for _ in 0..count {
      mn_list_diff_list.push(MnListDiff::decode_as(data, format)?);
    }
    Ok(Self {
      snapshot_h_c,
      snapshot_h_2c,
      snapshot_h_3c,
      diff_tip,
      diff_h,
      diff_h_c,
      diff_h_2c,
      diff_h_3c,
      cycle_h_4c,
      last_commitment_per_index,
      quorum_snapshot_list,
      mn_list_diff_list,
    })
  }
}

impl MsgDecode for QrInfo {
  /// Decodes rotation info in the negotiated layout.
  ///
  /// Core's handler reads nothing from a peer: it penalises one that sends
  /// `qrinfo` and stops. A node that follows Core decides from the command,
  /// before decoding, and decodes only the replies to its own requests.
  fn decode_msg(data: &mut &[u8], ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    Ok(Self::decode_as(data, MnListFormat::for_version(ctx.version))?)
  }
}

impl fmt::Display for QrInfo {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "qrinfo({})", self.diff_h.block_hash)
  }
}
